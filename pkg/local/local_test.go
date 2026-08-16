package local_test

import (
	"bytes"
	"context"
	"io"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"go.uber.org/goleak"

	"github.com/shareed2k/mogate/pkg/local"
)

const validToken = "0123456789abcdef-local-token"

// idleListener accepts and drains connections until it is closed. It stands in
// for the port-forwarded agent egress endpoint, which the relay dials lazily.
func idleListener(t *testing.T) net.Listener {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	go func() {
		for {
			conn, acceptErr := listener.Accept()
			if acceptErr != nil {
				return
			}
			go func() {
				_, _ = io.Copy(io.Discard, conn)
				_ = conn.Close()
			}()
		}
	}()
	return listener
}

// shortSocketPath returns a relay socket path in a private 0700 directory whose
// total length stays within the platform sun_path limit (104 bytes on macOS).
// t.TempDir embeds the test name, which can overflow that limit.
func shortSocketPath(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("", "mg")
	if err != nil {
		t.Fatalf("make socket dir: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	return filepath.Join(dir, "s.sock")
}

// writeFile writes content to path with mode 0600, failing the test on error.
func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}

// waitFor polls condition until it holds or the deadline elapses.
func waitFor(t *testing.T, timeout time.Duration, condition func() bool) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if condition() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("condition not met before deadline")
}

// skipInjectedSpawnOnDarwin skips a test that spawns a live command with the
// injector loaded. On macOS, execute() patches a restricted top-level binary
// and DYLD-injects the loader, so the child actually runs under the injector:
// a placeholder injector library gets the process killed by dyld/AMFI, and the
// only binary that survives the loader variable — an unpatched SIP-restricted
// one such as /bin/sh — has DYLD_* stripped by SIP, so the injection never
// takes effect. Exercising a surviving injected spawn therefore needs a real
// built injector, which lives in the E2E/golden phases. The platform-agnostic
// relay/drain flow still runs on Linux, and the loader variable and arch-aware
// injector selection are covered by the internal unit tests.
func skipInjectedSpawnOnDarwin(t *testing.T) {
	t.Helper()
	if runtime.GOOS == "darwin" {
		t.Skip("live injected spawn requires a real built injector on macOS; covered by E2E, not this unit test")
	}
}

// socketReady reports whether path is a Unix socket.
func socketReady(path string) bool {
	info, err := os.Stat(path)
	return err == nil && info.Mode()&os.ModeSocket != 0
}

// TestRun_InjectsAndDrains asserts that Run brings up the relay socket at mode
// 0600, delivers the injected environment to the command, and returns nil when
// the command exits. The command records MOGATE_SOCKET, a normal environment
// variable that survives across exec on every platform (macOS SIP strips the
// DYLD_* loader variable from protected binaries such as /bin/sh, so the loader
// variable itself is verified authoritatively by the internal unit test).
func TestRun_InjectsAndDrains(t *testing.T) {
	skipInjectedSpawnOnDarwin(t)
	defer goleak.VerifyNone(t)

	dir := t.TempDir()
	socket := shortSocketPath(t)
	library := filepath.Join(dir, "libmogate.test")
	tokenFile := filepath.Join(dir, "token")
	output := filepath.Join(dir, "socket.txt")
	gate := filepath.Join(dir, "gate")
	writeFile(t, library, "dummy injector")
	writeFile(t, tokenFile, validToken+"\n")

	egress := idleListener(t)
	defer func() { _ = egress.Close() }()

	// Record the injected socket variable, then block until the gate file
	// appears so the test can inspect the live relay socket before Run drains.
	script := "printf '%s' \"$MOGATE_SOCKET\" > '" + output +
		"'; while [ ! -e '" + gate + "' ]; do sleep 0.02; done"
	command := []string{"sh", "-c", script}

	cfg := local.Config{
		EgressAddr:  egress.Addr().String(),
		TokenFile:   tokenFile,
		Socket:      socket,
		InjectorLib: library,
		Modes:       local.Modes{Egress: true},
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	runErr := make(chan error, 1)
	go func() { runErr <- local.Run(ctx, cfg, command) }()

	waitFor(t, 5*time.Second, func() bool { return socketReady(socket) })
	info, err := os.Stat(socket)
	if err != nil {
		t.Fatalf("stat socket: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Fatalf("relay socket mode = %o, want 0600", perm)
	}

	writeFile(t, gate, "")
	select {
	case err := <-runErr:
		if err != nil {
			t.Fatalf("Run returned %v, want nil on command exit", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("Run did not return after command exit")
	}

	recorded, err := os.ReadFile(output)
	if err != nil {
		t.Fatalf("read injected socket output: %v", err)
	}
	if string(recorded) != socket {
		t.Fatalf("injected MOGATE_SOCKET = %q, want %q", recorded, socket)
	}
}

// TestRun_CancelReturnsPromptly asserts that cancelling ctx drains a running
// session promptly and leaves no goroutine behind.
func TestRun_CancelReturnsPromptly(t *testing.T) {
	skipInjectedSpawnOnDarwin(t)
	defer goleak.VerifyNone(t)

	dir := t.TempDir()
	socket := shortSocketPath(t)
	library := filepath.Join(dir, "libmogate.test")
	tokenFile := filepath.Join(dir, "token")
	writeFile(t, library, "dummy injector")
	writeFile(t, tokenFile, validToken)

	egress := idleListener(t)
	defer func() { _ = egress.Close() }()

	cfg := local.Config{
		EgressAddr:  egress.Addr().String(),
		TokenFile:   tokenFile,
		Socket:      socket,
		InjectorLib: library,
		Modes:       local.Modes{Egress: true},
	}

	ctx, cancel := context.WithCancel(context.Background())
	runErr := make(chan error, 1)
	go func() { runErr <- local.Run(ctx, cfg, []string{"sleep", "60"}) }()

	waitFor(t, 5*time.Second, func() bool { return socketReady(socket) })

	cancel()
	select {
	case <-runErr:
		// Returned; the absence of goroutine leaks is asserted by goleak.
	case <-time.After(10 * time.Second):
		t.Fatal("Run did not drain promptly after ctx cancel")
	}
}

// TestRun_IncomingRequiresTarget asserts that enabling incoming mode without a
// target address fails fast with a clear error rather than silently.
func TestRun_IncomingRequiresTarget(t *testing.T) {
	defer goleak.VerifyNone(t)

	dir := t.TempDir()
	tokenFile := filepath.Join(dir, "token")
	writeFile(t, tokenFile, validToken)

	cfg := local.Config{
		EgressAddr:  "127.0.0.1:0",
		TokenFile:   tokenFile,
		Socket:      filepath.Join(dir, "agent.sock"),
		InjectorLib: filepath.Join(dir, "libmogate.test"),
		Modes:       local.Modes{Egress: true, Incoming: true},
	}
	err := local.Run(context.Background(), cfg, []string{"true"})
	if err == nil {
		t.Fatal("Run succeeded with incoming mode and empty target, want error")
	}
	if !strings.Contains(err.Error(), "target") {
		t.Fatalf("error = %v, want it to mention the missing target", err)
	}
}

// TestRun_CustomStdout asserts that a caller-supplied Stdout (with Pty off)
// receives the injected child's output, exercising the stdio seam end to end
// through Run without disturbing the default stdin/stderr wiring.
func TestRun_CustomStdout(t *testing.T) {
	skipInjectedSpawnOnDarwin(t)
	defer goleak.VerifyNone(t)

	dir := t.TempDir()
	socket := shortSocketPath(t)
	library := filepath.Join(dir, "libmogate.test")
	tokenFile := filepath.Join(dir, "token")
	writeFile(t, library, "dummy injector")
	writeFile(t, tokenFile, validToken)

	egress := idleListener(t)
	defer func() { _ = egress.Close() }()

	var out bytes.Buffer
	cfg := local.Config{
		EgressAddr:  egress.Addr().String(),
		TokenFile:   tokenFile,
		Socket:      socket,
		InjectorLib: library,
		Modes:       local.Modes{Egress: true},
		Stdout:      &out,
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := local.Run(ctx, cfg, []string{"sh", "-c", "echo hi"}); err != nil {
		t.Fatalf("Run returned %v, want nil", err)
	}
	if !strings.Contains(out.String(), "hi") {
		t.Fatalf("custom stdout = %q, want it to contain %q", out.String(), "hi")
	}
}

// TestRun_PtyStreamsAndResizes asserts that with Pty set the child runs on a
// pseudo-terminal whose output reaches the caller's Stdout, that a window size
// delivered on ResizeCh is drained without deadlock, and that no pump goroutine
// outlives the command. Stdin is an empty reader so the input pump ends at once.
func TestRun_PtyStreamsAndResizes(t *testing.T) {
	skipInjectedSpawnOnDarwin(t)
	defer goleak.VerifyNone(t)

	dir := t.TempDir()
	socket := shortSocketPath(t)
	library := filepath.Join(dir, "libmogate.test")
	tokenFile := filepath.Join(dir, "token")
	writeFile(t, library, "dummy injector")
	writeFile(t, tokenFile, validToken)

	egress := idleListener(t)
	defer func() { _ = egress.Close() }()

	resize := make(chan local.Winsize, 1)
	resize <- local.Winsize{Rows: 24, Cols: 80}

	var out bytes.Buffer
	cfg := local.Config{
		EgressAddr:  egress.Addr().String(),
		TokenFile:   tokenFile,
		Socket:      socket,
		InjectorLib: library,
		Modes:       local.Modes{Egress: true},
		Stdin:       bytes.NewReader(nil),
		Stdout:      &out,
		Pty:         true,
		ResizeCh:    resize,
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := local.Run(ctx, cfg, []string{"sh", "-c", "echo hi"}); err != nil {
		t.Fatalf("Run returned %v, want nil", err)
	}
	if !strings.Contains(out.String(), "hi") {
		t.Fatalf("pty stdout = %q, want it to contain %q", out.String(), "hi")
	}
}
