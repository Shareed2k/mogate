//go:build darwin && sip_rosetta

// This is an opt-in macOS integration test for the SIP exec-interposer path. It
// reproduces the child-exec recursion that a plain `go test` cannot: the bug
// only manifests in the real, loaded injector dylib under Rosetta, where the
// __DATA,__interpose table also rewrites dlsym results — so resolving the real
// execve via dlsym returned our own hook and the detour recursed forever. A
// unit-test binary has no __interpose table, so this must run against a built
// dylib injected into a real x86_64 process.
//
// Run with:  go test -tags 'darwin sip_rosetta' -run TestSIPExecNoRecursion ./injector/
// Requires: an Apple-Silicon host with Rosetta 2, clang, lipo, codesign, curl,
// and a generated injector/protocol_generated.h (`go generate ./internal/protocol`).

package main

import (
	"bytes"
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

func TestSIPExecNoRecursion(t *testing.T) {
	for _, tool := range []string{"/usr/bin/clang", "/usr/bin/lipo", "/usr/bin/codesign", "/bin/bash", "/usr/bin/curl"} {
		if _, err := os.Stat(tool); err != nil {
			t.Skipf("missing %s: %v", tool, err)
		}
	}
	if _, err := os.Stat("protocol_generated.h"); err != nil {
		t.Skip("protocol_generated.h missing; run: go generate ./internal/protocol")
	}
	// Require Rosetta: an x86_64 helper must actually run.
	if err := exec.Command("/usr/bin/arch", "-x86_64", "/usr/bin/true").Run(); err != nil {
		t.Skipf("Rosetta 2 not available (arch -x86_64 failed: %v)", err)
	}

	tmp := t.TempDir()

	// 1. Build the x86_64 injector dylib from main.go's cgo block, exactly like
	//    the Makefile (extract the C between /* */, drop #cgo lines, compile).
	dylib := filepath.Join(tmp, "injector-x86_64.dylib")
	build := exec.Command("/bin/bash", "-c",
		`sed -n '/^\/\*$/,/^\*\/$/p' main.go | sed '1d;$d;/^#cgo /d' | `+
			`/usr/bin/clang -x c -Iinjector -I. -O2 -fPIC -arch x86_64 -dynamiclib `+
			`-Wno-deprecated-declarations -ldl -pthread -o `+dylib+` -`)
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build x86_64 injector: %v\n%s", err, out)
	}

	// 2. Make a SIP-patched (thinned + ad-hoc-resigned) x86_64 bash, mirroring
	//    what pkg/local does to a restricted top-level binary.
	bashx := filepath.Join(tmp, "bashx")
	if out, err := exec.Command("/usr/bin/lipo", "/bin/bash", "-thin", "x86_64", "-output", bashx).CombinedOutput(); err != nil {
		t.Fatalf("lipo thin bash: %v\n%s", err, out)
	}
	_ = exec.Command("/usr/bin/codesign", "--remove-signature", bashx).Run()
	if out, err := exec.Command("/usr/bin/codesign", "-s", "-", "-f", bashx).CombinedOutput(); err != nil {
		t.Fatalf("codesign bashx: %v\n%s", err, out)
	}

	// 3. Run a CHILD exec (bash spawns curl) with the injector loaded. Before the
	//    fix this recursed forever in mg_execve_hook -> mg_sip_execve_detour ->
	//    mg_execve_hook; the context deadline is the regression tripwire. curl
	//    --version makes no network calls, so the relay is never contacted — this
	//    isolates the exec path. MOGATE_SOCKET must be set for the exec hook to
	//    activate; a dead path is fine because --version does no egress.
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, bashx, "-c", "curl --version")
	cmd.Env = append(os.Environ(),
		"DYLD_INSERT_LIBRARIES="+dylib,
		"MOGATE_SOCKET="+filepath.Join(tmp, "relay.sock"),
	)
	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &out
	err := cmd.Run()

	if ctx.Err() == context.DeadlineExceeded {
		t.Fatalf("child exec (bash -> curl) hung: exec interposer recursed instead of calling the real execve\noutput:\n%s", out.String())
	}
	if err != nil {
		t.Fatalf("child exec failed: %v\noutput:\n%s", err, out.String())
	}
	if !bytes.Contains(out.Bytes(), []byte("curl ")) {
		t.Fatalf("expected curl --version output, got:\n%s", out.String())
	}
}
