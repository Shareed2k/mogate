package local

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"

	"go.uber.org/goleak"

	"github.com/shareed2k/mogate/internal/protocol"
)

// loaderVariable is the platform environment variable that loads the injector.
func loaderVariable() string {
	if runtime.GOOS == "darwin" {
		return "DYLD_INSERT_LIBRARIES"
	}
	return "LD_PRELOAD"
}

// findEnv returns the value of key in env, or ("", false) when absent.
func findEnv(env []string, key string) (string, bool) {
	prefix := key + "="
	for _, item := range env {
		if len(item) >= len(prefix) && item[:len(prefix)] == prefix {
			return item[len(prefix):], true
		}
	}
	return "", false
}

func TestResolveExecutable(t *testing.T) {
	// A bare name found on PATH resolves to an absolute path, mirroring what a
	// shell (and exec.Command) does at spawn time.
	resolved, err := resolveExecutable("true")
	if err != nil {
		t.Fatalf("resolveExecutable(%q) unexpected error: %v", "true", err)
	}
	if !filepath.IsAbs(resolved) {
		t.Fatalf("resolveExecutable(%q) = %q, want an absolute path", "true", resolved)
	}

	// A name that already contains a path separator is a path, not a PATH
	// lookup, and is returned verbatim (never consulting PATH).
	for _, name := range []string{"/usr/bin/true", "./x"} {
		got, err := resolveExecutable(name)
		if err != nil {
			t.Fatalf("resolveExecutable(%q) unexpected error: %v", name, err)
		}
		if got != name {
			t.Fatalf("resolveExecutable(%q) = %q, want it returned unchanged", name, got)
		}
	}

	// A bare name that is not on PATH fails loud rather than resolving to a
	// bogus or cwd-relative target.
	const bogus = "definitely-not-a-real-binary-xyz"
	if _, err := resolveExecutable(bogus); err == nil {
		t.Fatalf("resolveExecutable(%q) error = nil, want a lookup failure", bogus)
	}
}

func TestInjectedEnvironment_SetsLoaderAndSocket(t *testing.T) {
	loader := loaderVariable()
	const library = "/opt/mogate/libmogate.so"

	env := injectedEnvironment(nil, injectionOptions{socket: "/run/mogate/agent.sock", files: true}, library)

	if got, ok := findEnv(env, loader); !ok || got != library {
		t.Fatalf("%s = %q (present=%v), want %q", loader, got, ok, library)
	}
	if got, ok := findEnv(env, "MOGATE_SOCKET"); !ok || got != "/run/mogate/agent.sock" {
		t.Fatalf("MOGATE_SOCKET = %q (present=%v), want %q", got, ok, "/run/mogate/agent.sock")
	}
	if got, _ := findEnv(env, "MOGATE_FILE_MODE"); got != "remote" {
		t.Fatalf("MOGATE_FILE_MODE = %q, want remote", got)
	}
}

func TestInjectedEnvironment_FilesOffSelectsLocalMode(t *testing.T) {
	env := injectedEnvironment(nil, injectionOptions{socket: "/s", files: false}, "/lib.so")
	if got, _ := findEnv(env, "MOGATE_FILE_MODE"); got != "local" {
		t.Fatalf("MOGATE_FILE_MODE = %q, want local", got)
	}
}

func TestInjectedEnvironment_PreservesExistingLoaderValue(t *testing.T) {
	loader := loaderVariable()
	existing := "/existing/hook.so"
	base := []string{loader + "=" + existing}

	env := injectedEnvironment(base, injectionOptions{socket: "/s", files: true}, "/lib.so")

	want := "/lib.so" + string(os.PathListSeparator) + existing
	if got, _ := findEnv(env, loader); got != want {
		t.Fatalf("%s = %q, want %q", loader, got, want)
	}
}

func TestSelectInjector(t *testing.T) {
	const (
		native  = "/opt/mogate/libmogate.arm64.so"
		rosetta = "/opt/mogate/libmogate.x86_64.so"
	)
	options := injectionOptions{library: native, libraryRosetta: rosetta}

	tests := []struct {
		name    string
		options injectionOptions
		res     sipResult
		want    string
		wantErr bool
	}{
		{
			name:    "native arch returns library",
			options: options,
			res:     sipResult{path: "/usr/bin/true", arch: sipArchNative},
			want:    native,
		},
		{
			name:    "rosetta arch returns rosetta library",
			options: options,
			res:     sipResult{path: "/bin/ping", arch: sipArchRosetta},
			want:    rosetta,
		},
		{
			name:    "rosetta arch with unset rosetta library fails loud",
			options: injectionOptions{library: native},
			res:     sipResult{path: "/bin/ping", arch: sipArchRosetta},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := selectInjector(tt.options, tt.res)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("selectInjector() error = nil, want an error")
				}
				if !strings.Contains(err.Error(), tt.res.path) {
					t.Fatalf("selectInjector() error = %q, want it to name the binary %q", err, tt.res.path)
				}
				return
			}
			if err != nil {
				t.Fatalf("selectInjector() unexpected error: %v", err)
			}
			if got != tt.want {
				t.Fatalf("selectInjector() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestAssembleExec(t *testing.T) {
	t.Run("non-script runs the patched path but keeps the original argv[0]", func(t *testing.T) {
		// execute() captures origArg0 as the name the user passed, then (on
		// darwin) rewrites command[0] to the resolved binary before patching.
		// assembleExec must run the PATCHED path (res.path) while argv[0] stays
		// the original name -- matching the C child detour, which execs the
		// patched path with the caller's argv unchanged.
		origArg0 := "curl"
		command := []string{"/usr/bin/curl", "http://svc"}
		res := sipResult{path: "/cache/mogate/sip/v1/usr/bin/curl", arch: sipArchRosetta, patched: true}

		execPath, argv := assembleExec(origArg0, command, res)

		if execPath != res.path {
			t.Fatalf("execPath = %q, want the patched path %q", execPath, res.path)
		}
		want := []string{"curl", "http://svc"}
		if !slices.Equal(argv, want) {
			t.Fatalf("argv = %v, want %v", argv, want)
		}
		if argv[0] != origArg0 {
			t.Fatalf("argv[0] = %q, want the original name %q", argv[0], origArg0)
		}
		// The returned argv must not alias command: rewriting argv[0] must not
		// mutate the caller's slice.
		if command[0] != "/usr/bin/curl" {
			t.Fatalf("command[0] mutated to %q; assembleExec must not alias command", command[0])
		}
	})

	t.Run("unpatched non-script still restores the original argv[0]", func(t *testing.T) {
		// With no patch (the off-darwin no-op result) res.path == command[0] and
		// argv[0] is still the original name -- byte-identical to a plain
		// exec.Command(name), which sets Args[0] to the name it was given.
		origArg0 := "mytool"
		command := []string{"/abs/mytool", "-v"}
		res := sipResult{path: "/abs/mytool", arch: sipArchNative, patched: false}

		execPath, argv := assembleExec(origArg0, command, res)

		if execPath != "/abs/mytool" {
			t.Fatalf("execPath = %q, want %q", execPath, "/abs/mytool")
		}
		if !slices.Equal(argv, []string{"mytool", "-v"}) {
			t.Fatalf("argv = %v, want [mytool -v]", argv)
		}
	})

	t.Run("script runs the interpreter as program and argv[0], then shebang args, script, and original args", func(t *testing.T) {
		// For a "#!" script the (possibly patched) interpreter is both the
		// program and argv[0]; command[0] here is the resolved script path.
		origArg0 := "./deploy.sh"
		command := []string{"/work/deploy.sh", "prod"}
		res := sipResult{
			path:         "/cache/bin/bash",
			arch:         sipArchRosetta,
			patched:      true,
			scriptInterp: "/cache/bin/bash",
			scriptArgs:   []string{"-x"},
		}

		execPath, argv := assembleExec(origArg0, command, res)

		if execPath != res.scriptInterp {
			t.Fatalf("execPath = %q, want the interpreter %q", execPath, res.scriptInterp)
		}
		want := []string{"/cache/bin/bash", "-x", "/work/deploy.sh", "prod"}
		if !slices.Equal(argv, want) {
			t.Fatalf("argv = %v, want %v", argv, want)
		}
	})
}

// sortedKeys returns the keys of m in sorted order, for deterministic asserts.
func sortedKeys(m map[string]string) []string {
	keys := make([]string, 0, len(m))
	for key := range m {
		keys = append(keys, key)
	}
	slices.Sort(keys)
	return keys
}

func TestFilterEnv(t *testing.T) {
	tests := []struct {
		name    string
		target  map[string]string
		include []string
		exclude []string
		want    map[string]string
	}{
		{
			name: "default denylist keeps local execution and toolchain paths",
			target: map[string]string{
				"DATABASE_URL": "postgres://remote",
				"PATH":         "/remote/bin",
				"HOME":         "/root",
				"GOPATH":       "/remote/go",
				"PYTHONPATH":   "/remote/py",
				"JAVA_HOME":    "/remote/java",
			},
			want: map[string]string{"DATABASE_URL": "postgres://remote"},
		},
		{
			name: "include restricts to listed keys, still minus defaults",
			target: map[string]string{
				"FOO":  "1",
				"BAR":  "2",
				"PATH": "/remote/bin",
			},
			include: []string{"FOO", "PATH"},
			want:    map[string]string{"FOO": "1"},
		},
		{
			name: "exclude drops a key on top of the defaults",
			target: map[string]string{
				"SECRET": "shhh",
				"FOO":    "1",
			},
			exclude: []string{"SECRET"},
			want:    map[string]string{"FOO": "1"},
		},
		{
			name: "BUNDLER_ORIG_ prefix is always dropped",
			target: map[string]string{
				"BUNDLER_ORIG_PATH":     "/remote/bin",
				"BUNDLER_ORIG_GEM_HOME": "/remote/gems",
				"OK":                    "keep",
			},
			want: map[string]string{"OK": "keep"},
		},
		{
			name:   "empty target yields empty overlay",
			target: map[string]string{},
			want:   map[string]string{},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Snapshot the input to prove filterEnv never mutates its argument.
			before := sortedKeys(tt.target)

			got := filterEnv(tt.target, tt.include, tt.exclude)

			if !slices.Equal(sortedKeys(got), sortedKeys(tt.want)) {
				t.Fatalf("filterEnv keys = %v, want %v", sortedKeys(got), sortedKeys(tt.want))
			}
			for key, want := range tt.want {
				if got[key] != want {
					t.Fatalf("filterEnv[%q] = %q, want %q", key, got[key], want)
				}
			}
			if !slices.Equal(before, sortedKeys(tt.target)) {
				t.Fatalf("filterEnv mutated its target argument")
			}
		})
	}
}

func TestParseEnvPayload(t *testing.T) {
	tests := []struct {
		name string
		data string
		want map[string]string
	}{
		{
			name: "newline separated key value pairs",
			data: "A=1\nB=2\nC=3",
			want: map[string]string{"A": "1", "B": "2", "C": "3"},
		},
		{
			name: "value may contain equals signs",
			data: "URL=scheme://h?a=b&c=d",
			want: map[string]string{"URL": "scheme://h?a=b&c=d"},
		},
		{
			name: "blank lines and malformed entries are skipped",
			data: "A=1\n\nnoeq\n=novalue\nB=2",
			want: map[string]string{"A": "1", "B": "2"},
		},
		{
			name: "empty payload yields empty map",
			data: "",
			want: map[string]string{},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := parseEnvPayload([]byte(tt.data))
			if !slices.Equal(sortedKeys(got), sortedKeys(tt.want)) {
				t.Fatalf("parseEnvPayload keys = %v, want %v", sortedKeys(got), sortedKeys(tt.want))
			}
			for key, want := range tt.want {
				if got[key] != want {
					t.Fatalf("parseEnvPayload[%q] = %q, want %q", key, got[key], want)
				}
			}
		})
	}
}

func TestInjectedEnvironment_OverlaysTargetEnv(t *testing.T) {
	loader := loaderVariable()
	const (
		socket  = "/run/mogate/agent.sock"
		library = "/opt/mogate/libmogate.so"
	)
	base := []string{"DATABASE_URL=local-value", "KEEP=1"}
	targetEnv := map[string]string{
		"DATABASE_URL":  "remote-value",
		"NEWVAR":        "x",
		"MOGATE_SOCKET": "attacker-supplied",
	}

	env := injectedEnvironment(base, injectionOptions{socket: socket, files: false, targetEnv: targetEnv}, library)

	// A target var wins over a local var of the same name.
	if got, ok := findEnv(env, "DATABASE_URL"); !ok || got != "remote-value" {
		t.Fatalf("DATABASE_URL = %q (present=%v), want remote-value (remote wins)", got, ok)
	}
	// A target-only var is overlaid.
	if got, ok := findEnv(env, "NEWVAR"); !ok || got != "x" {
		t.Fatalf("NEWVAR = %q (present=%v), want x", got, ok)
	}
	// A local-only var is preserved.
	if got, ok := findEnv(env, "KEEP"); !ok || got != "1" {
		t.Fatalf("KEEP = %q (present=%v), want 1", got, ok)
	}
	// The injector variables still win over any same-named target value.
	if got, _ := findEnv(env, "MOGATE_SOCKET"); got != socket {
		t.Fatalf("MOGATE_SOCKET = %q, want %q (injector wins over target)", got, socket)
	}
	if got, ok := findEnv(env, loader); !ok || got != library {
		t.Fatalf("%s = %q (present=%v), want %q", loader, got, ok, library)
	}
}

// TestInjectedEnvironment_NoOverlayIsByteIdentical pins the Modes.Env=false
// behavior: with a nil (or empty) targetEnv the injected environment is exactly
// the pre-overlay output -- the base entries verbatim and in order, followed by
// only the injector variables. It must never change when the overlay is off.
func TestInjectedEnvironment_NoOverlayIsByteIdentical(t *testing.T) {
	base := []string{"PATH=/usr/bin", "DATABASE_URL=local", "FOO=bar"}
	options := injectionOptions{socket: "/s", files: false, library: "/lib.so", libraryRosetta: "/lib.rosetta.so"}

	withNil := injectedEnvironment(slices.Clone(base), options, "/lib.so")
	withEmpty := injectedEnvironment(slices.Clone(base), withTargetEnv(options, map[string]string{}), "/lib.so")

	if !slices.Equal(withNil, withEmpty) {
		t.Fatalf("nil overlay = %v, empty-map overlay = %v; want identical", withNil, withEmpty)
	}
	// Base entries are preserved verbatim, at their original positions.
	for i, want := range base {
		if withNil[i] != want {
			t.Fatalf("base entry %d = %q, want %q (no-overlay must not perturb base)", i, withNil[i], want)
		}
	}
	// Everything appended past the base is a known injector variable -- no target
	// key leaked in.
	allowed := map[string]struct{}{
		"MOGATE_SOCKET":          {},
		"MOGATE_FILE_MODE":       {},
		loaderVariable():         {},
		"MOGATE_INJECTOR_ARM64":  {},
		"MOGATE_INJECTOR_X86_64": {},
	}
	for _, item := range withNil[len(base):] {
		key, _, _ := strings.Cut(item, "=")
		if _, ok := allowed[key]; !ok {
			t.Fatalf("unexpected appended env key %q with no overlay", key)
		}
	}
}

// withTargetEnv returns a copy of options with targetEnv set, keeping the test
// intent (overlay off vs a specific overlay) explicit at the call site.
func withTargetEnv(options injectionOptions, targetEnv map[string]string) injectionOptions {
	options.targetEnv = targetEnv
	return options
}

// envShortSocket returns a Unix socket path in a private 0700 temp dir short
// enough for the platform sun_path limit (t.TempDir embeds the test name and
// can overflow it on macOS).
func envShortSocket(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("", "mg")
	if err != nil {
		t.Fatalf("make socket dir: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	return filepath.Join(dir, "s.sock")
}

// fakeEnvAgent stands in for the relay+agent: it accepts one connection, reads
// the request frame, asserts it is OpEnvGet, and replies with an OpEnvGet
// status frame carrying errno and payload. It returns a channel closed when the
// serving goroutine exits, so goleak sees no leak.
func fakeEnvAgent(t *testing.T, socket string, errno int32, payload string) <-chan struct{} {
	t.Helper()
	listener, err := net.Listen("unix", socket)
	if err != nil {
		t.Fatalf("listen fake agent: %v", err)
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		defer func() { _ = listener.Close() }()
		conn, acceptErr := listener.Accept()
		if acceptErr != nil {
			return
		}
		defer func() { _ = conn.Close() }()
		frame, readErr := protocol.ReadFrame(conn)
		if readErr != nil {
			t.Errorf("fake agent read frame: %v", readErr)
			return
		}
		if frame.Operation != protocol.OpEnvGet {
			t.Errorf("fake agent operation = %d, want OpEnvGet (%d)", frame.Operation, protocol.OpEnvGet)
			return
		}
		if writeErr := protocol.WriteFrame(conn, protocol.Frame{
			Operation: protocol.OpEnvGet,
			Payload:   protocol.StatusPayload(errno, []byte(payload)),
		}); writeErr != nil {
			t.Errorf("fake agent write frame: %v", writeErr)
		}
	}()
	return done
}

func TestFetchTargetEnv(t *testing.T) {
	t.Run("success parses the KEY=VALUE payload", func(t *testing.T) {
		defer goleak.VerifyNone(t)
		socket := envShortSocket(t)
		done := fakeEnvAgent(t, socket, 0, "A=1\nDATABASE_URL=postgres://x\nB=2")
		defer func() { <-done }()

		got, err := fetchTargetEnv(context.Background(), socket)
		if err != nil {
			t.Fatalf("fetchTargetEnv unexpected error: %v", err)
		}
		want := map[string]string{"A": "1", "DATABASE_URL": "postgres://x", "B": "2"}
		if !slices.Equal(sortedKeys(got), sortedKeys(want)) {
			t.Fatalf("fetchTargetEnv keys = %v, want %v", sortedKeys(got), sortedKeys(want))
		}
		for key, value := range want {
			if got[key] != value {
				t.Fatalf("fetchTargetEnv[%q] = %q, want %q", key, got[key], value)
			}
		}
	})

	t.Run("non-zero agent status is an error and skips the overlay", func(t *testing.T) {
		defer goleak.VerifyNone(t)
		socket := envShortSocket(t)
		done := fakeEnvAgent(t, socket, 13 /* EACCES */, "")
		defer func() { <-done }()

		if _, err := fetchTargetEnv(context.Background(), socket); err == nil {
			t.Fatal("fetchTargetEnv error = nil, want an error for a non-zero agent status")
		}
	})

	t.Run("empty payload yields an empty overlay, not an error", func(t *testing.T) {
		defer goleak.VerifyNone(t)
		socket := envShortSocket(t)
		done := fakeEnvAgent(t, socket, 0, "")
		defer func() { <-done }()

		got, err := fetchTargetEnv(context.Background(), socket)
		if err != nil {
			t.Fatalf("fetchTargetEnv unexpected error: %v", err)
		}
		if len(got) != 0 {
			t.Fatalf("fetchTargetEnv = %v, want an empty overlay", got)
		}
	})

	t.Run("dial failure is a plain error with no overlay", func(t *testing.T) {
		defer goleak.VerifyNone(t)
		missing := filepath.Join(t.TempDir(), "does-not-exist.sock")
		if _, err := fetchTargetEnv(context.Background(), missing); err == nil {
			t.Fatal("fetchTargetEnv error = nil, want a dial failure")
		}
	})
}
