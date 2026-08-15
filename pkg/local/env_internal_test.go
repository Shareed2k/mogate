package local

import (
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"
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
