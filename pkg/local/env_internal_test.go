package local

import (
	"os"
	"path/filepath"
	"runtime"
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
