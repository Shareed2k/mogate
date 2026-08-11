package local

import (
	"os"
	"runtime"
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
