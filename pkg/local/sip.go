package local

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// sipArch identifies the slice chosen from a (possibly fat) Mach-O.
type sipArch int

const (
	sipArchNative  sipArch = iota // plain arm64 (Apple Silicon) or x86_64 (Intel): the native injector
	sipArchRosetta                // x86_64 slice run under Rosetta on Apple Silicon: the x86_64 injector
)

// sipResult is the outcome of patching one binary.
type sipResult struct {
	path    string  // path to run (patched copy, or the original when patched==false)
	arch    sipArch // which injector the caller should load
	patched bool

	// scriptInterp and scriptArgs are set when the top-level path passed to
	// patchIfRestricted was a "#!" script: scriptInterp is the (possibly
	// patched) interpreter path — the same value as path — and scriptArgs are
	// the shebang's own arguments. The caller builds argv as
	// [scriptInterp, scriptArgs..., scriptPath, origArgs...].
	scriptInterp string
	scriptArgs   []string
}

// sipCacheVersion namespaces the on-disk patch cache so a mogate upgrade
// re-patches. Keep in sync with the module version.
const sipCacheVersion = "v1"

// sipEntitlementAllowDyld is the entitlement that already lets dyld honor
// insertion; a binary carrying it never needs patching.
const sipEntitlementAllowDyld = "com.apple.security.cs.allow-dyld-environment-variables"

// sipCacheDir is the seam tests replace to point the on-disk patch cache at a
// temp directory instead of the real user cache dir.
var sipCacheDir = os.UserCacheDir

// sipCachePath returns the on-disk cache path for the patched copy of orig:
// <sipCacheDir>/mogate/sip/<sipCacheVersion>/<abs(orig) without its leading
// path separator>. Namespacing by the absolute path keeps two distinct
// binaries from colliding; namespacing by sipCacheVersion invalidates every
// cached entry at once on a mogate upgrade.
func sipCachePath(orig string) (string, error) {
	dir, err := sipCacheDir()
	if err != nil {
		return "", fmt.Errorf("sip: user cache dir: %w", err)
	}
	abs, err := filepath.Abs(orig)
	if err != nil {
		return "", fmt.Errorf("sip: abs %q: %w", orig, err)
	}
	rel := strings.TrimPrefix(abs, string(filepath.Separator))
	return filepath.Join(dir, "mogate", "sip", sipCacheVersion, rel), nil
}
