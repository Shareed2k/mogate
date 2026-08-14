package local

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
}

// sipCacheVersion namespaces the on-disk patch cache so a mogate upgrade
// re-patches. Keep in sync with the module version.
const sipCacheVersion = "v1"

// sipEntitlementAllowDyld is the entitlement that already lets dyld honor
// insertion; a binary carrying it never needs patching.
const sipEntitlementAllowDyld = "com.apple.security.cs.allow-dyld-environment-variables"
