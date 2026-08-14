//go:build !darwin

package local

// needsSIPPatch is a no-op off darwin: no SIP, nothing to patch.
func needsSIPPatch(string) (bool, error) { return false, nil }

// patchIfRestricted is a no-op off darwin: run the binary as given.
func patchIfRestricted(path string) (sipResult, error) {
	return sipResult{path: path, arch: sipArchNative}, nil
}
