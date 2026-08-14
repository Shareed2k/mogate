//go:build darwin

package main

import (
	"os"
	"testing"
)

// TestCSipParity_ChooseSlice proves the C slice selector picks the same
// injectable slice as Go's chooseSlice for a real universal system binary:
// /usr/bin/true is x86_64+arm64e, so on any host the only injectable slice is
// x86_64 (arm64e enforces pointer authentication). Full Go-vs-C byte parity on
// golden vectors is asserted in Task E1; here we just prove the C works. The C
// call is bridged through sipChooseSlice (see sip_cgo_bridge_darwin.go), because
// Go forbids `import "C"` in _test.go files.
func TestCSipParity_ChooseSlice(t *testing.T) {
	data, err := os.ReadFile("/usr/bin/true")
	if err != nil {
		t.Fatal(err)
	}
	res := sipChooseSlice(data)
	if !res.ok {
		t.Fatal("mg_sip_choose_slice returned NULL for a universal binary")
	}
	// x86_64/Rosetta slice, non-empty, and in bounds of the file.
	if !res.rosetta || res.size == 0 {
		t.Fatalf("rosetta=%v size=%d, want a non-empty rosetta slice", res.rosetta, res.size)
	}
	if res.off < 0 || res.off+res.size > len(data) {
		t.Fatalf("slice [%d:%d] out of bounds for %d-byte file", res.off, res.off+res.size, len(data))
	}
}

// TestCSipParity_NeedsPatch proves mg_sip_needs_patch agrees with Go's
// needsSIPPatch that a restricted system binary (/usr/bin/curl carries
// SF_RESTRICTED on macOS) would ignore DYLD_INSERT_LIBRARIES and so needs a
// patched copy.
func TestCSipParity_NeedsPatch(t *testing.T) {
	if got := sipNeedsPatch("/usr/bin/curl"); got != 1 {
		t.Fatalf("mg_sip_needs_patch(/usr/bin/curl) = %d, want 1", got)
	}
}
