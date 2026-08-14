//go:build darwin

package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
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

// TestCSipPatch drives the full C thin+re-sign+cache pipeline end to end:
// mg_sip_patch("/usr/bin/true") must thin the universal (x86_64+arm64e) binary
// to its injectable x86_64 slice, ad-hoc re-sign it, and cache it under
// <HOME>/Library/Caches/mogate/sip/v1/usr/bin/true. HOME is redirected to a temp
// dir so the test is repeatable and self-cleaning. It mirrors the Go
// patchIfRestricted; Task E1 asserts full Go/C cache-path parity.
func TestCSipPatch(t *testing.T) {
	if _, err := os.Stat("/usr/bin/codesign"); err != nil {
		t.Skip("codesign unavailable; mg_sip_patch cannot re-sign")
	}
	home := t.TempDir()
	t.Setenv("HOME", home)

	want := filepath.Join(home, "Library", "Caches", "mogate", "sip", "v1", "usr", "bin", "true")

	res := sipPatch("/usr/bin/true")
	if !res.ok {
		t.Fatalf("mg_sip_patch(/usr/bin/true) returned NULL (err=%q), want a patched path", res.err)
	}
	if res.err != "" {
		t.Fatalf("mg_sip_patch reported last error %q on success", res.err)
	}
	if res.path != want {
		t.Fatalf("patched path = %q, want %q", res.path, want)
	}
	first, err := os.Stat(res.path)
	if err != nil {
		t.Fatalf("patched file missing: %v", err)
	}
	assertAdhocSigned(t, res.path)

	// A second call must reuse the cached copy: same path, same on-disk file.
	res2 := sipPatch("/usr/bin/true")
	if !res2.ok || res2.path != want {
		t.Fatalf("second mg_sip_patch = (%q, ok=%v, err=%q), want reuse of %q",
			res2.path, res2.ok, res2.err, want)
	}
	second, err := os.Stat(res2.path)
	if err != nil {
		t.Fatal(err)
	}
	if !os.SameFile(first, second) {
		t.Error("second call did not reuse the cached file")
	}
}

// TestCSipPatch_NoPatch proves a non-Mach-O file needs no patch: mg_sip_patch
// returns NULL with an empty last error (the "run the original" outcome), as
// distinct from a hard failure (NULL with a non-empty last error).
func TestCSipPatch_NoPatch(t *testing.T) {
	plain := filepath.Join(t.TempDir(), "plain.txt")
	if err := os.WriteFile(plain, []byte("not a mach-o\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	res := sipPatch(plain)
	if res.ok {
		t.Fatalf("mg_sip_patch(%q) = %q, want NULL (no patch needed)", plain, res.path)
	}
	if res.err != "" {
		t.Fatalf("mg_sip_patch(%q) set last error %q, want empty (no patch, not a failure)", plain, res.err)
	}
}

// assertAdhocSigned fails the test unless codesign reports path as ad-hoc signed.
func assertAdhocSigned(t *testing.T, path string) {
	t.Helper()
	out, err := exec.Command("/usr/bin/codesign", "-dvvv", path).CombinedOutput()
	if err != nil {
		t.Fatalf("codesign -dvvv %q: %v\n%s", path, err, out)
	}
	if !strings.Contains(string(out), "adhoc") {
		t.Errorf("codesign output does not report an adhoc signature:\n%s", out)
	}
}
