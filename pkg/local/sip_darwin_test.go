//go:build darwin

package local

import (
	"encoding/binary"
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"
)

// copyFile copies src to dst, failing the test on any error. The copy is a
// plain data copy: it does not preserve extended attributes, code-signature
// validity, or the SF_RESTRICTED file flag (cp semantics on macOS).
func copyFile(t *testing.T, src, dst string) {
	t.Helper()
	in, err := os.Open(src)
	if err != nil {
		t.Fatalf("open %q: %v", src, err)
	}
	defer in.Close()
	out, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o700)
	if err != nil {
		t.Fatalf("create %q: %v", dst, err)
	}
	defer out.Close()
	if _, err := io.Copy(out, in); err != nil {
		t.Fatalf("copy %q -> %q: %v", src, dst, err)
	}
}

func TestNeedsSIPPatch(t *testing.T) {
	t.Run("SF_RESTRICTED system binary is restricted", func(t *testing.T) {
		// /usr/bin/curl carries the SF_RESTRICTED file flag on macOS.
		got, err := needsSIPPatch("/usr/bin/curl")
		if err != nil {
			t.Fatalf("needsSIPPatch: %v", err)
		}
		if !got {
			t.Fatal("expected /usr/bin/curl to be restricted")
		}
	})

	t.Run("a plain unsigned copy is not restricted", func(t *testing.T) {
		dir := t.TempDir()
		dst := filepath.Join(dir, "curl")
		copyFile(t, "/usr/bin/curl", dst) // cp drops SF_RESTRICTED; still platform cdhash, but no CS RESTRICT/RUNTIME flags
		got, err := needsSIPPatch(dst)
		if err != nil {
			t.Fatalf("needsSIPPatch: %v", err)
		}
		// A bare copy of curl has flags=0x0 and no SF_RESTRICTED -> our
		// file+CS-flag detection returns false. (Platform-binary cdhash is not
		// file-detectable; the copy is what we ultimately run anyway.)
		if got {
			t.Fatal("expected a plain copy to be un-restricted by file+CS-flag detection")
		}
	})

	t.Run("non-existent path errors", func(t *testing.T) {
		if _, err := needsSIPPatch(filepath.Join(t.TempDir(), "nope")); err == nil {
			t.Fatal("expected error for missing file")
		}
	})

	t.Run("non-mach-o is not restricted", func(t *testing.T) {
		dir := t.TempDir()
		p := filepath.Join(dir, "hello.txt")
		if err := os.WriteFile(p, []byte("hello\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		got, err := needsSIPPatch(p)
		if err != nil {
			t.Fatalf("needsSIPPatch: %v", err)
		}
		if got {
			t.Fatal("expected a text file to be un-restricted")
		}
	})
}

func TestChooseSlice(t *testing.T) {
	t.Run("universal system binary yields x86_64 on apple silicon", func(t *testing.T) {
		data, err := os.ReadFile("/usr/bin/true") // universal x86_64+arm64e
		if err != nil {
			t.Fatal(err)
		}
		slice, arch, err := chooseSlice(data)
		if err != nil {
			t.Fatalf("chooseSlice: %v", err)
		}
		if !isMachO(slice) || isFat(slice) {
			t.Fatal("expected a thin slice")
		}
		// system binaries are x86_64+arm64e -> x86_64/Rosetta
		if arch != sipArchRosetta {
			t.Fatalf("arch=%v, want Rosetta(x86_64)", arch)
		}
		if got := thinCPUType(slice); got != cpuTypeX8664 {
			t.Fatalf("slice cpu=%#x, want x86_64", got)
		}
	})

	t.Run("thin plain arm64 binary is native and returned whole", func(t *testing.T) {
		data := thinMachHeader(cpuTypeArm64, 0) // subtype ALL, not arm64e
		slice, arch, err := chooseSlice(data)
		if err != nil {
			t.Fatalf("chooseSlice: %v", err)
		}
		if arch != sipArchNative {
			t.Fatalf("arch=%v, want Native(arm64)", arch)
		}
		if string(slice) != string(data) {
			t.Fatal("expected the whole thin file to be returned")
		}
	})

	t.Run("thin x86_64 binary is rosetta and returned whole", func(t *testing.T) {
		data := thinMachHeader(cpuTypeX8664, 0)
		slice, arch, err := chooseSlice(data)
		if err != nil {
			t.Fatalf("chooseSlice: %v", err)
		}
		if arch != sipArchRosetta {
			t.Fatalf("arch=%v, want Rosetta(x86_64)", arch)
		}
		if string(slice) != string(data) {
			t.Fatal("expected the whole thin file to be returned")
		}
	})

	t.Run("thin arm64e-only binary has no injectable slice", func(t *testing.T) {
		data := thinMachHeader(cpuTypeArm64, 0x80000000|cpuSubtypeArm64E) // capability bits + arm64e subtype
		_, _, err := chooseSlice(data)
		if !errors.Is(err, ErrNoInjectableSlice) {
			t.Fatalf("err=%v, want ErrNoInjectableSlice", err)
		}
	})

	t.Run("crafted fat header with out-of-bounds slice size errors instead of panicking", func(t *testing.T) {
		data := fatMachWithBogusSize(t)
		_, _, err := chooseSlice(data)
		if err == nil {
			t.Fatal("expected an out-of-bounds error, got nil")
		}
	})
}

// thinMachHeader builds a minimal, valid thin 64-bit Mach-O header (no load
// commands) for the given cpu/subtype, sufficient for debug/macho.NewFile to
// parse.
func thinMachHeader(cpu uint32, subCPU uint32) []byte {
	buf := make([]byte, 32)
	binary.LittleEndian.PutUint32(buf[0:4], 0xfeedfacf) // MH_MAGIC_64
	binary.LittleEndian.PutUint32(buf[4:8], cpu)
	binary.LittleEndian.PutUint32(buf[8:12], subCPU)
	binary.LittleEndian.PutUint32(buf[12:16], 0x2) // MH_EXECUTE
	binary.LittleEndian.PutUint32(buf[16:20], 0)   // ncmds
	binary.LittleEndian.PutUint32(buf[20:24], 0)   // sizeofcmds
	binary.LittleEndian.PutUint32(buf[24:28], 0)   // flags
	binary.LittleEndian.PutUint32(buf[28:32], 0)   // reserved
	return buf
}

// fatMachWithBogusSize builds a fat Mach-O with one plain-arm64 arch whose
// declared FatArchHeader.Size extends far past the end of the buffer.
// debug/macho.NewFatFile accepts this (it only needs to read the thin
// header's fixed-size fields, not `Size` bytes), so chooseSlice must itself
// bounds-check before slicing data on the arch's offset/size.
func fatMachWithBogusSize(t *testing.T) []byte {
	t.Helper()
	thin := thinMachHeader(cpuTypeArm64, 0)
	buf := make([]byte, 8+20+len(thin))
	binary.BigEndian.PutUint32(buf[0:4], 0xcafebabe) // fat magic
	binary.BigEndian.PutUint32(buf[4:8], 1)          // nfat_arch
	binary.BigEndian.PutUint32(buf[8:12], cpuTypeArm64)
	binary.BigEndian.PutUint32(buf[12:16], 0)     // subtype: plain
	binary.BigEndian.PutUint32(buf[16:20], 28)    // offset of thin header
	binary.BigEndian.PutUint32(buf[20:24], 1<<30) // size: absurdly past EOF
	binary.BigEndian.PutUint32(buf[24:28], 0)     // align
	copy(buf[28:], thin)
	return buf
}
