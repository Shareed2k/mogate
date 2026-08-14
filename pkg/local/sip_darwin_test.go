//go:build darwin

package local

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
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

func TestAdhocResign(t *testing.T) {
	t.Run("removes existing signature then applies an ad-hoc signature", func(t *testing.T) {
		var calls [][]string
		orig := codesignRunner
		codesignRunner = func(args ...string) error {
			calls = append(calls, append([]string(nil), args...))
			return nil
		}
		defer func() { codesignRunner = orig }()

		p := "/tmp/fixture/binary"
		if err := adhocResign(p); err != nil {
			t.Fatalf("adhocResign: %v", err)
		}

		want := [][]string{
			{"--remove-signature", p},
			{"-s", "-", "-f", p},
		}
		if len(calls) != len(want) {
			t.Fatalf("calls = %v, want %v", calls, want)
		}
		for i, wantArgs := range want {
			if len(calls[i]) != len(wantArgs) {
				t.Fatalf("call %d = %v, want %v", i, calls[i], wantArgs)
			}
			for j, wantArg := range wantArgs {
				if calls[i][j] != wantArg {
					t.Fatalf("call %d = %v, want %v", i, calls[i], wantArgs)
				}
			}
		}
	})

	t.Run("tolerates the not-signed no-op error from --remove-signature", func(t *testing.T) {
		orig := codesignRunner
		codesignRunner = func(args ...string) error {
			if args[0] == "--remove-signature" {
				return errors.New("object: /tmp/fixture/binary\ncode object is not signed at all")
			}
			return nil
		}
		defer func() { codesignRunner = orig }()

		if err := adhocResign("/tmp/fixture/binary"); err != nil {
			t.Fatalf("adhocResign: %v", err)
		}
	})

	t.Run("wraps the ad-hoc sign failure", func(t *testing.T) {
		sentinel := errors.New("boom")
		orig := codesignRunner
		codesignRunner = func(args ...string) error {
			if args[0] == "-s" {
				return sentinel
			}
			return nil
		}
		defer func() { codesignRunner = orig }()

		err := adhocResign("/tmp/fixture/binary")
		if err == nil {
			t.Fatal("expected an error")
		}
		if !errors.Is(err, sentinel) {
			t.Fatalf("err = %v, want it to wrap %v", err, sentinel)
		}
	})

	t.Run("integration: really ad-hoc signs a thinned /usr/bin/true copy", func(t *testing.T) {
		if testing.Short() {
			t.Skip("skipping codesign integration test in short mode")
		}
		dir := t.TempDir()
		dst := filepath.Join(dir, "true")
		copyFile(t, "/usr/bin/true", dst)

		data, err := os.ReadFile(dst)
		if err != nil {
			t.Fatal(err)
		}
		slice, _, err := chooseSlice(data)
		if err != nil {
			t.Fatalf("chooseSlice: %v", err)
		}
		if err := os.WriteFile(dst, slice, 0o700); err != nil {
			t.Fatal(err)
		}

		if err := adhocResign(dst); err != nil {
			t.Fatalf("adhocResign: %v", err)
		}

		out, err := exec.Command("/usr/bin/codesign", "-dvvv", dst).CombinedOutput()
		if err != nil {
			t.Fatalf("codesign -dvvv %q: %v\n%s", dst, err, out)
		}
		if !bytes.Contains(out, []byte("adhoc")) {
			t.Fatalf("expected codesign -dvvv output to mention \"adhoc\", got:\n%s", out)
		}
	})
}

func TestReadShebang(t *testing.T) {
	writeFile := func(t *testing.T, data []byte) string {
		t.Helper()
		dir := t.TempDir()
		p := filepath.Join(dir, "script")
		if err := os.WriteFile(p, data, 0o700); err != nil {
			t.Fatal(err)
		}
		return p
	}

	tests := []struct {
		name       string
		data       []byte
		wantInterp string
		wantArgs   []string
		wantOK     bool
	}{
		{
			name:       "simple bash shebang",
			data:       []byte("#!/bin/bash\n"),
			wantInterp: "/bin/bash",
			wantArgs:   nil,
			wantOK:     true,
		},
		{
			name:       "env with an interpreter argument",
			data:       []byte("#!/usr/bin/env python3\n"),
			wantInterp: "/usr/bin/env",
			wantArgs:   []string{"python3"},
			wantOK:     true,
		},
		{
			name:       "leading spaces after #! are ignored",
			data:       []byte("#!   /bin/sh -e\n"),
			wantInterp: "/bin/sh",
			wantArgs:   []string{"-e"},
			wantOK:     true,
		},
		{
			name:   "a mach-o binary has no shebang",
			data:   thinMachHeader(cpuTypeArm64, 0),
			wantOK: false,
		},
		{
			name:   "empty file",
			data:   nil,
			wantOK: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := writeFile(t, tt.data)
			interp, args, ok, err := readShebang(p)
			if err != nil {
				t.Fatalf("readShebang: %v", err)
			}
			if ok != tt.wantOK {
				t.Fatalf("ok = %v, want %v", ok, tt.wantOK)
			}
			if !tt.wantOK {
				return
			}
			if interp != tt.wantInterp {
				t.Fatalf("interp = %q, want %q", interp, tt.wantInterp)
			}
			if !slices.Equal(args, tt.wantArgs) {
				t.Fatalf("args = %v, want %v", args, tt.wantArgs)
			}
		})
	}

	t.Run("a read error is wrapped", func(t *testing.T) {
		_, _, _, err := readShebang(filepath.Join(t.TempDir(), "nope"))
		if err == nil {
			t.Fatal("expected an error for a missing file")
		}
	})
}
