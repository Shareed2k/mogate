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

// withTempSipCache points the sipCacheDir seam at a fresh temp directory for
// the duration of the calling test, restoring it on cleanup.
func withTempSipCache(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	orig := sipCacheDir
	sipCacheDir = func() (string, error) { return dir, nil }
	t.Cleanup(func() { sipCacheDir = orig })
	return dir
}

// restrictedThinMachHeader builds a minimal thin 64-bit Mach-O for the given
// cpu/subtype, carrying a hand-built LC_CODE_SIGNATURE whose CodeDirectory
// flags set CS_RUNTIME. needsSIPPatch treats that the same as the
// SF_RESTRICTED file flag, which an unprivileged test process cannot set via
// chflags on an arbitrary file (macOS requires a private entitlement/root).
func restrictedThinMachHeader(cpu, subCPU uint32) []byte {
	const (
		headerSize     = 32
		loadCmdSize    = 16
		superBlobSize  = 12 + csBlobIndexSize + 16 // superblob header + 1 index + 1 CodeDirectory
		codeDirOffset  = 12 + csBlobIndexSize      // CodeDirectory offset within the superblob
		dataOff        = headerSize + loadCmdSize
		totalFileBytes = dataOff + superBlobSize
	)

	buf := make([]byte, totalFileBytes)
	copy(buf, thinMachHeader(cpu, subCPU))
	binary.LittleEndian.PutUint32(buf[16:20], 1)           // ncmds
	binary.LittleEndian.PutUint32(buf[20:24], loadCmdSize) // sizeofcmds

	// LC_CODE_SIGNATURE load command (linkedit_data_command).
	binary.LittleEndian.PutUint32(buf[32:36], lcCodeSignature)
	binary.LittleEndian.PutUint32(buf[36:40], loadCmdSize)
	binary.LittleEndian.PutUint32(buf[40:44], dataOff)
	binary.LittleEndian.PutUint32(buf[44:48], superBlobSize)

	// CS SuperBlob: 1-entry index pointing at a CodeDirectory whose flags
	// carry CS_RUNTIME.
	blob := buf[dataOff:]
	binary.BigEndian.PutUint32(blob[0:4], csMagicEmbeddedSignature)
	binary.BigEndian.PutUint32(blob[4:8], superBlobSize)
	binary.BigEndian.PutUint32(blob[8:12], 1)
	binary.BigEndian.PutUint32(blob[12:16], csSlotCodeDirectory)
	binary.BigEndian.PutUint32(blob[16:20], codeDirOffset)
	binary.BigEndian.PutUint32(blob[codeDirOffset:codeDirOffset+4], csMagicCodeDirectory)
	binary.BigEndian.PutUint32(blob[codeDirOffset+4:codeDirOffset+8], superBlobSize) // length field, unread by our parser
	binary.BigEndian.PutUint32(blob[codeDirOffset+8:codeDirOffset+12], 0)            // version field, unread
	binary.BigEndian.PutUint32(blob[codeDirOffset+12:codeDirOffset+16], csRuntime)
	return buf
}

func TestPatchIfRestricted(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping codesign integration tests in short mode")
	}

	t.Run("restricted system binary is thinned, ad-hoc signed, and cached", func(t *testing.T) {
		dir := withTempSipCache(t)

		res, err := patchIfRestricted("/usr/bin/true")
		if err != nil {
			t.Fatalf("patchIfRestricted: %v", err)
		}
		if !res.patched {
			t.Fatal("expected patched=true for a restricted system binary")
		}
		wantPath := filepath.Join(dir, "mogate", "sip", sipCacheVersion, "usr", "bin", "true")
		if res.path != wantPath {
			t.Fatalf("path = %q, want %q", res.path, wantPath)
		}
		info, err := os.Stat(res.path)
		if err != nil {
			t.Fatalf("expected the cached file to exist: %v", err)
		}
		if perm := info.Mode().Perm(); perm != 0o700 {
			t.Fatalf("cached file mode = %o, want 0700", perm)
		}
		if dirInfo, err := os.Stat(filepath.Dir(res.path)); err != nil {
			t.Fatalf("stat cache dir: %v", err)
		} else if perm := dirInfo.Mode().Perm(); perm != 0o700 {
			t.Fatalf("cache dir mode = %o, want 0700", perm)
		}

		out, err := exec.Command("/usr/bin/codesign", "-dvvv", res.path).CombinedOutput()
		if err != nil {
			t.Fatalf("codesign -dvvv %q: %v\n%s", res.path, err, out)
		}
		if !bytes.Contains(out, []byte("adhoc")) {
			t.Fatalf("expected an ad-hoc signature, got:\n%s", out)
		}

		t.Run("a second call reuses the cache without re-signing", func(t *testing.T) {
			var calls int
			orig := codesignRunner
			codesignRunner = func(args ...string) error {
				calls++
				return nil
			}
			defer func() { codesignRunner = orig }()

			res2, err := patchIfRestricted("/usr/bin/true")
			if err != nil {
				t.Fatalf("patchIfRestricted (cached): %v", err)
			}
			if res2.path != res.path {
				t.Fatalf("path = %q, want cached path %q", res2.path, res.path)
			}
			if !res2.patched {
				t.Fatal("expected patched=true on a cache hit")
			}
			if res2.arch != res.arch {
				t.Fatalf("arch = %v, want %v (re-derived from the cached slice)", res2.arch, res.arch)
			}
			if calls != 0 {
				t.Fatalf("codesignRunner called %d times on a cache hit, want 0", calls)
			}
		})
	})

	t.Run("a script fixture patches its interpreter and carries shebang args", func(t *testing.T) {
		withTempSipCache(t)

		scriptDir := t.TempDir()
		script := filepath.Join(scriptDir, "myscript")
		if err := os.WriteFile(script, []byte("#!/bin/bash -x\necho hi\n"), 0o700); err != nil {
			t.Fatal(err)
		}

		res, err := patchIfRestricted(script)
		if err != nil {
			t.Fatalf("patchIfRestricted: %v", err)
		}

		wantInterp, err := sipCachePath("/bin/bash")
		if err != nil {
			t.Fatalf("sipCachePath: %v", err)
		}
		if res.scriptInterp != wantInterp {
			t.Fatalf("scriptInterp = %q, want the patched interpreter %q", res.scriptInterp, wantInterp)
		}
		if res.path != res.scriptInterp {
			t.Fatalf("path = %q, want it to equal scriptInterp %q", res.path, res.scriptInterp)
		}
		if !slices.Equal(res.scriptArgs, []string{"-x"}) {
			t.Fatalf("scriptArgs = %v, want [-x]", res.scriptArgs)
		}
		if !res.patched {
			t.Fatal("expected patched=true (/bin/bash is SIP-restricted)")
		}
		if _, err := os.Stat(res.scriptInterp); err != nil {
			t.Fatalf("expected the patched interpreter to exist on disk: %v", err)
		}
	})

	t.Run("an arm64e-only restricted binary has no injectable slice", func(t *testing.T) {
		withTempSipCache(t)

		fixtureDir := t.TempDir()
		p := filepath.Join(fixtureDir, "arm64e-only")
		data := restrictedThinMachHeader(cpuTypeArm64, 0x80000000|cpuSubtypeArm64E)
		if err := os.WriteFile(p, data, 0o700); err != nil {
			t.Fatal(err)
		}

		_, err := patchIfRestricted(p)
		if !errors.Is(err, ErrNoInjectableSlice) {
			t.Fatalf("err = %v, want ErrNoInjectableSlice", err)
		}
	})
}
