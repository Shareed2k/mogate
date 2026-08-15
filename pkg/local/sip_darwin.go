//go:build darwin

package local

import (
	"bufio"
	"bytes"
	"debug/macho"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
)

const sfRestricted = 0x00080000

// cpu type/subtype constants (from mach/machine.h), used to pick a loadable
// slice out of a (possibly fat) Mach-O.
const (
	cpuTypeX8664     = 0x01000007
	cpuTypeArm64     = 0x0100000c
	cpuSubtypeArm64E = 2
)

// ErrNoInjectableSlice is returned when a Mach-O offers only arm64e slices:
// dyld enforces pointer authentication on arm64e, so DYLD_INSERT_LIBRARIES
// injection needs a plain-arm64 or x86_64 slice instead.
var ErrNoInjectableSlice = errors.New("sip: no injectable slice (arm64e-only); needs x86_64 or plain-arm64")

// CS constants (from cs_blobs.h).
const (
	csMagicEmbeddedSignature = 0xfade0cc0
	csMagicCodeDirectory     = 0xfade0c02
	csSlotCodeDirectory      = 0
	csSlotEntitlements       = 5
	csRestrict               = 0x0000800
	csRuntime                = 0x00010000
)

// needsSIPPatch reports whether path is a restricted Mach-O whose execution
// would ignore DYLD_INSERT_LIBRARIES. Scripts and non-Mach-O files return false
// (scripts are handled by the shebang path).
func needsSIPPatch(path string) (bool, error) {
	info, err := os.Stat(path)
	if err != nil {
		return false, fmt.Errorf("sip: stat %q: %w", path, err)
	}
	restrictedFlag := false
	if st, ok := info.Sys().(*syscall.Stat_t); ok {
		restrictedFlag = st.Flags&sfRestricted != 0
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return false, fmt.Errorf("sip: read %q: %w", path, err)
	}
	if !isMachO(data) {
		return false, nil
	}
	csFlags, hasDyldEnt, err := codeSignatureFlags(data)
	if err != nil {
		return false, err
	}
	restricted := restrictedFlag || csFlags&(csRestrict|csRuntime) != 0
	return restricted && !hasDyldEnt, nil
}

// isMachO reports whether data begins with a thin or fat Mach-O magic.
func isMachO(data []byte) bool {
	if len(data) < 4 {
		return false
	}
	switch binary.BigEndian.Uint32(data[:4]) {
	case 0xcafebabe, 0xcafebabf: // fat, fat64 (big-endian)
		return true
	}
	switch binary.LittleEndian.Uint32(data[:4]) {
	case 0xfeedface, 0xfeedfacf: // thin 32/64 (little-endian host)
		return true
	}
	switch binary.BigEndian.Uint32(data[:4]) {
	case 0xfeedface, 0xfeedfacf:
		return true
	}
	return false
}

// isFat reports whether data begins with a fat (universal) Mach-O magic, as
// opposed to a thin one.
func isFat(data []byte) bool {
	if len(data) < 4 {
		return false
	}
	switch binary.BigEndian.Uint32(data[:4]) {
	case 0xcafebabe, 0xcafebabf: // fat, fat64
		return true
	}
	return false
}

// thinCPUType returns the CPU type (mach_header.cputype) of a thin Mach-O
// slice. Callers must ensure data is a thin Mach-O (isMachO && !isFat); it
// returns 0 if the file cannot be parsed.
func thinCPUType(data []byte) uint32 {
	file, err := macho.NewFile(bytes.NewReader(data))
	if err != nil {
		return 0
	}
	defer file.Close()
	return uint32(file.Cpu)
}

// chooseSlice selects a slice from a (possibly fat) Mach-O that dyld can load
// with DYLD_INSERT_LIBRARIES honored: a plain-arm64 slice (subtype != arm64e)
// is preferred as the native injector, falling back to x86_64 run under
// Rosetta. An arm64e-only binary (dyld enforces pointer authentication there)
// returns ErrNoInjectableSlice.
func chooseSlice(data []byte) (slice []byte, arch sipArch, err error) {
	reader := bytes.NewReader(data)
	if fat, ferr := macho.NewFatFile(reader); ferr == nil {
		defer fat.Close()
		var x86Slice *macho.FatArchHeader
		for i := range fat.Arches {
			fa := &fat.Arches[i]
			if isPlainArm64(fa.Cpu, fa.SubCpu) {
				s, err := extractFatSlice(data, fa.FatArchHeader)
				if err != nil {
					return nil, 0, err
				}
				return s, sipArchNative, nil
			}
			if fa.Cpu == macho.CpuAmd64 && x86Slice == nil {
				x86Slice = &fat.Arches[i].FatArchHeader
			}
		}
		if x86Slice != nil {
			s, err := extractFatSlice(data, *x86Slice)
			if err != nil {
				return nil, 0, err
			}
			return s, sipArchRosetta, nil
		}
		return nil, 0, ErrNoInjectableSlice
	} else if !errors.Is(ferr, macho.ErrNotFat) {
		return nil, 0, fmt.Errorf("sip: parse fat mach-o: %w", ferr)
	}

	file, err := macho.NewFile(bytes.NewReader(data))
	if err != nil {
		return nil, 0, fmt.Errorf("sip: parse mach-o: %w", err)
	}
	defer file.Close()
	switch {
	case isPlainArm64(file.Cpu, file.SubCpu):
		return data, sipArchNative, nil
	case file.Cpu == macho.CpuAmd64:
		return data, sipArchRosetta, nil
	default:
		return nil, 0, ErrNoInjectableSlice
	}
}

// isPlainArm64 reports whether cpu/subCpu identify an arm64 slice that is not
// arm64e (pointer authentication enforced, which dyld will not relax for
// DYLD_INSERT_LIBRARIES on a restricted process).
func isPlainArm64(cpu macho.Cpu, subCpu uint32) bool {
	return cpu == macho.CpuArm64 && subCpu&0xff != cpuSubtypeArm64E
}

// extractFatSlice returns the bytes of one architecture slice of a fat
// Mach-O, validating that the declared offset/size fall within data so a
// crafted fat header cannot wrap or slice out of bounds.
func extractFatSlice(data []byte, arch macho.FatArchHeader) ([]byte, error) {
	offset := uint64(arch.Offset)
	size := uint64(arch.Size)
	total := uint64(len(data))
	end := offset + size
	if end < offset || end > total {
		return nil, fmt.Errorf("sip: fat arch slice [%d:%d] out of bounds for %d-byte file", offset, end, total)
	}
	return data[offset:end], nil
}

// codeSignatureFlags returns the CodeDirectory flags of the first slice that
// carries a signature, and whether the allow-dyld entitlement is present.
// A binary with no signature returns (0, false, nil).
func codeSignatureFlags(data []byte) (flags uint32, hasDyldEnt bool, err error) {
	sigOff, sigSize, ok, err := firstCodeSignature(data)
	if err != nil || !ok {
		return 0, false, err
	}
	if sigOff+uint64(sigSize) > uint64(len(data)) {
		return 0, false, errors.New("sip: code signature out of bounds")
	}
	blob := data[sigOff : sigOff+uint64(sigSize)]
	return parseCSSuperBlob(blob)
}

// lcCodeSignature is LC_CODE_SIGNATURE (0x1d). debug/macho does not type this
// load command; it is a linkedit_data_command: { cmd, cmdsize, dataoff,
// datasize }, all uint32, in the file's own byte order.
const lcCodeSignature = 0x1d

// firstCodeSignature returns the file offset and size of the code-signature
// blob (LC_CODE_SIGNATURE) of the first Mach-O slice that carries one. For a
// fat binary the offset is absolute within data: the arch's fat-header
// offset plus that slice's own dataoff, since dataoff is relative to the
// start of the slice, not the start of the fat file. The offset is returned as
// a uint64 and the fat sum is computed in 64-bit and bounds-checked against
// len(data), so a crafted fat header cannot wrap two uint32s past the buffer
// (mirroring the C side at injector/sip_darwin.h:321-324).
func firstCodeSignature(data []byte) (offset uint64, size uint32, ok bool, err error) {
	reader := bytes.NewReader(data)
	if fat, ferr := macho.NewFatFile(reader); ferr == nil {
		defer fat.Close()
		for _, arch := range fat.Arches {
			off, sz, found, findErr := codeSignatureLoad(arch.File)
			if findErr != nil {
				return 0, 0, false, findErr
			}
			if found {
				absolute := uint64(arch.Offset) + uint64(off)
				if absolute > uint64(len(data)) {
					return 0, 0, false, errors.New("sip: code signature offset out of bounds")
				}
				return absolute, sz, true, nil
			}
		}
		return 0, 0, false, nil
	} else if !errors.Is(ferr, macho.ErrNotFat) {
		return 0, 0, false, fmt.Errorf("sip: parse fat mach-o: %w", ferr)
	}

	file, err := macho.NewFile(reader)
	if err != nil {
		return 0, 0, false, fmt.Errorf("sip: parse mach-o: %w", err)
	}
	defer file.Close()
	off, sz, found, err := codeSignatureLoad(file)
	if err != nil {
		return 0, 0, false, err
	}
	return uint64(off), sz, found, nil
}

// codeSignatureLoad scans f.Loads for LC_CODE_SIGNATURE and returns its
// dataoff/datasize, relative to the start of f's own Mach-O slice.
func codeSignatureLoad(f *macho.File) (offset, size uint32, ok bool, err error) {
	for _, load := range f.Loads {
		raw := load.Raw()
		if len(raw) < 16 {
			continue
		}
		if f.ByteOrder.Uint32(raw[0:4]) != lcCodeSignature {
			continue
		}
		return f.ByteOrder.Uint32(raw[8:12]), f.ByteOrder.Uint32(raw[12:16]), true, nil
	}
	return 0, 0, false, nil
}

// csBlobIndexSize is the size of one CS_BlobIndex entry: { type, offset },
// both big-endian uint32.
const csBlobIndexSize = 8

// csMaxBlobCount caps the SuperBlob index walk against a corrupted count
// field; a real code signature carries a handful of slots.
const csMaxBlobCount = 1 << 16

// parseCSSuperBlob walks a CS SuperBlob's index (magic csMagicEmbeddedSignature),
// returning the CodeDirectory flags (csSlotCodeDirectory) and whether the
// entitlements blob (csSlotEntitlements) contains sipEntitlementAllowDyld.
// All CS fields are big-endian.
func parseCSSuperBlob(blob []byte) (flags uint32, hasDyldEnt bool, err error) {
	if len(blob) < 12 {
		return 0, false, errors.New("sip: code signature superblob too small")
	}
	if magic := binary.BigEndian.Uint32(blob[0:4]); magic != csMagicEmbeddedSignature {
		return 0, false, fmt.Errorf("sip: unexpected code signature magic %#x", magic)
	}
	count := binary.BigEndian.Uint32(blob[8:12])
	if count > csMaxBlobCount {
		return 0, false, fmt.Errorf("sip: implausible code signature blob count %d", count)
	}
	for i := uint32(0); i < count; i++ {
		entryOff := 12 + i*csBlobIndexSize
		if int(entryOff)+csBlobIndexSize > len(blob) {
			return 0, false, errors.New("sip: code signature index out of bounds")
		}
		slotType := binary.BigEndian.Uint32(blob[entryOff : entryOff+4])
		slotOffset := binary.BigEndian.Uint32(blob[entryOff+4 : entryOff+8])
		if int(slotOffset) > len(blob) {
			return 0, false, errors.New("sip: code signature slot offset out of bounds")
		}
		switch slotType {
		case csSlotCodeDirectory:
			flags, err = codeDirectoryFlags(blob[slotOffset:])
			if err != nil {
				return 0, false, err
			}
		case csSlotEntitlements:
			if bytes.Contains(blob[slotOffset:], []byte(sipEntitlementAllowDyld)) {
				hasDyldEnt = true
			}
		}
	}
	return flags, hasDyldEnt, nil
}

// codeDirectoryFlags reads the big-endian flags field (offset 12) of a
// CodeDirectory blob (magic csMagicCodeDirectory).
func codeDirectoryFlags(blob []byte) (uint32, error) {
	if len(blob) < 16 {
		return 0, errors.New("sip: code directory too small")
	}
	if magic := binary.BigEndian.Uint32(blob[0:4]); magic != csMagicCodeDirectory {
		return 0, fmt.Errorf("sip: unexpected code directory magic %#x", magic)
	}
	return binary.BigEndian.Uint32(blob[12:16]), nil
}

// codesignRunner is the seam tests replace to assert the exact codesign
// invocations adhocResign makes without actually invoking /usr/bin/codesign.
var codesignRunner = runCodesign

// runCodesign runs /usr/bin/codesign with args, capturing stderr so a
// failure can be reported with codesign's own diagnostic text.
func runCodesign(args ...string) error {
	cmd := exec.Command("/usr/bin/codesign", args...)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("sip: codesign %v: %w: %s", args, err, stderr.String())
	}
	return nil
}

// readShebang parses the first line of the file at path for a "#!interp
// [arg...]" shebang. It reads only the first line (via bufio), not the whole
// file. ok=false covers every non-shebang case this parser recognizes: no
// "#!" prefix (including binaries like Mach-O), an empty file, or a "#!"
// line with no interpreter token. It does not default a missing shebang's
// interpreter to $SHELL; that policy belongs to the caller.
func readShebang(path string) (interp string, args []string, ok bool, err error) {
	f, err := os.Open(path)
	if err != nil {
		return "", nil, false, fmt.Errorf("sip: open %q: %w", path, err)
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	if !scanner.Scan() {
		if err := scanner.Err(); err != nil {
			return "", nil, false, fmt.Errorf("sip: read %q: %w", path, err)
		}
		return "", nil, false, nil // empty file
	}

	line, ok := strings.CutPrefix(scanner.Text(), "#!")
	if !ok {
		return "", nil, false, nil
	}
	fields := strings.Fields(line)
	if len(fields) == 0 {
		return "", nil, false, nil
	}
	if len(fields) > 1 {
		args = fields[1:]
	}
	return fields[0], args, true, nil
}

// adhocResign strips path's existing code signature and replaces it with an
// ad-hoc signature. An ad-hoc signature ("-s -") carries none of the
// original signer's entitlements or hardened-runtime flags, so dyld stops
// enforcing the restrictions (e.g. library validation) that would otherwise
// cause it to ignore DYLD_INSERT_LIBRARIES for this copy.
func adhocResign(path string) error {
	// A freshly extracted/copied slice may already be unsigned, in which case
	// --remove-signature exits non-zero ("object is not signed at all"); that
	// is a no-op, not a failure, so its error is deliberately discarded.
	_ = codesignRunner("--remove-signature", path)
	if err := codesignRunner("-s", "-", "-f", path); err != nil {
		return fmt.Errorf("sip: ad-hoc sign %q: %w", path, err)
	}
	return nil
}

// patchIfRestricted is the top-level entrypoint execute() uses to make path
// loadable with DYLD_INSERT_LIBRARIES honored:
//
//  1. If path is a "#!" script, the interpreter is patched recursively (an
//     interpreter can itself be a restricted Mach-O, e.g. /bin/bash); the
//     result carries the patched interpreter as both path and scriptInterp,
//     plus the shebang's own scriptArgs, so the caller can build argv as
//     [scriptInterp, scriptArgs..., scriptPath, origArgs...].
//  2. Otherwise, an unrestricted binary is returned unpatched.
//  3. A restricted binary is served from the on-disk cache if a prior call
//     already patched it.
//  4. Otherwise it is thinned to an injectable slice, ad-hoc re-signed, and
//     written into the cache for next time.
//
// Fail-loud: any detection, thinning, signing, or I/O error is returned
// wrapped; the caller must not fall back to running the unpatched original.
func patchIfRestricted(path string) (sipResult, error) {
	interp, args, isScript, err := readShebang(path)
	if err != nil {
		return sipResult{}, err
	}
	if isScript {
		patchedInterp, err := patchIfRestricted(interp)
		if err != nil {
			return sipResult{}, err
		}
		patchedInterp.scriptInterp = patchedInterp.path
		patchedInterp.scriptArgs = args
		return patchedInterp, nil
	}

	restricted, err := needsSIPPatch(path)
	if err != nil {
		return sipResult{}, err
	}
	if !restricted {
		return sipResult{path: path, arch: sipArchNative, patched: false}, nil
	}

	cachePath, err := sipCachePath(path)
	if err != nil {
		return sipResult{}, err
	}
	if cached, err := os.ReadFile(cachePath); err == nil {
		_, arch, err := chooseSlice(cached)
		if err != nil {
			return sipResult{}, err
		}
		return sipResult{path: cachePath, arch: arch, patched: true}, nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return sipResult{}, fmt.Errorf("sip: read cached %q: %w", cachePath, err)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return sipResult{}, fmt.Errorf("sip: read %q: %w", path, err)
	}
	slice, arch, err := chooseSlice(data)
	if err != nil {
		return sipResult{}, err
	}

	cacheDir := filepath.Dir(cachePath)
	if err := os.MkdirAll(cacheDir, 0o700); err != nil {
		return sipResult{}, fmt.Errorf("sip: mkdir %q: %w", cacheDir, err)
	}

	tmp, err := os.CreateTemp(cacheDir, ".sip-*")
	if err != nil {
		return sipResult{}, fmt.Errorf("sip: create temp in %q: %w", cacheDir, err)
	}
	tmpPath := tmp.Name()

	if _, err := tmp.Write(slice); err != nil {
		_ = tmp.Close()
		_ = os.Remove(tmpPath)
		return sipResult{}, fmt.Errorf("sip: write %q: %w", tmpPath, err)
	}
	if err := tmp.Chmod(0o700); err != nil {
		_ = tmp.Close()
		_ = os.Remove(tmpPath)
		return sipResult{}, fmt.Errorf("sip: chmod %q: %w", tmpPath, err)
	}
	if err := tmp.Close(); err != nil {
		_ = os.Remove(tmpPath)
		return sipResult{}, fmt.Errorf("sip: close %q: %w", tmpPath, err)
	}

	if err := adhocResign(tmpPath); err != nil {
		_ = os.Remove(tmpPath)
		return sipResult{}, err
	}

	if err := os.Rename(tmpPath, cachePath); err != nil {
		_ = os.Remove(tmpPath)
		return sipResult{}, fmt.Errorf("sip: rename %q -> %q: %w", tmpPath, cachePath, err)
	}

	return sipResult{path: cachePath, arch: arch, patched: true}, nil
}
