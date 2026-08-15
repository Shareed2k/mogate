# macOS SIP-Patching Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make the mogate injector load into SIP-restricted macOS binaries by patching a re-signed copy — so `-- /usr/bin/curl`, restricted children (`bash -> curl`), and `#!` scripts route through the agent. Fail loud when a binary cannot be patched.

**Architecture:** Two patch points, both in mogate, each a native implementation kept in lockstep by shared golden vectors. (1) **Top-level** binary: pure-Go SIP logic in `pkg/local`, called from `execute()` before the child spawns. (2) **Children**: C SIP logic + `execve`/`execvp`/`posix_spawn`/`posix_spawnp` interposers in the injector dylib. The patch routine: detect (SF_RESTRICTED / CS RESTRICT|RUNTIME, minus the dyld-env entitlement) → thin to a loadable slice (x86_64 on Apple Silicon) in-code → ad-hoc re-sign via `/usr/bin/codesign` → cache under `UserCacheDir/mogate/sip/<version>/…`. x86_64 slices run under Rosetta 2 with the x86_64 injector.

**Tech Stack:** Go 1.24+ (`debug/macho`, `os/exec`), C (cgo comment block in `injector/main.go`, `__DATA,__interpose`), `/usr/bin/codesign` (base-OS).

**Design doc:** `docs/superpowers/specs/2026-08-14-macos-sip-patching-design.md`.

## Global Constraints

- **Fail-loud.** A binary that cannot be patched aborts the run with an actionable message. Never run a command un-intercepted.
- **Copies only.** Patching writes only into `UserCacheDir/mogate/sip/<version>/…`. The original system binary is never modified.
- **darwin-only.** All SIP code is behind `//go:build darwin` (Go) / `#ifdef __APPLE__` (C). Linux/Windows builds are strict no-ops.
- **No Xcode-CLT dependency.** Thinning is in-code (no `lipo`); signing uses base-OS `/usr/bin/codesign`. codesign is the only external process.
- **Dual-impl parity.** The Go and C thinners must produce byte-identical output; a golden-vector test enforces it.
- **Constants (verbatim):** `SF_RESTRICTED = 0x00080000`; CS `CSSLOT_CODEDIRECTORY = 0`, `CSSLOT_ENTITLEMENTS = 5`; CS flag `CS_RESTRICT = 0x0000800`, `CS_RUNTIME = 0x00010000`; `CSMAGIC_EMBEDDED_SIGNATURE = 0xfade0cc0`, `CSMAGIC_CODEDIRECTORY = 0xfade0c02`; CodeDirectory `flags` is a big-endian `uint32` at offset 12 of the CodeDirectory blob; entitlement string `com.apple.security.cs.allow-dyld-environment-variables`.
- **Cache version namespace:** the mogate module version string (from `internal/version` or a `const`), so an upgrade re-patches.
- golang: `%w`, lowercase errors, single-handling, `-race`, table-driven, `goleak` where goroutines exist. **No `#nosec`/`#nolint`.** No third-party product names in code/docs.

---

## File Structure

**mogate (this PR):**
- Create `pkg/local/sip.go` — platform-agnostic types (`sipResult`, arch enum, cache-path helper, version const).
- Create `pkg/local/sip_darwin.go` — real detection/thin/sign/shebang/patch.
- Create `pkg/local/sip_other.go` — `//go:build !darwin` no-op.
- Create `pkg/local/sip_darwin_test.go`, `pkg/local/sip_test.go` — unit tests + fixtures.
- Create `pkg/local/testdata/sip/` — committed Mach-O + script fixtures.
- Modify `pkg/local/local.go` — `Config.InjectorLibRosetta`; `execute()` calls the patch on darwin and selects the injector by arch.
- Create `injector/sip_darwin.h` — C detection/thin/sign/patch (`#ifdef __APPLE__`), `#include`d from the cgo block.
- Modify `injector/main.go` — `#include "sip_darwin.h"` in the cgo block; add `mg_execve_hook`/`mg_execvp_hook`/`mg_posix_spawn_hook`/`mg_posix_spawnp_hook` + `MG_INTERPOSE` entries (darwin).
- Create `injector/sip_test/` (a tiny C test built by a new `make test-injector-c` target) OR a Go cgo test `injector/sip_cgo_test.go` exercising the C patch + parity.
- Modify `Makefile` — add a target that compiles + runs the C SIP unit test; keep the dylib build as-is (sip is in the cgo stream via the header include).
- Modify `README.md` — macOS SIP section (supersede the "may ignore DYLD" note).

**honey (separate follow-up PR, after the mogate SIP release — marked Phase H):**
- Modify `scripts/build-intercept-injector.sh` — ensure `darwin_amd64` real dylib is built (`clang -arch x86_64`).
- Modify `internal/intercept/injector.go` / the local-config wiring — extract both darwin dylibs, set `local.Config.InjectorLib` + `InjectorLibRosetta`.
- Bump `INJECTOR_REF` + `github.com/shareed2k/mogate` module version.
- Docs in `website/docs/intercept.md`.

---

## Phase A — Go SIP core (`pkg/local`), pure, top-level only

### Task A1: Detection — `needsSIPPatch`

**Files:**
- Create: `pkg/local/sip.go`, `pkg/local/sip_darwin.go`, `pkg/local/sip_other.go`
- Test: `pkg/local/sip_darwin_test.go`

**Interfaces:**
- Produces: `func needsSIPPatch(path string) (bool, error)` (darwin); returns `(false, nil)` on non-darwin. Reports whether `path` is a restricted Mach-O that must be patched (true), or a plain/unrestricted/non-Mach-O that can run as-is (false). Scripts are handled separately (Task A4), so a `#!` file returns `(false, nil)` here.

- [ ] **Step 1: Write the failing test** (`pkg/local/sip_darwin_test.go`)

```go
//go:build darwin

package local

import (
	"os"
	"path/filepath"
	"testing"
)

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
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd pkg/local && go test -run TestNeedsSIPPatch -v`
Expected: FAIL — `needsSIPPatch` undefined.

- [ ] **Step 3: Write minimal implementation**

`pkg/local/sip.go` (platform-agnostic):

```go
package local

// sipArch identifies the slice chosen from a (possibly fat) Mach-O.
type sipArch int

const (
	sipArchNative sipArch = iota // plain arm64 (Apple Silicon) or x86_64 (Intel): the native injector
	sipArchRosetta               // x86_64 slice run under Rosetta on Apple Silicon: the x86_64 injector
)

// sipResult is the outcome of patching one binary.
type sipResult struct {
	path string  // path to run (patched copy, or the original when patched==false)
	arch sipArch // which injector the caller should load
	patched bool
}

// sipCacheVersion namespaces the on-disk patch cache so a mogate upgrade
// re-patches. Keep in sync with the module version.
const sipCacheVersion = "v1"

// sipEntitlementAllowDyld is the entitlement that already lets dyld honor
// insertion; a binary carrying it never needs patching.
const sipEntitlementAllowDyld = "com.apple.security.cs.allow-dyld-environment-variables"
```

`pkg/local/sip_other.go`:

```go
//go:build !darwin

package local

// needsSIPPatch is a no-op off darwin: no SIP, nothing to patch.
func needsSIPPatch(string) (bool, error) { return false, nil }

// patchIfRestricted is a no-op off darwin: run the binary as given.
func patchIfRestricted(path string) (sipResult, error) {
	return sipResult{path: path, arch: sipArchNative}, nil
}
```

`pkg/local/sip_darwin.go` (detection only for now):

```go
//go:build darwin

package local

import (
	"debug/macho"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
	"syscall"
)

const sfRestricted = 0x00080000

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

// codeSignatureFlags returns the CodeDirectory flags of the first slice that
// carries a signature, and whether the allow-dyld entitlement is present.
// A binary with no signature returns (0, false, nil).
func codeSignatureFlags(data []byte) (flags uint32, hasDyldEnt bool, err error) {
	sigOff, sigSize, ok, err := firstCodeSignature(data)
	if err != nil || !ok {
		return 0, false, err
	}
	if int(sigOff)+int(sigSize) > len(data) {
		return 0, false, errors.New("sip: code signature out of bounds")
	}
	blob := data[sigOff : sigOff+sigSize]
	return parseCSSuperBlob(blob)
}
```

Plus helpers `firstCodeSignature` (walk `macho.File`/`macho.FatFile` load commands for `LC_CODE_SIGNATURE = 0x1d`, returning its `dataoff`/`datasize` within the file — use `debug/macho` to find `__LINKEDIT` + iterate `f.Loads`; `LC_CODE_SIGNATURE` is a `LinkEditData`-shaped command not typed by `debug/macho`, so read the raw load command bytes) and `parseCSSuperBlob` (walk the SuperBlob index; for `csSlotCodeDirectory` read the CodeDirectory `flags` at offset 12 big-endian; for `csSlotEntitlements` search the blob bytes for `sipEntitlementAllowDyld`). Include a `copyFile` test helper.

- [ ] **Step 4: Run test to verify it passes**

Run: `cd pkg/local && go test -run TestNeedsSIPPatch -v`
Expected: PASS (on a macOS host; the suite is `//go:build darwin`).

- [ ] **Step 5: Commit**

```bash
git add pkg/local/sip.go pkg/local/sip_darwin.go pkg/local/sip_other.go pkg/local/sip_darwin_test.go
git commit -m "feat(sip): detect SIP-restricted mach-o binaries (darwin)"
```

### Task A2: Thin a fat Mach-O to a loadable slice (in-code)

**Files:**
- Modify: `pkg/local/sip_darwin.go`
- Test: `pkg/local/sip_darwin_test.go`
- Test data: `pkg/local/testdata/sip/` (add a fat fixture in Step 1 via a generator helper that copies `/usr/bin/true` — universal — into testdata at test time, or commit a small committed fat fixture)

**Interfaces:**
- Produces: `func chooseSlice(data []byte) (slice []byte, arch sipArch, err error)` — prefers a plain-arm64 slice (native), else x86_64 (Rosetta on Apple Silicon), else `ErrNoInjectableSlice`. A thin supported Mach-O returns the whole file. arm64e-only → `ErrNoInjectableSlice`.
- `var ErrNoInjectableSlice = errors.New("sip: no injectable slice (arm64e-only); needs x86_64 or plain-arm64")`

- [ ] **Step 1: Write the failing test**

```go
func TestChooseSlice(t *testing.T) {
	t.Run("universal system binary yields x86_64 on apple silicon", func(t *testing.T) {
		data, err := os.ReadFile("/usr/bin/true") // universal x86_64+arm64e
		if err != nil { t.Fatal(err) }
		slice, arch, err := chooseSlice(data)
		if err != nil { t.Fatalf("chooseSlice: %v", err) }
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
}
```

- [ ] **Step 2: Run — FAIL** (`chooseSlice` undefined). Run: `go test -run TestChooseSlice -v`.

- [ ] **Step 3: Implement `chooseSlice`** using `macho.NewFatFile(bytes.NewReader(data))`; iterate `Arches`; select by `Cpu`/`SubCpu` (prefer `macho.CpuArm64` with subtype != arm64e; else `macho.CpuAmd64`). For the chosen `FatArch`, copy `data[arch.Offset : arch.Offset+arch.Size]`. For a thin file (`macho.NewFile`), accept x86_64 or non-arm64e arm64, else `ErrNoInjectableSlice`. Add constants `cpuTypeX8664 = 0x01000007`, `cpuTypeArm64 = 0x0100000c`, `cpuSubtypeArm64E = 2`, and helpers `isFat`, `thinCPUType`.

- [ ] **Step 4: Run — PASS.**

- [ ] **Step 5: Commit** `feat(sip): choose a loadable slice (arm64 preferred, x86_64 fallback)`.

### Task A3: Ad-hoc re-sign via /usr/bin/codesign

**Files:** Modify `pkg/local/sip_darwin.go`; Test `pkg/local/sip_darwin_test.go`.

**Interfaces:**
- Produces: `func adhocResign(path string) error` — `codesign --remove-signature <path>` (ignore "not signed" error) then `codesign -s - -f <path>`; wraps codesign stderr on failure. The seam for tests: a package var `var codesignRunner = runCodesign` so a unit test can assert the exact argv without signing.

- [ ] **Step 1: Failing test** — inject a fake `codesignRunner`, assert it is called with `["--remove-signature", p]` then `["-s","-","-f",p]`; and an integration sub-test (guarded by `testing.Short()` skip) that actually signs a copied `/usr/bin/true` slice and greps `codesign -dvvv` for `adhoc`.
- [ ] **Step 2: Run — FAIL.**
- [ ] **Step 3: Implement** `adhocResign` + `runCodesign(args ...string) error` using `exec.Command("/usr/bin/codesign", args...)`.
- [ ] **Step 4: Run — PASS.**
- [ ] **Step 5: Commit** `feat(sip): ad-hoc re-sign patched binaries via codesign`.

### Task A4: Shebang parsing + interpreter resolution

**Files:** Modify `pkg/local/sip_darwin.go`; Test `pkg/local/sip_darwin_test.go`.

**Interfaces:**
- Produces: `func readShebang(path string) (interp string, args []string, ok bool, err error)` — if the file starts with `#!`, parse `#!<ws><interp>[<ws><arg>]` from the first line; `ok=false` for non-scripts. Interpreter with no shebang but executed as script defaults to `$SHELL` at the call site, not here.

- [ ] **Step 1: Failing test** — table: `#!/bin/bash\n` → `("/bin/bash", nil, true)`; `#!/usr/bin/env python3\n` → `("/usr/bin/env", ["python3"], true)`; leading spaces; a Mach-O → `ok=false`; empty file → `ok=false`.
- [ ] **Step 2: Run — FAIL.**
- [ ] **Step 3: Implement** reading only the first line (bufio), strip `#!`, split on whitespace (first token = interp, rest = args).
- [ ] **Step 4: Run — PASS.**
- [ ] **Step 5: Commit** `feat(sip): parse shebang interpreter for script patching`.

### Task A5: Cache + orchestrator `patchIfRestricted`

**Files:** Modify `pkg/local/sip.go`, `pkg/local/sip_darwin.go`; Test `pkg/local/sip_darwin_test.go`.

**Interfaces:**
- Produces: `func patchIfRestricted(path string) (sipResult, error)` (darwin) — the top-level entrypoint used by `execute()`. Algorithm:
  1. `interp, args, isScript, err := readShebang(path)`. If script: recurse `patchIfRestricted(interp)`; return a result whose `path` is the patched interpreter and carries the original script + shebang-args so the caller builds argv `[patchedInterp, args..., scriptPath, origArgs...]`. (Model this with an extended `sipResult`: add `scriptInterp string`, `scriptArgs []string` — set when the top-level was a script.)
  2. Else `needsSIPPatch(path)`. If false → `sipResult{path: path, arch: sipArchNative, patched: false}`.
  3. Else compute cache path `sipCachePath(path)` = `UserCacheDir/mogate/sip/<sipCacheVersion>/<abs path without leading '/'>`. If it exists → return it (with the arch recorded alongside — store arch in a sibling `.arch` marker or re-derive via `chooseSlice` on the cached bytes).
  4. Else: read original → `chooseSlice` → write slice to a temp in the cache dir (0700 dir, 0700 file) → `adhocResign(temp)` → atomic rename to the cache path → return `sipResult{path: cachePath, arch: arch, patched: true}`.
- Cache-path helper `sipCachePath(orig string) (string, error)` in `sip.go` (uses `os.UserCacheDir`).

- [ ] **Step 1: Failing test** — (a) restricted `/usr/bin/true` → returns a cached path under `UserCacheDir/mogate/sip/v1/usr/bin/true`, `patched=true`, file exists + is adhoc-signed; (b) second call reuses the cache (assert no re-sign via the `codesignRunner` spy call-count); (c) a `#!` script fixture → result carries `scriptInterp` patched + `scriptArgs`; (d) arm64e-only fixture → `ErrNoInjectableSlice`. Use a `t.Setenv` to point the cache at a temp dir (add a `sipCacheDir` seam var defaulting to `os.UserCacheDir`).
- [ ] **Step 2: Run — FAIL.**
- [ ] **Step 3: Implement** the orchestrator + cache.
- [ ] **Step 4: Run — PASS** (`go test -race ./pkg/local/`).
- [ ] **Step 5: Commit** `feat(sip): patchIfRestricted orchestrator with on-disk cache`.

---

## Phase B — Wire top-level patching into `pkg/local`

### Task B1: `Config.InjectorLibRosetta` + arch-aware injector selection in `execute()`

**Files:** Modify `pkg/local/local.go`; Test `pkg/local/local_test.go`, `pkg/local/env_internal_test.go`.

**Interfaces:**
- Consumes: `patchIfRestricted`, `sipResult`, `sipArchRosetta` (Task A5).
- Modifies: `Config` gains `InjectorLibRosetta string` (doc: "path to the x86_64 injector, loaded for binaries thinned to x86_64 under Rosetta; required on Apple Silicon for restricted system binaries"). `execute()` on darwin: `res, err := patchIfRestricted(command[0])`; fail-loud on err; rebuild `command` for scripts (`[res.scriptInterp, res.scriptArgs..., command[0], command[1:]...]` when script, else `command[0] = res.path`); pick `lib := options.library`; if `res.arch == sipArchRosetta` then `lib = options.libraryRosetta` and fail-loud if empty (`"sip: %s needs the x86_64 injector but InjectorLibRosetta is unset"`). Thread `InjectorLibRosetta` into `injectionOptions` (`libraryRosetta string`).

- [ ] **Step 1: Failing test** — with a `LocalRunner`-level seam is not available here (`execute` is internal), so test `injectedEnvironment`/selection via a new internal helper `selectInjector(options, res) (string, error)`: Rosetta arch + empty rosetta lib → error; Rosetta arch + set → returns rosetta lib; native → returns library. Table-driven in `env_internal_test.go`.
- [ ] **Step 2: Run — FAIL.**
- [ ] **Step 3: Implement** `selectInjector` + `Config.InjectorLibRosetta` + `injectionOptions.libraryRosetta` + call `selectInjector` in `execute()`. Non-darwin `execute()` path unchanged (patchIfRestricted no-op returns native).
- [ ] **Step 4: Run — PASS** (`go test -race ./pkg/local/`).
- [ ] **Step 5: Commit** `feat(local): patch restricted top-level binaries and load the arch-matched injector`.

---

## Phase C — C SIP core (`injector/sip_darwin.h`), parity with Go

### Task C1: C detection + thinning + signing + cache

**Files:** Create `injector/sip_darwin.h`; Modify `injector/main.go` (add `#include "sip_darwin.h"` inside the cgo block, after `protocol_generated.h`, guarded by `#ifdef __APPLE__`).
Test: a cgo Go test `injector/sip_cgo_test.go` (`//go:build darwin`) that calls the exported C functions via a thin cgo bridge and asserts parity with the Go `pkg/local` output on the shared fixtures.

**Interfaces (C, all `#ifdef __APPLE__`):**
- `int mg_sip_needs_patch(const char *path);` — 1 restricted, 0 not, -1 error. Same logic as `needsSIPPatch` (SF_RESTRICTED via `stat.st_flags`; CS flags via SuperBlob parse; entitlement search).
- `char *mg_sip_choose_slice(const uint8_t *data, size_t len, size_t *out_off, size_t *out_size, int *out_is_rosetta);` — returns NULL on `ErrNoInjectableSlice`; sets offset/size of the chosen slice + rosetta flag. Manual `struct fat_header`/`fat_arch` big-endian parse (`<mach-o/fat.h>`).
- `char *mg_sip_patch(const char *path);` — full orchestrator: shebang? → patch interpreter; else needs-patch? → cache-path → reuse-or (thin→write→codesign→rename) → return malloc'd patched path, or NULL when no patch needed. On unrecoverable error, return a sentinel + set an error string retrievable via `mg_sip_last_error()` (the exec detour turns it into a failed exec / logged error).
- Signing shells `/usr/bin/codesign` via `posix_spawn` of the REAL function (see reentrancy guard, Task D2) + `waitpid`.
- Cache dir: `getenv("HOME")` + `/Library/Caches/mogate/sip/<version>/…`; `mkdir` 0700.

- [ ] **Step 1: Write the failing parity test** (`injector/sip_cgo_test.go`):

```go
//go:build darwin

package main

/*
#include "sip_darwin.h"
*/
import "C"

import (
	"os"
	"testing"
	"unsafe"
)

func TestCSipParity_ChooseSlice(t *testing.T) {
	data, err := os.ReadFile("/usr/bin/true")
	if err != nil { t.Fatal(err) }
	var off, size C.size_t
	var rosetta C.int
	cp := C.CBytes(data)
	defer C.free(cp)
	r := C.mg_sip_choose_slice((*C.uint8_t)(cp), C.size_t(len(data)), &off, &size, &rosetta)
	if r == nil {
		t.Fatal("mg_sip_choose_slice returned NULL for a universal binary")
	}
	// The chosen slice bytes must equal what Go's chooseSlice picks (golden parity
	// is asserted fully in Phase E; here assert non-empty x86_64/rosetta).
	if rosetta != 1 || size == 0 {
		t.Fatalf("rosetta=%d size=%d, want rosetta slice", rosetta, size)
	}
	_ = unsafe.Pointer(cp)
}
```

- [ ] **Step 2: Run — FAIL** (`sip_darwin.h` missing). Run: `cd injector && go generate ./... 2>/dev/null; go test -run TestCSipParity -v` (the cgo test compiles the header directly).
- [ ] **Step 3: Implement `injector/sip_darwin.h`** (detection + fat parse + slice selection first; signing/cache in C3) and add the `#include` to the cgo block.
- [ ] **Step 4: Run — PASS.**
- [ ] **Step 5: Commit** `feat(injector): C SIP detection + slice selection (darwin)`.

### Task C2: C thin+sign+cache orchestrator `mg_sip_patch`

**Files:** Modify `injector/sip_darwin.h`; Test `injector/sip_cgo_test.go`.

- [ ] **Step 1: Failing test** — `C.mg_sip_patch("/usr/bin/true")` returns a non-NULL path under `~/Library/Caches/mogate/sip/v1/usr/bin/true`, the file exists and is adhoc-signed (grep `codesign -dvvv`), and a second call reuses it. A non-restricted file (e.g. a copied plain binary) returns NULL.
- [ ] **Step 2: Run — FAIL.**
- [ ] **Step 3: Implement** the cache path, in-code slice write, `posix_spawn` of codesign (real fn), atomic rename, `mg_sip_last_error`.
- [ ] **Step 4: Run — PASS.**
- [ ] **Step 5: Commit** `feat(injector): C mg_sip_patch thin+resign+cache (darwin)`.

---

## Phase D — C exec interposers + envp preservation + reentrancy guard

### Task D1: exec detours + interpose entries

**Files:** Modify `injector/main.go` (cgo block: add hook functions + `MG_INTERPOSE` entries, darwin only).
Test: `injector/sip_cgo_test.go` — call `mg_execve_hook` with a fake "real exec" spy.

**Interfaces (C):**
- `int mg_execve_hook(const char *path, char *const argv[], char *const envp[]);`
- `int mg_execvp_hook(const char *file, char *const argv[]);`
- `int mg_posix_spawn_hook(pid_t *pid, const char *path, const posix_spawn_file_actions_t *fa, const posix_spawnattr_t *attr, char *const argv[], char *const envp[]);`
- `int mg_posix_spawnp_hook(...);`
- Each: resolve path (PATH-resolve for the `p` variants) → `mg_sip_patch` → on patched, use the patched path → build a new envp ensuring `DYLD_INSERT_LIBRARIES=<self>` + `MOGATE_SOCKET=<socket>` present (`mg_sip_fix_env`) → call the real function. On `mg_sip_patch` hard error → set errno and return -1 (execve) / return the error (posix_spawn) — fail-loud, do not exec un-patched.
- The injector's own path (for DYLD self-reference) is obtained from `dladdr(&mg_connect_hook, ...)` / `_dyld_image` scan, cached at constructor time (`mg_initialize`).
- `MG_INTERPOSE(mg_execve_hook, execve)` etc., inside `#ifdef __APPLE__`.

- [ ] **Step 1: Failing test** — a test-only seam: compile the hooks with a `MG_SIP_TEST_REAL_EXEC` weak hook that records `(path, argv, envp)` instead of exec'ing. Assert: given a fixture restricted binary, `mg_execve_hook` calls real-exec with the patched path and an envp containing `DYLD_INSERT_LIBRARIES`. Given a non-restricted path, real-exec is called with the original path unchanged (but envp still carries DYLD).
- [ ] **Step 2: Run — FAIL.**
- [ ] **Step 3: Implement** the four detours + `mg_sip_fix_env` + interpose entries.
- [ ] **Step 4: Run — PASS.**
- [ ] **Step 5: Commit** `feat(injector): execve/execvp/posix_spawn(p) SIP interposers with DYLD-preserving envp`.

### Task D2: Reentrancy guard for codesign spawns

**Files:** Modify `injector/sip_darwin.h`, `injector/main.go`.

**Interfaces:** a thread-local `__thread int mg_sip_in_patch;` — set around `mg_sip_patch`'s own codesign spawn; the `posix_spawn`/`posix_spawnp` detours early-return to the real function when `mg_sip_in_patch != 0`. Also never patch a target whose resolved path is `/usr/bin/codesign` or `/usr/bin/lipo`.

- [ ] **Step 1: Failing test** — simulate: set `mg_sip_in_patch`, call `mg_posix_spawn_hook` on a restricted fixture, assert it calls real-spawn with the ORIGINAL path (no patch, no recursion). Also assert `mg_execve_hook("/usr/bin/codesign", …)` never patches.
- [ ] **Step 2: Run — FAIL.**
- [ ] **Step 3: Implement** the guard + codesign/lipo path skip.
- [ ] **Step 4: Run — PASS.**
- [ ] **Step 5: Commit** `fix(injector): reentrancy guard so patching does not hook its own codesign`.

---

## Phase E — Golden vectors + cross-impl parity

### Task E1: Committed fixtures + byte-identical thinner parity

**Files:** Create `pkg/local/testdata/sip/` (also referenced from the injector cgo test via a relative path); Create `pkg/local/sip_parity_test.go` and extend `injector/sip_cgo_test.go`.

**Interfaces:** Fixtures: `fat_x64_arm64e` (a small universal Mach-O — build a tiny `int main(){}` with `clang -arch x86_64 -arch arm64` at fixture-gen time and commit the output, or copy `/usr/bin/true` into testdata during a `go generate`-style helper and commit), `thin_x64`, `thin_arm64e`, `script.sh` (`#!/bin/bash`). Keep them tiny.

- [ ] **Step 1: Failing test** — `pkg/local/sip_parity_test.go`: for each fixture, `chooseSlice` (Go) output bytes are recorded to a golden `.slice` file; a test asserts the current output equals the golden. In `injector/sip_cgo_test.go`, assert `mg_sip_choose_slice` produces bytes byte-identical to the same golden `.slice`.
- [ ] **Step 2: Run — FAIL** (goldens absent → generate with an `-update` flag guarded helper, then commit).
- [ ] **Step 3: Generate + commit goldens**; implement the parity assertions.
- [ ] **Step 4: Run — PASS** both `go test -race ./pkg/local/` and `cd injector && go test -run TestCSipParity`.
- [ ] **Step 5: Commit** `test(sip): golden-vector parity between Go and C thinners`.

### Task E2: Makefile C-test target + README

**Files:** Modify `Makefile`, `README.md`.

- [ ] **Step 1:** Add `make test-injector-c` that runs `cd injector && go test -tags darwin -run TestCSip ./...` (darwin) and is a no-op message on linux; wire it into `test` on darwin. Update `README.md` macOS section: SIP-restricted binaries are now supported via copy+thin+ad-hoc-resign (Rosetta for x86_64 slices); note arm64e-only limitation + fail-loud.
- [ ] **Step 2:** Run `make test` on darwin → green.
- [ ] **Step 3: Commit** `docs(sip): document macOS SIP support + wire C parity test into make test`.

---

## Phase H — honey integration (SEPARATE honey PR, after mogate SIP release)

> These tasks land in the **honey** repo and depend on a cut mogate SIP release. Do NOT include in the mogate PR. Listed so the release coupling is explicit.

- [ ] **H1:** `scripts/build-intercept-injector.sh` — build the real `darwin_amd64` injector on the Apple-Silicon builder (`DARWIN_AMD64_CC="clang"` with `-arch x86_64` in `SHARED_FLAGS`); fail the build if the release cannot produce it (targetless/SIP need it).
- [ ] **H2:** honey local wiring — extract both `darwin_arm64` + `darwin_amd64` dylibs and set `local.Config.InjectorLib` + `InjectorLibRosetta`.
- [ ] **H3:** bump `INJECTOR_REF` + `github.com/shareed2k/mogate` to the SIP release; `go mod tidy`.
- [ ] **H4:** `website/docs/intercept.md` — macOS section: system binaries / bare `bash` / scripts now work; note Rosetta requirement + fail-loud + arm64e-only limitation.
- [ ] **H5:** manual runbook verification on the Apple-Silicon host (see Verification).

---

## Verification

- **Go unit (`-race`, on darwin host):** `cd pkg/local && go test -race ./...` — detection, slice choice, resign seam, shebang, cache reuse, arch selection, fail-loud, parity goldens.
- **C unit / parity (darwin host):** `cd injector && go test -run TestCSip -v` — detection, `mg_sip_patch` cache, exec-detour path rewrite + envp DYLD preservation, reentrancy guard, golden parity.
- **macOS manual runbook (Apple Silicon + Rosetta), the real proof** (after Phase H wires honey):
  - `honey intercept --cluster <c> --mode egress -- /usr/bin/curl http://<svc>` → 200 via the agent; `~/Library/Caches/mogate/sip/v1/usr/bin/curl` created; `ls -lO /usr/bin/curl` still `restricted` (original untouched).
  - `honey intercept … -- bash -c 'curl http://<svc>'` → child intercepted.
  - `honey intercept … -- ./script.sh` (`#!/bin/bash`, body `curl http://<svc>`) → intercepted via patched interpreter.
  - Rosetta-absent simulation (or arm64e-only fixture) → fail-loud with the remediation message; command not run.
- **lefthook / CI:** mogate CI is Linux — it builds the linux injector + runs the Go suite with the darwin files excluded; the darwin SIP suite runs on a macOS host / the manual runbook. Note this asymmetry in the PR description.

## Risks / notes

- **`debug/macho` does not type `LC_CODE_SIGNATURE`** — the CodeDirectory flags + entitlements are parsed from raw load-command + SuperBlob bytes (Task A1). Keep that parser small and fixture-tested; it is the subtlest Go code here.
- **C/Go parity** is the top drift risk — Phase E goldens are the guard; run both suites in the same task before marking C tasks done.
- **arm64e-only binaries** are unsupported (fail-loud); revisit with an arm64e-native injector when Apple reduces Rosetta.
- **macOS-only CI gap:** the C SIP + real injection path can only be exercised on a macOS runner or the manual runbook; the PR must state this explicitly so review does not assume Linux CI covered it.
- Patch cache is per-user (`~/Library/Caches`), mode 0700; originals never modified; ad-hoc re-sign strips entitlements (less privilege). No escalation.
