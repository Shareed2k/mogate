# macOS SIP-Patching for the Injector — Design

**Date:** 2026-08-14
**Repo:** mogate (separate PR from honey; honey consumes it via the pinned injector module + `pkg/local`)
**Status:** Approved design — ready for implementation planning.

## Goal

Make an injected local command work on macOS when the command, a child it
spawns, or a script's interpreter is a **SIP-restricted** system binary
(`/usr/bin/curl`, `/bin/bash`, `/usr/bin/python3`, …). Today macOS `dyld`
strips `DYLD_INSERT_LIBRARIES` before executing a restricted binary, so the
mogate injector never loads and that process's traffic is **not** intercepted.

Concretely, all three of these must route through the agent after this work:

```
honey intercept -- /usr/bin/curl http://svc        # top-level restricted binary
honey intercept -- bash -c 'curl http://svc'        # restricted child of a restricted binary
honey intercept -- ./deploy.sh                       # script with #!/bin/bash interpreter
```

**Failure is loud.** If a binary cannot be patched, the command is **not run
un-intercepted** — abort with a clear, actionable error. Silently running on
the host network would leak traffic the user believes is going through the
cluster.

## Background — why `DYLD_INSERT_LIBRARIES` is ignored

macOS `dyld` refuses `DYLD_INSERT_LIBRARIES` (and other `DYLD_*` env vars) for a
binary that is **restricted**. A binary is restricted when any of:

- the file has the `SF_RESTRICTED` (`0x00080000`) BSD file flag, or
- its code signature sets the `RESTRICT` or `RUNTIME` (hardened-runtime) flags, or
- it is a **platform binary** — its cdhash is in the OS's AMFI trust cache
  (all Apple-shipped `/usr/bin`, `/bin`, `/sbin`, `/System` binaries), or
- it is setuid/setgid.

Verified on the target machine (Apple Silicon M3, macOS 26.4, Darwin 25):

```
$ lipo -archs /usr/bin/curl          # -> x86_64 arm64e    (universal, NO plain-arm64 slice)
$ codesign -dvvv /usr/bin/curl       # -> flags=0x0(none), Authority=Apple Software Signing (platform binary)
$ ls -lO /usr/bin/curl               # -> restricted        (SF_RESTRICTED file flag set)
```

Note the CS flags are `0x0` here — the restriction is carried by the
`SF_RESTRICTED` file flag **and** platform-binary status, not by the CS
`RESTRICT|RUNTIME` flags. Detection must cover both signals.

**The fix (mirrord-proven, verified end to end on the target machine):** operate
on a **copy** of the binary — copying to a new path drops `SF_RESTRICTED`, and
**ad-hoc re-signing** recomputes the cdhash so it is no longer a recognized
platform binary and drops the hardened-runtime flag. After that, `dyld` honors
`DYLD_INSERT_LIBRARIES`:

```
cp /usr/bin/curl /tmp/x/curl              # SF_RESTRICTED dropped by cp
# thin to a loadable slice (x86_64 here), then:
codesign --remove-signature /tmp/x/curl
codesign -s - -f /tmp/x/curl              # -> CodeDirectory flags=0x2(adhoc), Signature=adhoc
# /tmp/x/curl now honors DYLD_INSERT_LIBRARIES
```

## Mechanism — patch one binary

For a binary `B` at path `P`:

1. **Detect** — `needsPatch(P)` is true iff
   `(SF_RESTRICTED set on P) OR (CS flags intersect RESTRICT|RUNTIME)`, **and**
   the binary is **not** entitled `com.apple.security.cs.allow-dyld-environment-variables`
   (that entitlement means dyld already honors insertion — no patch needed).
   A non-Mach-O, non-`#!` file, or an unrestricted binary → no patch (run as-is).

2. **Thin** — choose a loadable slice from the (possibly fat) Mach-O:
   - prefer a **plain-arm64** slice (`CPU_TYPE_ARM64` and **not** `CPU_SUBTYPE_ARM64E`) — runs natively, native `arm64` injector;
   - else an **x86_64** slice (`CPU_TYPE_X86_64`) — runs under **Rosetta 2**, `x86_64` injector.
   - `arm64e`-only with no x86_64 slice → **unsupported** (fail-loud; see Risks).
   On the target machine, system binaries are `x86_64 arm64e` (no plain-arm64),
   so the **x86_64 + Rosetta** path is the one exercised. Extract the chosen
   slice **in-code** (no `lipo`; `lipo` is Xcode-CLT-gated). A thin (non-fat)
   Mach-O that is already a supported arch is copied whole.

3. **Re-sign ad-hoc** — on the extracted copy:
   `codesign --remove-signature P'` then `codesign -s - -f P'`. `/usr/bin/codesign`
   is base-OS (present without Xcode/CLT). Ad-hoc signing sets `flags=0x2(adhoc)`,
   carries no entitlements, and drops the `RUNTIME` flag.

4. **Result** — return the patched path `P'`. The caller runs `P'` with
   `DYLD_INSERT_LIBRARIES=<injector matching P''s arch>` and `MOGATE_SOCKET=…`.
   An x86_64 `P'` executes under Rosetta 2 automatically.

### Shebang scripts

If `P` begins with `#!`, it is a script, not a Mach-O. Parse the interpreter
path from the shebang (strip `#!`, skip whitespace, take the interpreter token).
Patch the **interpreter** via the mechanism above → `interp'`. Then either
(a) exec `interp' <args-of-shebang> P` directly, or (b) write a rewritten copy
of the script whose first line is `#!interp'` and run that. Approach (a) is
preferred (no script copy, no argv reshuffling surprises); (b) is the fallback
when the kernel/exec path must see a self-contained script. If `P` has no
shebang but is executed as a script, default the interpreter to `$SHELL`.

### Caching

Patched binaries are cached and reused across runs (patching costs a copy + a
`codesign` spawn):

- Directory: `<user-cache>/mogate/sip/<mogate-version>/<original-path>`
  (`<user-cache>` = `os.UserCacheDir()` in Go; `getenv("HOME")/Library/Caches`
  equivalent in C). Version-namespaced so a mogate upgrade re-patches.
- Staleness: if the cached patched file exists, reuse it; else patch and write
  it. (Version namespacing is the coarse invalidation; per-file mtime/cdhash
  checks are a possible refinement, not required for v1.)
- Patching writes only into this cache. **The original system binary is never
  modified.**

## Architecture — two patch points, both in mogate

The same routine runs in two contexts. Per the approved decision, each context
gets a native implementation kept in lockstep by shared golden test vectors
(rather than a single shared binary or cgo in `pkg/local`, which would force a C
toolchain on honey's pure-Go build or ship a second embedded artifact).

### A. Top-level binary — `pkg/local` (pure Go)

The top-level `-- <cmd>` is spawned by `pkg/local/execute()` via `os/exec`,
which sets `DYLD_INSERT_LIBRARIES` in `injectedEnvironment()`. This is where the
top-level binary is patched, before the child is spawned.

- New files: `pkg/local/sip_darwin.go` (real) and `pkg/local/sip_other.go`
  (no-op stub returning "not needed" so non-darwin builds are unaffected),
  split by `//go:build darwin` / `//go:build !darwin`.
- Core: `patchIfRestricted(binPath string) (patched sipResult, err error)`
  where `sipResult` carries the patched path (or the original if no patch was
  needed) and the slice arch chosen (so the caller picks the matching injector).
- Thinning uses `debug/macho` (`macho.NewFatFile` → iterate `Arches` → pick the
  slice → copy its bytes). No `lipo`.
- Signing shells `/usr/bin/codesign` (`--remove-signature`, then `-s - -f`).
- `execute()` on darwin: resolve `command[0]`; if it is a `#!` script, patch the
  interpreter and rewrite the exec to `interp' … command[0]`; else patch
  `command[0]`. Then select the injector library whose arch matches the patched
  slice (native-arm64 → `InjectorLib`; x86_64 → new `InjectorLibRosetta`), set
  `DYLD_INSERT_LIBRARIES` to it, and spawn the patched path.
- **Fail-loud:** any patch error returns from `Run` with an actionable message;
  the command is not spawned.

### B. Children — C injector (`injector/sip.c` + new exec interposers)

Once the top-level (patched, unrestricted) process spawns a **child** that is
itself a restricted binary, `dyld` would strip the injector from the child. The
only place to catch this is **in-process, in the parent**, at the exec call —
which the injector is loaded into. The injector already interposes syscalls via
the `__DATA,__interpose` section (`DYLD_INTERPOSE`); this adds exec interposers.

- New files: `injector/sip.c` and `injector/sip.h` (compiled into the injector
  dylib alongside `injector/main.go`'s cgo C block). `mg_sip_patch(const char *path)`
  → returns a newly-allocated patched path (caller frees) or `NULL` when no
  patch is needed; same 4 steps as the Go side (manual fat-header parse for
  thinning — `struct fat_header`/`fat_arch`, big-endian byte-swap; `posix_spawn`
  of `/usr/bin/codesign` for signing; same cache dir).
- New interposers (added to the interpose table in `injector/main.go`'s C block):
  `execve`, `execvp`, `posix_spawn`, `posix_spawnp`. (`execv`, `execl`, `execle`,
  `execlp`, `execvP` funnel through `execve`/`execvp` in libc, so these four
  cover the family.) Each detour:
  1. resolve the target path (for `execvp`/`posix_spawnp`, `PATH`-resolve first);
  2. `mg_sip_patch()` it (handling `#!` scripts by patching the interpreter);
  3. ensure the child's `envp` contains `DYLD_INSERT_LIBRARIES=<this same
     injector>` and `MOGATE_SOCKET=<socket>` (re-add if a caller dropped them);
  4. call the **real** exec function with the patched path + fixed `envp`.
- **Reentrancy guard:** `mg_sip_patch` spawns `/usr/bin/codesign`, which would
  re-enter the `posix_spawn` interposer and try to patch codesign itself.
  A thread-local (or a well-known env marker) guard makes the patch routine's
  own spawns call the real functions directly, and `/usr/bin/codesign` /
  `/usr/bin/lipo`-class helper paths are never patched.
- The child of an x86_64/Rosetta parent is already x86_64, so it stays
  x86_64/Rosetta + injected with the x86_64 injector the parent was loaded from.

### Shared correctness — golden vectors

`testdata/sip/` holds small committed Mach-O fixtures (a fat `x86_64+arm64e`
sample, a thin x86_64, a thin arm64e, a `#!` script). A test asserts the Go and
C thinners produce **byte-identical** output for each fixture and that
`needsPatch`/detection agrees across both implementations. This is the guard
against the two implementations drifting.

## Build + honey wiring (required for the x86_64/Rosetta path)

Because system binaries thin to **x86_64**, the **x86_64 injector must exist**.
Today honey embeds a real `darwin_arm64/injector.dylib` but only a
`darwin_amd64/lib.placeholder`.

- mogate `Makefile` / honey `scripts/build-intercept-injector.sh` must emit
  **both** real darwin dylibs. On an Apple-Silicon builder, `clang -arch x86_64`
  cross-compiles the x86_64 dylib natively (no osxcross). Fail the build if the
  host darwin arch's injector cannot be built; the cross darwin arch is built
  when its compiler is available (it is, via `-arch`).
- `pkg/local.Config` gains `InjectorLibRosetta string` (path to the x86_64
  injector), used when a binary is thinned to x86_64. `InjectorLib` stays the
  native/default. A darwin session with only `InjectorLib` set and a binary that
  requires the x86_64 path → fail-loud (missing Rosetta injector).
- honey extracts **both** darwin injectors and sets both `Config` fields.
- At release: cut the mogate SIP version, bump honey's `INJECTOR_REF` and the
  `github.com/shareed2k/mogate` module version.

## Fail-loud behavior

Every unrecoverable patch condition aborts `Run` (Go) / the exec detour (C
returns the exec error) with a specific message, e.g.:

- arm64e-only, no x86_64 slice:
  `intercept: <bin> has no injectable slice (arm64e-only); SIP-patching needs an x86_64 or plain-arm64 slice`
- x86_64 slice chosen but Rosetta 2 absent:
  `intercept: <bin> must run under Rosetta 2 to be intercepted; install it: softwareupdate --install-rosetta`
- `codesign` failure: surface `codesign` stderr and abort.
- injector for the chosen arch missing: name the arch and abort.

## Testing

- **Go unit (`-race`):** `needsPatch` across SF_RESTRICTED / CS `RESTRICT|RUNTIME`
  / `allow-dyld-environment-variables` exemption (crafted Mach-O fixtures); fat
  slice selection (arm64 preferred, arm64e excluded, x86_64 fallback, arm64e-only
  → error); in-code thinning byte-exactness; shebang parse + interpreter
  resolution; cache reuse; injector-arch selection; fail-loud paths. No network,
  no real signing in unit tests (sign step behind a seam that a fake can assert
  the command line of).
- **C unit:** fat-header parse + thinning parity with the Go output; detection;
  exec-detour path rewrite and `envp` DYLD/socket preservation via a test harness
  that calls the detour with a captured "real exec" spy; reentrancy guard.
- **Golden parity:** Go vs C thinner byte-identical on every `testdata/sip/`
  fixture.
- **macOS e2e (opt-in build tag, manual runbook):** mogate CI is Linux, so real
  SIP behavior is exercised behind a `sip_e2e` (macOS-only) tag and a documented
  manual runbook on an Apple-Silicon host with Rosetta:
  `-- /usr/bin/curl …` (top-level), `-- bash -c 'curl …'` (child),
  `-- ./script.sh` with `#!/bin/bash` (shebang) all reach the egress target;
  Rosetta-absent simulation → fail-loud. Assert the cache dir is populated and
  the original binaries are untouched.

## Risks / limitations

- **arm64e-only binaries** (no x86_64 slice, no plain-arm64 slice): unsupported
  in v1 → fail-loud. Rare today (Apple system binaries are still universal), but
  Apple is scaling back Rosetta/x86_64; a future **arm64e-native injector**
  (matching the platform arm64e ABI + PAC) is the follow-up that removes the
  Rosetta dependency.
- **Rosetta 2 dependency** for the x86_64 path on Apple Silicon — required and
  documented; fail-loud when absent.
- **codesign** is base-OS (no CLT); **thinning is in-code** (no `lipo`/CLT) — so
  neither honey nor mogate gains an Xcode-CLT build/runtime requirement.
- **Reentrancy** in the C exec detour (patching spawns codesign) is the main
  correctness hazard — covered by the guard + a dedicated test.
- **Security:** patching mutates only cache **copies**, never originals; ad-hoc
  re-signing **removes** entitlements, so the patched copy is strictly *less*
  privileged than the original; it runs the user's own command; there is no
  privilege escalation. The cache lives under the user's own cache dir (mode
  0700).

## Out of scope (v1)

- arm64e-native injection (removes Rosetta dependency) — follow-up.
- Linux has no SIP; this is darwin-only. `sip_other.go` / non-darwin builds are
  strictly no-ops.
- Per-file cache invalidation beyond version-namespacing.
- Windows.
