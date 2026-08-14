//go:build darwin

package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
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

const (
	testSelf   = "/opt/mogate/libmogate.dylib"
	testSocket = "/tmp/mogate-test.sock"
)

// envGet returns the value of key in a "KEY=value" slice, or "" plus false.
func envGet(env []string, key string) (string, bool) {
	prefix := key + "="
	for _, e := range env {
		if strings.HasPrefix(e, prefix) {
			return strings.TrimPrefix(e, prefix), true
		}
	}
	return "", false
}

// assertInjectedEnv fails unless the recorded env re-asserts the injector's own
// DYLD_INSERT_LIBRARIES and the relay MOGATE_SOCKET.
func assertInjectedEnv(t *testing.T, env []string) {
	t.Helper()
	dyld, ok := envGet(env, "DYLD_INSERT_LIBRARIES")
	if !ok {
		t.Fatalf("recorded env is missing DYLD_INSERT_LIBRARIES: %v", env)
	}
	if !strings.Contains(dyld, testSelf) {
		t.Errorf("DYLD_INSERT_LIBRARIES = %q, want it to list %q", dyld, testSelf)
	}
	if sock, ok := envGet(env, "MOGATE_SOCKET"); !ok || sock != testSocket {
		t.Errorf("MOGATE_SOCKET = %q (present=%v), want %q", sock, ok, testSocket)
	}
}

// TestCSipExecDetour_RestrictedPatched proves the execve detour rewrites the
// target of a restricted binary to its patched cache copy while re-asserting the
// injector's DYLD_INSERT_LIBRARIES. /usr/bin/true is universal (x86_64+arm64e),
// so it is thinned and ad-hoc re-signed just like TestCSipPatch.
func TestCSipExecDetour_RestrictedPatched(t *testing.T) {
	if _, err := os.Stat("/usr/bin/codesign"); err != nil {
		t.Skip("codesign unavailable; the detour cannot patch a restricted binary")
	}
	home := t.TempDir()
	t.Setenv("HOME", home)
	want := filepath.Join(home, "Library", "Caches", "mogate", "sip", "v1", "usr", "bin", "true")

	rec := sipExecveDetour("/usr/bin/true",
		[]string{"/usr/bin/true", "--version"},
		[]string{"PATH=/usr/bin", "HOME=" + home},
		testSelf, testSocket)

	if rec.rc != 0 {
		t.Fatalf("detour rc = %d, want 0 (spy reached)", rec.rc)
	}
	if rec.path != want {
		t.Fatalf("exec path = %q, want the patched copy %q", rec.path, want)
	}
	// A non-script keeps its original argv unchanged.
	if len(rec.argv) != 2 || rec.argv[0] != "/usr/bin/true" || rec.argv[1] != "--version" {
		t.Errorf("argv = %v, want [/usr/bin/true --version]", rec.argv)
	}
	assertInjectedEnv(t, rec.env)
}

// TestCSipExecDetour_NonRestrictedOriginal proves a path that needs no patch is
// exec'd unchanged, but the environment still carries the injector (re-added
// here because the supplied env dropped both variables).
func TestCSipExecDetour_NonRestrictedOriginal(t *testing.T) {
	plain := filepath.Join(t.TempDir(), "plain")
	if err := os.WriteFile(plain, []byte("not a mach-o\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	rec := sipExecveDetour(plain,
		[]string{plain, "arg"},
		[]string{"PATH=/usr/bin"}, // no DYLD, no MOGATE_SOCKET
		testSelf, testSocket)

	if rec.rc != 0 {
		t.Fatalf("detour rc = %d, want 0", rec.rc)
	}
	if rec.path != plain {
		t.Fatalf("exec path = %q, want the unchanged original %q", rec.path, plain)
	}
	assertInjectedEnv(t, rec.env)
}

// TestCSipExecDetour_PreservesExistingDyld proves that when the child env already
// lists the injector in DYLD_INSERT_LIBRARIES, the detour does not duplicate it
// and preserves any other entries the caller set.
func TestCSipExecDetour_PreservesExistingDyld(t *testing.T) {
	plain := filepath.Join(t.TempDir(), "plain")
	if err := os.WriteFile(plain, []byte("not a mach-o\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	existing := testSelf + ":/some/other.dylib"
	rec := sipExecveDetour(plain,
		[]string{plain},
		[]string{"DYLD_INSERT_LIBRARIES=" + existing, "MOGATE_SOCKET=" + testSocket},
		testSelf, testSocket)

	dyld, ok := envGet(rec.env, "DYLD_INSERT_LIBRARIES")
	if !ok {
		t.Fatalf("missing DYLD_INSERT_LIBRARIES: %v", rec.env)
	}
	if dyld != existing {
		t.Errorf("DYLD_INSERT_LIBRARIES = %q, want it left as %q (self already present)", dyld, existing)
	}
	if strings.Count(dyld, testSelf) != 1 {
		t.Errorf("self %q duplicated in %q", testSelf, dyld)
	}
}

// TestCSipExecDetour_Script proves a "#!" script is rewritten to run its
// (patched) interpreter with argv [interp, shebangArgs..., scriptPath,
// origArgv[1:]...]. The interpreter here is an ordinary file needing no patch,
// so no codesign is required.
func TestCSipExecDetour_Script(t *testing.T) {
	dir := t.TempDir()
	interp := filepath.Join(dir, "fakeinterp")
	if err := os.WriteFile(interp, []byte("plain interpreter, not a mach-o\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	script := filepath.Join(dir, "run.sh")
	if err := os.WriteFile(script, []byte("#!"+interp+" -x -y\nbody\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	rec := sipExecveDetour(script,
		[]string{script, "A", "B"},
		[]string{"PATH=/usr/bin"},
		testSelf, testSocket)

	if rec.rc != 0 {
		t.Fatalf("detour rc = %d, want 0", rec.rc)
	}
	if rec.path != interp {
		t.Fatalf("exec path = %q, want the interpreter %q", rec.path, interp)
	}
	wantArgv := []string{interp, "-x", "-y", script, "A", "B"}
	if !slices.Equal(rec.argv, wantArgv) {
		t.Fatalf("argv = %v, want %v", rec.argv, wantArgv)
	}
	assertInjectedEnv(t, rec.env)
}

// TestCSipExecDetour_FailLoud proves the detour refuses to exec a target it
// cannot resolve into an executable: a shebang whose interpreter does not exist
// is a hard failure (mg_sip_patch sets a last-error), so the spy is never
// reached and the detour returns -1.
func TestCSipExecDetour_FailLoud(t *testing.T) {
	dir := t.TempDir()
	script := filepath.Join(dir, "bad.sh")
	if err := os.WriteFile(script, []byte("#!"+dir+"/does-not-exist\nbody\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	rec := sipExecveDetour(script,
		[]string{script},
		[]string{"PATH=/usr/bin"},
		testSelf, testSocket)

	if rec.rc != -1 {
		t.Fatalf("detour rc = %d, want -1 (fail-loud, spy not reached)", rec.rc)
	}
	if rec.path != "" {
		t.Fatalf("spy recorded path %q, want it never called", rec.path)
	}
}

// TestCSipExecDetour_ExecvpResolvesPath proves the execvp detour PATH-resolves a
// bare command name before patching, and still injects the environment.
func TestCSipExecDetour_ExecvpResolvesPath(t *testing.T) {
	dir := t.TempDir()
	tool := filepath.Join(dir, "mytool")
	if err := os.WriteFile(tool, []byte("not a mach-o\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir)
	rec := sipExecvpDetour("mytool", []string{"mytool", "-v"}, testSelf, testSocket)

	if rec.rc != 0 {
		t.Fatalf("detour rc = %d, want 0", rec.rc)
	}
	if rec.path != tool {
		t.Fatalf("exec path = %q, want PATH-resolved %q", rec.path, tool)
	}
	assertInjectedEnv(t, rec.env)
}

// TestCSipExecDetour_PosixSpawn proves the posix_spawn detour applies the same
// patch + env rewrite as execve for a restricted binary.
func TestCSipExecDetour_PosixSpawn(t *testing.T) {
	if _, err := os.Stat("/usr/bin/codesign"); err != nil {
		t.Skip("codesign unavailable; the detour cannot patch a restricted binary")
	}
	home := t.TempDir()
	t.Setenv("HOME", home)
	want := filepath.Join(home, "Library", "Caches", "mogate", "sip", "v1", "usr", "bin", "true")

	rec := sipPosixSpawnDetour("/usr/bin/true",
		[]string{"/usr/bin/true"},
		[]string{"PATH=/usr/bin", "HOME=" + home},
		testSelf, testSocket)

	if rec.rc != 0 {
		t.Fatalf("detour rc = %d, want 0 (posix_spawn success)", rec.rc)
	}
	if rec.path != want {
		t.Fatalf("spawn path = %q, want the patched copy %q", rec.path, want)
	}
	assertInjectedEnv(t, rec.env)
}

// TestCSipExecDetour_GuardSkipsReentrantPatch is the core D2 reentrancy proof.
// It simulates being mid-patch (mg_sip_in_patch set) and shows that a re-entrant
// exec detour on a restricted binary does NOT patch: it calls the real exec with
// the ORIGINAL path, the ORIGINAL argv, and the ORIGINAL env (no DYLD/MOGATE
// rewrite). In the live dylib this is the path the codesign spawn takes, so a
// restricted signing tool is never re-patched -> no unbounded recursion.
//
// The guard is thread-local, so the goroutine is pinned to its OS thread for the
// whole test: the C call that sets the guard and the C calls that run the detours
// must observe the same __thread variable. The guard is restored to 0 (then the
// thread unlocked) via defers so a t.Fatalf cannot leak it into another test.
func TestCSipExecDetour_GuardSkipsReentrantPatch(t *testing.T) {
	// mg_sip_in_patch is a C __thread, so the C call that sets it and the C calls
	// that run the detours must share one OS thread: pin the goroutine and keep
	// everything on this goroutine (no t.Run, which would hop to a new one).
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	sipSetInPatch(1)
	defer sipSetInPatch(0)

	argv := []string{"/usr/bin/curl", "--version"}
	env := []string{"PATH=/usr/bin"}

	check := func(name string, rec sipExecRecord) {
		if rec.rc != 0 {
			t.Errorf("%s: detour rc = %d, want 0 (real exec reached directly)", name, rec.rc)
		}
		if rec.path != "/usr/bin/curl" {
			t.Errorf("%s: exec path = %q, want the ORIGINAL /usr/bin/curl (guard must skip patching)", name, rec.path)
		}
		if !slices.Equal(rec.argv, argv) {
			t.Errorf("%s: argv = %v, want the original %v (no rewrite under guard)", name, rec.argv, argv)
		}
		// Under the guard the env is passed straight through: no injection.
		if !slices.Equal(rec.env, env) {
			t.Errorf("%s: env = %v, want the original %v (no rewrite under guard)", name, rec.env, env)
		}
		if _, ok := envGet(rec.env, "DYLD_INSERT_LIBRARIES"); ok {
			t.Errorf("%s: env injected DYLD_INSERT_LIBRARIES under guard: %v", name, rec.env)
		}
		if _, ok := envGet(rec.env, "MOGATE_SOCKET"); ok {
			t.Errorf("%s: env injected MOGATE_SOCKET under guard: %v", name, rec.env)
		}
	}

	check("posix_spawn", sipPosixSpawnDetour("/usr/bin/curl", argv, env, testSelf, testSocket))
	check("execve", sipExecveDetour("/usr/bin/curl", argv, env, testSelf, testSocket))
}

// TestCSipPatch_SkipsSigningTools proves the belt-and-suspenders path skip: even
// called directly, mg_sip_patch never patches the signing tools it depends on.
// It returns NULL with an empty last error (the "run the original" outcome, not a
// hard failure), so the detour execs /usr/bin/codesign (and /usr/bin/lipo)
// unchanged rather than thinning + re-signing them (which would itself spawn
// codesign). This holds regardless of the reentrancy guard.
func TestCSipPatch_SkipsSigningTools(t *testing.T) {
	for _, tool := range []string{"/usr/bin/codesign", "/usr/bin/lipo"} {
		t.Run(tool, func(t *testing.T) {
			if _, err := os.Stat(tool); err != nil {
				t.Skipf("%s unavailable", tool)
			}
			// Redirect HOME so that, if the skip regressed, a produced cache copy
			// would land in a temp dir instead of the real user cache.
			t.Setenv("HOME", t.TempDir())
			res := sipPatch(tool)
			if res.ok {
				t.Fatalf("mg_sip_patch(%q) = %q, want NULL (signing tool must not be patched)", tool, res.path)
			}
			if res.err != "" {
				t.Fatalf("mg_sip_patch(%q) set last error %q, want empty (skip is a no-op, not a failure)", tool, res.err)
			}
		})
	}
}

// TestCSipExecDetour_CodesignNeverPatched proves the same skip through the detour:
// exec'ing /usr/bin/codesign resolves to the ORIGINAL path (not a thinned cache
// copy), so the signing tool the patch pipeline itself invokes is never rewritten.
// The environment is still injected here (the guard is not set) — only the
// executable is left untouched.
func TestCSipExecDetour_CodesignNeverPatched(t *testing.T) {
	if _, err := os.Stat("/usr/bin/codesign"); err != nil {
		t.Skip("codesign unavailable")
	}
	t.Setenv("HOME", t.TempDir())
	rec := sipPosixSpawnDetour("/usr/bin/codesign",
		[]string{"/usr/bin/codesign", "--version"},
		[]string{"PATH=/usr/bin"},
		testSelf, testSocket)

	if rec.rc != 0 {
		t.Fatalf("detour rc = %d, want 0", rec.rc)
	}
	if rec.path != "/usr/bin/codesign" {
		t.Fatalf("exec path = %q, want the ORIGINAL /usr/bin/codesign (never patch the signing tool)", rec.path)
	}
	assertInjectedEnv(t, rec.env)
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
