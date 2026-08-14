//go:build darwin

package main

// Thin cgo bridge to the static C SIP functions in sip_darwin.h. Go forbids
// `import "C"` in _test.go files ("use of cgo in test not supported"), so the
// cgo calls live in this ordinary darwin-only file and the test calls these
// wrappers. Including sip_darwin.h here is a second translation unit alongside
// injector/main.go's cgo block, which is why those C functions are `static`
// (each TU gets its own copy; no duplicate-symbol link error).

/*
#include "sip_darwin.h"

// ---- D1 exec-detour test seam ------------------------------------------------
// The exec detours are parameterized on the real exec function, so the test
// injects a recording spy in its place instead of replacing the process. The
// spy deep-copies (path, argv, envp) into these globals; accessors below read
// them back into Go. mg_test_record duplicates the arrays because the detour
// frees its built envp once the spy returns.

static char *mg_test_rec_path;
static char **mg_test_rec_argv;
static char **mg_test_rec_env;

static char **mg_test_dup_strv(char *const v[]) {
	size_t n = 0;
	if (v) while (v[n]) n++;
	char **out = (char **)calloc(n + 1, sizeof(char *));
	if (!out) return NULL;
	for (size_t i = 0; i < n; i++) out[i] = strdup(v[i]);
	out[n] = NULL;
	return out;
}

static void mg_test_record(const char *path, char *const argv[], char *const envp[]) {
	free(mg_test_rec_path);
	mg_test_rec_path = path ? strdup(path) : NULL;
	mg_sip_free_strv(mg_test_rec_argv);
	mg_test_rec_argv = mg_test_dup_strv(argv);
	mg_sip_free_strv(mg_test_rec_env);
	mg_test_rec_env = mg_test_dup_strv(envp);
}

static void mg_test_reset(void) {
	free(mg_test_rec_path);
	mg_test_rec_path = NULL;
	mg_sip_free_strv(mg_test_rec_argv);
	mg_test_rec_argv = NULL;
	mg_sip_free_strv(mg_test_rec_env);
	mg_test_rec_env = NULL;
}

static int mg_test_spy_execve(const char *path, char *const argv[], char *const envp[]) {
	mg_test_record(path, argv, envp);
	return 0;
}

static int mg_test_spy_spawn(pid_t *pid, const char *path,
	const posix_spawn_file_actions_t *fa, const posix_spawnattr_t *attr,
	char *const argv[], char *const envp[]) {
	(void)fa;
	(void)attr;
	if (pid) *pid = 4242;
	mg_test_record(path, argv, envp);
	return 0;
}

static int mg_test_call_execve(const char *path, char *const argv[], char *const envp[],
	const char *self, const char *socket) {
	return mg_sip_execve_detour(path, argv, envp, self, socket, mg_test_spy_execve);
}

static int mg_test_call_execvp(const char *file, char *const argv[],
	const char *self, const char *socket) {
	return mg_sip_execvp_detour(file, argv, self, socket, mg_test_spy_execve);
}

static int mg_test_call_posix_spawn(const char *path, char *const argv[], char *const envp[],
	const char *self, const char *socket) {
	pid_t pid = 0;
	return mg_sip_posix_spawn_detour(&pid, path, NULL, NULL, argv, envp, self, socket, mg_test_spy_spawn);
}

static int mg_test_call_posix_spawnp(const char *file, char *const argv[], char *const envp[],
	const char *self, const char *socket) {
	pid_t pid = 0;
	return mg_sip_posix_spawnp_detour(&pid, file, NULL, NULL, argv, envp, self, socket, mg_test_spy_spawn);
}

static const char *mg_test_rec_path_get(void) { return mg_test_rec_path; }
static int mg_test_rec_argv_len(void) {
	int n = 0;
	if (mg_test_rec_argv) while (mg_test_rec_argv[n]) n++;
	return n;
}
static const char *mg_test_rec_argv_at(int i) {
	return mg_test_rec_argv ? mg_test_rec_argv[i] : NULL;
}
static int mg_test_rec_env_len(void) {
	int n = 0;
	if (mg_test_rec_env) while (mg_test_rec_env[n]) n++;
	return n;
}
static const char *mg_test_rec_env_at(int i) {
	return mg_test_rec_env ? mg_test_rec_env[i] : NULL;
}
*/
import "C"

import "unsafe"

// sipChooseSliceResult mirrors the outputs of the C mg_sip_choose_slice.
type sipChooseSliceResult struct {
	off     int
	size    int
	rosetta bool
	ok      bool // false when the C function returned NULL (no injectable slice/error)
}

// sipChooseSlice calls the C mg_sip_choose_slice over data and returns the
// chosen slice's offset/size, whether it is the x86_64/Rosetta slice, and
// whether a slice was found at all.
func sipChooseSlice(data []byte) sipChooseSliceResult {
	if len(data) == 0 {
		return sipChooseSliceResult{}
	}
	var off, size C.size_t
	var rosetta C.int
	cp := C.CBytes(data)
	defer C.free(cp)
	r := C.mg_sip_choose_slice((*C.uint8_t)(cp), C.size_t(len(data)), &off, &size, &rosetta)
	if r == nil {
		return sipChooseSliceResult{}
	}
	return sipChooseSliceResult{
		off:     int(off),
		size:    int(size),
		rosetta: rosetta == 1,
		ok:      true,
	}
}

// sipNeedsPatch calls the C mg_sip_needs_patch: 1 restricted, 0 not, -1 error.
func sipNeedsPatch(path string) int {
	cpath := C.CString(path)
	defer C.free(unsafe.Pointer(cpath))
	return int(C.mg_sip_needs_patch(cpath))
}

// sipPatchResult mirrors the outcome of the C mg_sip_patch: the returned path
// (empty when the C returned NULL), whether the C returned non-NULL, and the
// thread-local last-error string read after the call. On a NULL return, an empty
// err means "no patch needed" and a non-empty err means a hard failure.
type sipPatchResult struct {
	path string
	ok   bool
	err  string
}

// sipPatch calls the C mg_sip_patch, copying then freeing the malloc'd result,
// and reads mg_sip_last_error after the call so the test can distinguish the
// no-patch and failure cases that both return NULL.
func sipPatch(path string) sipPatchResult {
	cpath := C.CString(path)
	defer C.free(unsafe.Pointer(cpath))
	r := C.mg_sip_patch(cpath)
	res := sipPatchResult{err: C.GoString(C.mg_sip_last_error())}
	if r != nil {
		res.path = C.GoString(r)
		res.ok = true
		C.free(unsafe.Pointer(r))
	}
	return res
}

// sipExecRecord mirrors what the D1 exec detour handed to the (spy) real exec:
// the executable path, the child argv, the child envp, and the detour's return
// code (0 when the spy was reached; ENOEXEC/-1 on a fail-loud patch error).
type sipExecRecord struct {
	path string
	argv []string
	env  []string
	rc   int
}

// cStrv builds a malloc-free NULL-terminated C char* array from a Go slice,
// returning it plus a cleanup that frees the duplicated C strings. The backing
// array is Go memory holding only C pointers, so it is legal to pass to C for
// the duration of the call.
func cStrv(items []string) (**C.char, func()) {
	ptrs := make([]*C.char, len(items)+1)
	for i, s := range items {
		ptrs[i] = C.CString(s)
	}
	ptrs[len(items)] = nil
	cleanup := func() {
		for i := 0; i < len(items); i++ {
			C.free(unsafe.Pointer(ptrs[i]))
		}
	}
	return (**C.char)(unsafe.Pointer(&ptrs[0])), cleanup
}

// readExecRecord copies the C recorder globals set by the spy into Go.
func readExecRecord(rc C.int) sipExecRecord {
	rec := sipExecRecord{rc: int(rc)}
	if p := C.mg_test_rec_path_get(); p != nil {
		rec.path = C.GoString(p)
	}
	for i := 0; i < int(C.mg_test_rec_argv_len()); i++ {
		rec.argv = append(rec.argv, C.GoString(C.mg_test_rec_argv_at(C.int(i))))
	}
	for i := 0; i < int(C.mg_test_rec_env_len()); i++ {
		rec.env = append(rec.env, C.GoString(C.mg_test_rec_env_at(C.int(i))))
	}
	return rec
}

// sipExecveDetour drives mg_sip_execve_detour with a recording spy and returns
// what the detour would have exec'd.
func sipExecveDetour(path string, argv, envp []string, self, socket string) sipExecRecord {
	cpath := C.CString(path)
	defer C.free(unsafe.Pointer(cpath))
	cself := C.CString(self)
	defer C.free(unsafe.Pointer(cself))
	csock := C.CString(socket)
	defer C.free(unsafe.Pointer(csock))
	cargv, freeArgv := cStrv(argv)
	defer freeArgv()
	cenvp, freeEnvp := cStrv(envp)
	defer freeEnvp()
	C.mg_test_reset()
	rc := C.mg_test_call_execve(cpath, cargv, cenvp, cself, csock)
	return readExecRecord(rc)
}

// sipExecvpDetour drives mg_sip_execvp_detour (PATH-resolving file) with a spy.
// The detour injects into the current process environment, so envp is not passed.
func sipExecvpDetour(file string, argv []string, self, socket string) sipExecRecord {
	cfile := C.CString(file)
	defer C.free(unsafe.Pointer(cfile))
	cself := C.CString(self)
	defer C.free(unsafe.Pointer(cself))
	csock := C.CString(socket)
	defer C.free(unsafe.Pointer(csock))
	cargv, freeArgv := cStrv(argv)
	defer freeArgv()
	C.mg_test_reset()
	rc := C.mg_test_call_execvp(cfile, cargv, cself, csock)
	return readExecRecord(rc)
}

// sipPosixSpawnDetour drives mg_sip_posix_spawn_detour with a spy.
func sipPosixSpawnDetour(path string, argv, envp []string, self, socket string) sipExecRecord {
	cpath := C.CString(path)
	defer C.free(unsafe.Pointer(cpath))
	cself := C.CString(self)
	defer C.free(unsafe.Pointer(cself))
	csock := C.CString(socket)
	defer C.free(unsafe.Pointer(csock))
	cargv, freeArgv := cStrv(argv)
	defer freeArgv()
	cenvp, freeEnvp := cStrv(envp)
	defer freeEnvp()
	C.mg_test_reset()
	rc := C.mg_test_call_posix_spawn(cpath, cargv, cenvp, cself, csock)
	return readExecRecord(rc)
}

// sipPosixSpawnpDetour drives mg_sip_posix_spawnp_detour (PATH-resolving file).
func sipPosixSpawnpDetour(file string, argv, envp []string, self, socket string) sipExecRecord {
	cfile := C.CString(file)
	defer C.free(unsafe.Pointer(cfile))
	cself := C.CString(self)
	defer C.free(unsafe.Pointer(cself))
	csock := C.CString(socket)
	defer C.free(unsafe.Pointer(csock))
	cargv, freeArgv := cStrv(argv)
	defer freeArgv()
	cenvp, freeEnvp := cStrv(envp)
	defer freeEnvp()
	C.mg_test_reset()
	rc := C.mg_test_call_posix_spawnp(cfile, cargv, cenvp, cself, csock)
	return readExecRecord(rc)
}
