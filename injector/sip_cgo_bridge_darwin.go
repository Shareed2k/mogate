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
