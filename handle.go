//go:build go1.17
// +build go1.17

// This variant contains a trivial wrapper around "runtime/cgo".Handle.

package yara

import (
	"runtime/cgo"
	"unsafe"
)

// #include <stdlib.h>
import "C"

type cgoHandle cgo.Handle

func (h *cgoHandle) Value() interface{} {
	return cgo.Handle(*h).Value()
}

func (h *cgoHandle) Delete() {
	cgo.Handle(*h).Delete()
	C.free(unsafe.Pointer(h))
}

func newCgoHandle(v interface{}) *cgoHandle {
	handle := cgo.NewHandle(v)
	pointer := C.malloc(C.ulong(unsafe.Sizeof(handle)))
	*((*uintptr)(pointer)) = uintptr(handle)
	return (*cgoHandle)(pointer)
}

func loadCgoHandle(pointer unsafe.Pointer) *cgoHandle {
	return (*cgoHandle)(pointer)
}

func (h *cgoHandle) Pointer() unsafe.Pointer {
	return (unsafe.Pointer)(h)
}
