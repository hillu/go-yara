//go:build !go1.17
// +build !go1.17

// This variant contains a modified backport of go 1.18's "runtime/cgo".Handle that returns valid, CGO allocated pointers.

package yara

import (
	"sync"
	"sync/atomic"
	"unsafe"
)

// #include <stdlib.h>
import "C"

type cgoHandle uintptr

func newCgoHandle(v interface{}) *cgoHandle {
	handle := atomic.AddUintptr(&handleIdx, 1)
	if handle == 0 {
		panic("newCgoHandle: ran out of handle space")
	}

	handles.Store(handle, v)
	pointer := C.malloc(C.ulong(unsafe.Sizeof(handle)))
	*((*uintptr)(pointer)) = handle
	return (*cgoHandle)(pointer)
}

func (h *cgoHandle) Value() interface{} {
	v, ok := handles.Load(uintptr(*h))
	if !ok {
		panic("cgoHandle: misuse of an invalid Handle")
	}
	return v
}

func (h *cgoHandle) Delete() {
	_, ok := handles.LoadAndDelete(uintptr(*h))
	if !ok {
		panic("cgoHandle: misuse of an invalid Handle")
	}
	C.free(unsafe.Pointer(h))
}

func loadCgoHandle(pointer unsafe.Pointer) *cgoHandle {
	return (*cgoHandle)(pointer)
}

func (h *cgoHandle) Pointer() unsafe.Pointer {
	return (unsafe.Pointer)(h)
}

var (
	handles   = sync.Map{}
	handleIdx uintptr
)
