// Copyright © 2015-2017 Hilko Bengen <bengen@hilluzination.de>. All rights reserved.
// Use of this source code is governed by the license that can be
// found in the LICENSE file.

// +build !go1.7

package yara

// #include <stdlib.h>
import "C"
import (
	"reflect"
	"unsafe"
)

func cBytes(data []byte) (unsafe.Pointer, C.size_t) {
	cbuf := C.malloc(C.size_t(len(data)))

	outbuf := make([]byte, 0)
	hdr := (*reflect.SliceHeader)(unsafe.Pointer(&outbuf))
	hdr.Data, hdr.Len, hdr.Cap = uintptr(cbuf), len(data), len(data)
	copy(outbuf, data)
	return cbuf, C.size_t(len(data))
}
