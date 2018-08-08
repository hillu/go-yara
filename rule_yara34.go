// Copyright © 2018 Hilko Bengen <bengen@hilluzination.de>
// All rights reserved.
//
// Use of this source code is governed by the license that can be
// found in the LICENSE file.

// +build yara3.3 yara3.4

package yara

// #include <yara.h>
import "C"
import (
	"reflect"
	"unsafe"
)

// Data returns the blob of data associated with the string match
func (m *Match) Data() []byte {
	tmpbuf := []byte{}
	// Use unsafe instead of C.GoBytes to avoid "cgo argument has Go
	// pointer to Go pointer" panic (see
	// https://github.com/hillu/go-yara/issues/5)
	hdr := (*reflect.SliceHeader)(unsafe.Pointer(&tmpbuf))
	hdr.Data = uintptr(*(*unsafe.Pointer)(unsafe.Pointer(&(m.cptr.anon0))))
	hdr.Len = int(m.cptr.length)
	hdr.Cap = int(m.cptr.length)
	buf := make([]byte, len(tmpbuf))
	copy(buf, tmpbuf)
	return buf
}
