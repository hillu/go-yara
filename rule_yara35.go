// Copyright © 2018 Hilko Bengen <bengen@hilluzination.de>
// All rights reserved.
//
// Use of this source code is governed by the license that can be
// found in the LICENSE file.

// +build !yara3.3,!yara3.4

package yara

// #include <yara.h>
import "C"
import "unsafe"

// Data returns the blob of data associated with the string match
func (m *Match) Data() []byte {
	return C.GoBytes(unsafe.Pointer(m.cptr.data), C.int(m.cptr.data_length))
}
