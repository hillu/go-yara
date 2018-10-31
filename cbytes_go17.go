// Copyright © 2015-2017 Hilko Bengen <bengen@hilluzination.de>. All rights reserved.
// Use of this source code is governed by the license that can be
// found in the LICENSE file.

// +build go1.7

package yara

import "C"
import "unsafe"

func cBytes(data []byte) (unsafe.Pointer, C.size_t) {
	return C.CBytes(data), C.size_t(len(data))
}
