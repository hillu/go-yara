// Copyright © 2015-2017 Hilko Bengen <bengen@hilluzination.de>
// All rights reserved.
//
// Use of this source code is governed by the license that can be
// found in the LICENSE file.

package yara

/*
#include <yara.h>
*/
import "C"

import (
	"unsafe"
)

func init() {
	if err := Initialize(); err != nil {
		panic(err)
	}
}

// Initialize prepares the library to be used.
func Initialize() error {
	return newError(C.yr_initialize())
}

// Finalize releases all the resources allocated by the library. It should be
// called when the program finishes using it.
func Finalize() error {
	return newError(C.yr_finalize())
}

// GetMaxMatchData returns the value for YARA's YR_CONFIG_MAX_MATCH_DATA
// configuration option. This controls the maximum amount of bytes that YARA
// stores for each matching string.
func GetMaxMatchData() int {
	var m C.uint32_t
	C.yr_get_configuration(2, unsafe.Pointer(&m))
	return int(m)
}

// SetMaxMatchData sets the value for YR_CONFIG_MAX_MATCH_DATA configuration
// option, which controls the maximum amount of bytes that YARA stores for each
// matching string. If this value is zero YARA won't copy any data at all.
func SetMaxMatchData(n int) {
	a := C.uint32_t(n)
	C.yr_set_configuration(2, unsafe.Pointer(&a))
}
