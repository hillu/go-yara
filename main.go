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

func init() {
	_ = C.yr_initialize()
}

// Finalize releases all the resources allocated by the library. It should be
// called when the program finishes using it.
func Finalize() {
	C.yr_finalize()
}
