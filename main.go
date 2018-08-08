// Copyright © 2015-2018 Hilko Bengen <bengen@hilluzination.de>
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
	if err := initialize(); err != nil {
		panic(err)
	}
}

// Prepares the library to be used.
func initialize() error {
	return newError(C.yr_initialize())
}

// Finalize releases all the resources allocated by the library. It should be
// called when your program is about to exit. Calling Finalize is not strictly
// required as the program is going to die anyways, but it's highly recommended
// because memory profiling tools can detect and report memory leaks if you
// don't. The recommended practice is calling it as a defered function in your
// program's main:
//  defer yara.Finalize()
func Finalize() error {
	return newError(C.yr_finalize())
}
