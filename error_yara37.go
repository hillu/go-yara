// Copyright © 2017 Hilko Bengen <bengen@hilluzination.de>
// All rights reserved.
//
// Use of this source code is governed by the license that can be
// found in the LICENSE file.

// This file contains additional error codes introduced with yara 3.7.0.

// +build !yara3.3,!yara3.4,!yara3.5,!yara3.6

package yara

// #include <yara.h>
import "C"

func init() {
	errorStrings[C.ERROR_TOO_MANY_STRINGS] = "too many strings"
	errorStrings[C.ERROR_INTEGER_OVERFLOW] = "integer overflow"
}
