// Copyright © 2015-2019 Hilko Bengen <bengen@hilluzination.de>
// All rights reserved.
//
// Use of this source code is governed by the license that can be
// found in the LICENSE file.

// This file contains additional error codes introduced with yara 3.11.0.

// +build !yara3.3,!yara3.4,!yara3.5,!yara3.6,!yara3.7,!yara3.8

package yara

// #include <yara.h>
import "C"

func init() {
	errorStrings[C.ERROR_INVALID_MODIFIER] = "invalid modifier"
	errorStrings[C.ERROR_DUPLICATED_MODIFIER] = "duplicated modifier"
}
