// Copyright © 2018 Hilko Bengen <bengen@hilluzination.de>
// All rights reserved.
//
// Use of this source code is governed by the license that can be
// found in the LICENSE file.

// This file contains additional error codes introduced with yara 3.7.0.

// +build !yara3.3,!yara3.4,!yara3.5,!yara3.6,!yara3.7

package yara

// #include <yara.h>
import "C"

func init() {
	errorStrings[C.ERROR_CALLBACK_REQUIRED] = "callback required"
	errorStrings[C.ERROR_INVALID_OPERAND] = "invalid operand"
	errorStrings[C.ERROR_COULD_NOT_READ_FILE] = "could not read file"
	errorStrings[C.ERROR_DUPLICATED_EXTERNAL_VARIABLE] = "duplicated external variable"
	errorStrings[C.ERROR_INVALID_MODULE_DATA] = "invalid module data"
	errorStrings[C.ERROR_WRITING_FILE] = "error writing file"
}
