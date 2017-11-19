// Copyright © 2017 Hilko Bengen <bengen@hilluzination.de>
// All rights reserved.
//
// Use of this source code is governed by the license that can be
// found in the LICENSE file.

// This file contains additional error codes introduced with yara 3.5.0.

// +build !yara3.3,!yara3.4

package yara

// #include <yara.h>
import "C"

func init() {
	errorStrings[C.ERROR_DIVISION_BY_ZERO] = "division by zero"
	errorStrings[C.ERROR_REGULAR_EXPRESSION_TOO_LARGE] = "regular expression too large"
	errorStrings[C.ERROR_TOO_MANY_RE_FIBERS] = "too many regular expression fibers"
	errorStrings[C.ERROR_COULD_NOT_READ_PROCESS_MEMORY] = "could not read process memory"
	errorStrings[C.ERROR_INVALID_EXTERNAL_VARIABLE_TYPE] = "invalid external variable type"
}
