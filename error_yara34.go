// Copyright © 2017 Hilko Bengen <bengen@hilluzination.de>
// All rights reserved.
//
// Use of this source code is governed by the license that can be
// found in the LICENSE file.

// This file contains an additional error code introduced with yara 3.4.0.

// +build !yara3.3

package yara

// #include <yara.h>
import "C"

func init() {
	errorStrings[C.ERROR_EMPTY_STRING] = "empty string"
}
