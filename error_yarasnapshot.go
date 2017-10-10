// Copyright © 2017 Hilko Bengen <bengen@hilluzination.de>
// All rights reserved.
//
// Use of this source code is governed by the license that can be
// found in the LICENSE file.

// This file contains any additional error codes introduced on the
// master branch since yara 3.6.0.

// +build yara_snapshot

package yara

// #include <yara.h>
import "C"

func init() {
	errorStrings[C.ERROR_TOO_MANY_STRINGS] = "too many strings"
}
