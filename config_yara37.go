// Copyright © 2015-2019 Hilko Bengen <bengen@hilluzination.de>. All rights reserved.
// Use of this source code is governed by the license that can be
// found in the LICENSE file.

// +build !yara3.3,!yara3.4,!yara3.5,!yara3.6

package yara

// #include <yara.h>
import "C"

const ConfigMaxStringsPerRule ConfigName = C.YR_CONFIG_MAX_STRINGS_PER_RULE
