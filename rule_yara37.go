// Copyright © 2015-2017 Hilko Bengen <bengen@hilluzination.de>
// All rights reserved.
//
// Use of this source code is governed by the license that can be
// found in the LICENSE file.

//+build !yara3.3,!yara3.4,!yara3.5,!yara3.6

package yara

// #include <yara.h>
import "C"

// Enable enables a single rule
func (r *Rule) Enable() {
	C.yr_rule_enable(r.cptr)
}

// Disable disables a single rule
func (r *Rule) Disable() {
	C.yr_rule_disable(r.cptr)
}
