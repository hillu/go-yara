// Copyright © 2015-2017 Hilko Bengen <bengen@hilluzination.de>
// All rights reserved.
//
// Use of this source code is governed by the license that can be
// found in the LICENSE file.

// This file contains functionality that require libyara 3.8 or higher

//+build !yara3.3,!yara3.4,!yara3.5,!yara3.6,!yara3.7

package yara

import (
	"strings"
	"testing"
)

func TestScanner(t *testing.T) {
	r := makeRulesWithVars(t,
		`rule test {
			strings:
				$a = "abc" fullword
			condition:
				$a and int_var == 1 and bool_var
		 }`,
		map[string]interface{}{
			"int_var":  0,
			"bool_var": false,
		})
	s, err := NewScanner(r)
	if err != nil {
		t.Errorf("NewScanner: %s", err)
	}
	s.DefineVariable("int_var", 1)
	s.DefineVariable("bool_var", true)
	m, err := s.ScanMem([]byte(" abc "), 0, 0)
	if err != nil {
		t.Errorf("ScanMem: %s", err)
	}
	if len(m) != 1 {
		t.Errorf("Expecting a match.")
	}
	t.Logf("Matches: %+v", m)
}
