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

func TestScannerError(t *testing.T) {
	r := makeRules(t,
		`rule test {
			strings:
				$a = "aa"
			condition:
				$a
		 }`)

	s, err := NewScanner(r)
	if err != nil {
		t.Errorf("NewScanner: %s", err)
	}
	_, err = s.ScanMem([]byte(strings.Repeat("a", 10000000)), 0, 0)
	if err == nil {
		t.Error("Expecting error")
	}

	if !strings.Contains(err.Error(), "test") {
		t.Error("Rule name expected in error message")
	}

	er := s.GetLastErrorRule()
	if er == nil {
		t.Error("The rule causing the error should not be nil")
	}
	if er.Identifier() != "test" {
		t.Error("The rule causing the error should be \"test\"")
	}

	es := s.GetLastErrorString()
	if es == nil {
		t.Error("The string causing the error should not be nil")
	}
	if es.Identifier() != "$a" {
		t.Error("The string causing the error should be \"$a\"")
	}
}
