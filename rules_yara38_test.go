// Copyright © 2015-2017 Hilko Bengen <bengen@hilluzination.de>
// All rights reserved.
//
// Use of this source code is governed by the license that can be
// found in the LICENSE file.

// This file contains functionality that require libyara 3.8 or higher

// +build !yara3.3,!yara3.4,!yara3.5,!yara3.6,!yara3.7

package yara

import (
	"fmt"
	"sort"
	"strings"
	"testing"
)

func TestSortByCost(t *testing.T) {
	r := makeRules(t, `
		 rule fast { strings: $a = "abcd" condition: $a }
		 rule slow { strings: $a = /a.*b/ condition: $a }`)
	_, err := r.ScanMem([]byte(strings.Repeat("a", 1000)), 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	rules := r.GetRules()
	sort.Sort(ByCostDesc(rules))
	if rules[0].Identifier() != "slow" {
		t.Error("Slowest rule should be the first one (was YARA built with ./configure --enable-profiling?)")
	}
}

func TestGetMostCostlyRules(t *testing.T) {
	r := makeRules(t, `
		 rule fast1 { strings: $a = "abcd" condition: $a }
		 rule fast2 { strings: $a = "abcd" condition: $a }
		 rule fast3 { strings: $a = "abcd" condition: $a }
		 rule slow { strings: $a = /a.*b/ condition: $a }`)
	_, err := r.ScanMem([]byte(strings.Repeat("a", 1000)), 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	ruleCosts := r.GetMostCostlyRules(2)
	if len(ruleCosts) != 2 {
		t.Error("GetMostCostlyRules should return 2 items")
	}
	if ruleCosts[0].Rule.Identifier() != "slow" {
		t.Error("Slowest rule should be the first one")
	}
	if ruleCosts[0].Percentage < 90 {
		fmt.Println(ruleCosts[0].Percentage)
		t.Error("Slow rule cost percentage shold be >90%")
	}
}
