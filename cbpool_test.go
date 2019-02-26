// Copyright © 2015-2019 Hilko Bengen <bengen@hilluzination.de>
// All rights reserved.
//
// Use of this source code is governed by the license that can be
// found in the LICENSE file.

package yara

import (
	"testing"
)

func TestBasic(t *testing.T) {
	pool := makecbPool(32)
	p1 := pool.Put("asdf")
	p2 := pool.Put("ghjk")
	s1, ok := pool.Get(p1).(string)
	if !ok || s1 != "asdf" {
		t.Errorf("s1: expected 'asdf', got '%v'", s1)
	}
	pool.Delete(p1)
	i := func() interface{} {
		defer func() {
			if x := recover(); x != nil {
				t.Logf("Get: Got expected panic: %v", x)
			}
		}()
		x := pool.Get(p1)
		t.Error("Get: No panic was triggered.")
		return x
	}()
	if s1, ok := i.(string); ok || s1 == "asdf" {
		t.Errorf("s1: expected nil, got '%v'", s1)
	}
	s2, ok := pool.Get(p2).(string)
	if !ok || s2 != "ghjk" {
		t.Errorf("s1: expected 'hjkl', got '%v'", s1)
	}
	pool.Delete(p2)
	func() {
		defer func() {
			if x := recover(); x != nil {
				t.Logf("Delete: Got expected panic: %v", x)
			}
		}()
		pool.Delete(p2)
		t.Error("Delete: No panic was triggered.")
	}()

	// Fill pool
	for i := 0; i < 32; i++ {
		pool.Put(i)
	}
	func() {
		defer func() {
			if x := recover(); x != nil {
				t.Logf("full pool: Got expected panic: %v", x)
			}
		}()
		pool.Put(100)
		t.Error("full pool: No panic was triggered.")
	}()
}
