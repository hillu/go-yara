// Copyright © 2015-2020 Hilko Bengen <bengen@hilluzination.de>
// All rights reserved.
//
// Use of this source code is governed by the license that can be
// found in the LICENSE file.

package yara

import "testing"

func TestCompiler(t *testing.T) {
	c, _ := NewCompiler()
	if err := c.AddString(
		"rule test : tag1 { meta: author = \"Hilko Bengen\" strings: $a = \"abc\" fullword condition: $a }", "",
	); err != nil {
		t.Errorf("error: %s", err)
	}
	if err := c.AddString("xxx", ""); err == nil {
		t.Error("did not recognize error")
	} else {
		t.Logf("expected error: %s", err)
	}
}

func TestPanic(t *testing.T) {
	defer func() {
		err := recover()
		if err == nil {
			t.Error("MustCompile with broken data did not panic")
		} else {
			t.Logf("Everything ok, MustCompile panicked: %v", err)
		}
	}()
	_ = MustCompile("asflkjkl", nil)
}

func TestWarnings(t *testing.T) {
	c, _ := NewCompiler()
	c.AddString("rule foo { bar }", "")
	if len(c.Errors) == 0 {
		t.Error()
	}
	t.Logf("Recorded Errors=%#v, Warnings=%#v", c.Errors, c.Warnings)
}

func setupCompiler(t *testing.T) *Compiler {
	c, err := NewCompiler()
	if err != nil {
		t.Fatal(err)
	}
	c.SetIncludeCallback(func(name, rulefile, namespace string) []byte {
		t.Logf(`Processing include "%s" (from ns="%s", file="%s")`, name, namespace, rulefile)
		if name == "existing" {
			return []byte(`rule ext { condition: true }`)
		}
		return nil
	})
	return c
}

func TestCompilerIncludeCallback(t *testing.T) {
	c := setupCompiler(t)
	var err error
	if err = c.AddString(`include "existing"`, ""); err != nil {
		t.Fatalf(`Failed to include "existing" rule "file": %s`, err)
	}
	if err = c.AddString(`rule int { condition: ext }`, ""); err != nil {
		t.Fatalf(`Failed to define rule referring to included rule: %s`, err)
	}

	c = setupCompiler(t)
	if err = c.AddString(`include "non-existing"`, ""); err != nil {
		t.Logf("Compiler returned error on attempt to include non-existing rule: %s", err)
	} else {
		t.Fatal(`Compiler did not return error on non-existing include rule`)
	}
}
