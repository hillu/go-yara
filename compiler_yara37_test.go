//+build !yara3.3,!yara3.4,!yara3.5,!yara3.6

package yara

import (
	"testing"
)

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
