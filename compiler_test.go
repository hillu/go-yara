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
