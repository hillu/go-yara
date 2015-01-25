package yara

import (
	"testing"
)

func TestCompile(t *testing.T) {
	c, err := NewCompiler()
	if c == nil || err != nil {
		t.Errorf("NewCompiler(): %s", err)
	}
	if err = c.AddString("rule test : tag1 { meta: author = \"Hilko Bengen\" strings: $a = \"abc\" fullword condition: $a }", ""); err != nil {
		t.Errorf("AddString: %s", err)
	}
	r, err := c.GetRules()
	if r == nil || err != nil {
		t.Errorf("GetRules: %s", err)
	}
	m, err := r.ScanMem([]byte(" abc "), 0, 0)
	if err != nil {
		t.Errorf("ScanMem: %s", err)
	}
	t.Logf("Matches: %+v", m)
}
