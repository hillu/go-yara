//+build !yara3.3,!yara3.4,!yara3.5,!yara3.6

package yara

import (
	"bytes"
	"testing"
)

func TestModuleData(t *testing.T) {
	buf := &bytes.Buffer{}
	buf.Write([]byte("not used"))
	opts := ScanOptions{
		ModulesData: map[string][]byte{
			"tests": []byte("test module data"),
		},
	}
	r := makeRules(t, `
		import "tests"
		rule t { condition: tests.module_data == "test module data" }`)
	if m, err := r.ScanMemWithOptions(buf.Bytes(), opts); err != nil {
		t.Errorf("Error %s", err)
	} else if len(m) != 1 {
		t.Error("tests.module_data != \"test module data\"")
	}
}
