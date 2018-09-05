package yara

import (
	"io/ioutil"
	"log"
	"os"
	"testing"
)

var compiledTestRulesPath string

func TestMain(m *testing.M) {
	r, err := Compile(`rule test : tag1 { meta: author = "Hilko Bengen" strings: $a = "abc" fullword condition: $a }`, nil)
	if err != nil {
		log.Fatalf("Compile: %v", err)
	}

	f, err := ioutil.TempFile("", "testrules.yac")
	if err != nil {
		log.Fatalf("ioutil.TempFile: %v", err)
	}
	compiledTestRulesPath = f.Name()

	if err := r.Save(compiledTestRulesPath); err != nil {
		os.Remove(compiledTestRulesPath)
		log.Fatalf("Save(%q): %v", compiledTestRulesPath, err)
	}

	rc := m.Run()
	os.Remove(compiledTestRulesPath)
	os.Exit(rc)
}
