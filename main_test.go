package yara

import (
	"os"
	"testing"
)

func TestMain(m *testing.M) {
	if r, err := Compile(`rule test : tag1 { meta: author = "Hilko Bengen" strings: $a = "abc" fullword condition: $a }`, nil); err != nil {
		os.Exit(1)
	} else if err = r.Save("testrules.yac"); err != nil {
		os.Exit(1)
	}
	rc := m.Run()
	os.Remove("testrules.yac")
	os.Exit(rc)
}

func TestMaxMatchData(t *testing.T) {
	oldMax := GetMaxMatchData()
	SetMaxMatchData(0)
	r, err := Compile("rule t {strings: $a = \"abc\" condition: $a}", nil)
	if err != nil {
		t.Errorf("Compile: %s", err)
	}
	m, err := r.ScanMem([]byte("abc"), 0, 0)
	if err != nil {
		t.Errorf("ScanMem: %s", err)
	}
	if m[0].Strings[0].Data != nil {
		t.Errorf("expecting nil")
	}
	maxMatchData := 1
	SetMaxMatchData(maxMatchData)
	m, err = r.ScanMem([]byte("abc"), 0, 0)
	if err != nil {
		t.Errorf("ScanMem: %s", err)
	}
	if len(m[0].Strings[0].Data) != maxMatchData {
		t.Errorf("expecting %d, got %d", maxMatchData, len(m[0].Strings[0].Data))
	}
	SetMaxMatchData(oldMax)
}
