package yara

import (
	"bytes"
	"compress/bzip2"
	"fmt"
	"io/ioutil"
	"os"
	"os/exec"
	"reflect"
	"testing"
)

func makeRulesWithVars(t *testing.T, rule string, vars map[string]interface{}) *Rules {
	c, err := NewCompiler()
	if c == nil || err != nil {
		t.Fatal("NewCompiler():", err)
	}
	for identifier, value := range vars {
		c.DefineVariable(identifier, value)
	}
	if err = c.AddString(rule, ""); err != nil {
		t.Fatal("AddString():", err)
	}
	r, err := c.GetRules()
	if err != nil {
		t.Fatal("GetRules:", err)
	}
	return r
}

func makeRules(t *testing.T, rule string) *Rules {
	return makeRulesWithVars(t, rule, nil)
}

func TestSimpleMatch(t *testing.T) {
	r := makeRules(t,
		"rule test : tag1 { meta: author = \"Hilko Bengen\" strings: $a = \"abc\" fullword condition: $a }")
	m, err := r.ScanMem([]byte(" abc "), 0, 0)
	if err != nil {
		t.Errorf("ScanMem: %s", err)
	}
	t.Logf("Matches: %+v", m)
}

func TestSimpleFileMatch(t *testing.T) {
	r, _ := Compile(
		"rule test : tag1 { meta: author = \"Hilko Bengen\" strings: $a = \"abc\" fullword condition: $a }",
		nil)
	tf, _ := ioutil.TempFile("", "TestSimpleFileMatch")
	defer os.Remove(tf.Name())
	tf.Write([]byte(" abc "))
	tf.Close()
	m, err := r.ScanFile(tf.Name(), 0, 0)
	if err != nil {
		t.Errorf("ScanFile(%s): %s", tf.Name(), err)
	}
	t.Logf("Matches: %+v", m)
}

func TestSimpleFileDescriptorMatch(t *testing.T) {
	r, _ := Compile(
		"rule test : tag1 { meta: author = \"Hilko Bengen\" strings: $a = \"abc\" fullword condition: $a }",
		nil)
	tf, _ := ioutil.TempFile("", "TestSimpleFileMatch")
	defer os.Remove(tf.Name())
	tf.Write([]byte(" abc "))
	tf.Seek(0, os.SEEK_SET)
	m, err := r.ScanFileDescriptor(tf.Fd(), 0, 0)
	if err != nil {
		t.Errorf("ScanFile(%s): %s", tf.Name(), err)
	}
	t.Logf("Matches: %+v", m)
}

func TestEmpty(t *testing.T) {
	r, _ := Compile("rule test { condition: true }", nil)
	r.ScanMem([]byte{}, 0, 0)
	t.Log("Scan of null-byte slice did not crash. Yay.")
}

func assertTrueRules(t *testing.T, rules []string, data []byte) {
	for _, rule := range rules {
		r := makeRules(t, rule)
		if m, err := r.ScanMem(data, 0, 0); len(m) == 0 {
			t.Errorf("Rule < %s > did not match data < %v >", rule, data)
		} else if err != nil {
			t.Errorf("Error %s", err)
		}
	}
}

func assertFalseRules(t *testing.T, rules []string, data []byte) {
	for _, rule := range rules {
		r := makeRules(t, rule)
		if m, err := r.ScanMem(data, 0, 0); len(m) > 0 {
			t.Errorf("Rule < %s > matched data < %v >", rule, data)
		} else if err != nil {
			t.Errorf("Error %s", err)
		}
	}
}

func TestLoad(t *testing.T) {
	r, err := LoadRules("testrules.yac")
	if r == nil || err != nil {
		t.Fatalf("LoadRules: %s", err)
	}
}

func TestReader(t *testing.T) {
	rd, err := os.Open("testrules.yac")
	if err != nil {
		t.Fatalf("os.Open: %s", err)
	}
	r, err := ReadRules(rd)
	if err != nil {
		t.Fatalf("ReadRules: %+v", err)
	}
	m, err := r.ScanMem([]byte(" abc "), 0, 0)
	if err != nil {
		t.Errorf("ScanMem: %s", err)
	}
	t.Logf("Matches: %+v", m)
}

func TestWriter(t *testing.T) {
	rd, err := os.Open("testrules.yac")
	if err != nil {
		t.Fatalf("os.Open: %s", err)
	}
	compareBuf, _ := ioutil.ReadAll(rd)
	r, _ := Compile("rule test : tag1 { meta: author = \"Hilko Bengen\" strings: $a = \"abc\" fullword condition: $a }",
		nil)
	wr := bytes.Buffer{}
	if err := r.Write(&wr); err != nil {
		t.Fatal(err)
	}
	newBuf := wr.Bytes()
	if len(compareBuf) != len(newBuf) {
		t.Errorf("len(compareBuf) = %d, len(newBuf) = %d", len(compareBuf), len(newBuf))
	}
	if bytes.Compare(compareBuf, newBuf) != 0 {
		t.Error("buffers are not equal")
	}
}

// in Go 1.8 this code does not work in go-yara 1.0.2
// go 1.8/debian stretch panics
// go 1.8/darwin produces stack overflow
func TestWriterBuffer(t *testing.T) {
	rulesBuf := bytes.NewBuffer(nil)
	for i := 0; i < 10000; i++ {
		fmt.Fprintf(rulesBuf, "rule test%d : tag%d { meta: author = \"Hilko Bengen\" strings: $a = \"abc\" fullword condition: $a }", i, i)
	}
	r, _ := Compile(string(rulesBuf.Bytes()), nil)
	buf := new(bytes.Buffer)
	if err := r.Write(buf); err != nil {
		t.Fatalf("write to bytes.Buffer: %s", err)
	}
}

// compress/bzip2 seems to return short reads which apparently leads
// to YARA complaining about corrupt files. Tested with Go 1.4, 1.5.
func TestReaderBZIP2(t *testing.T) {
	rulesBuf := bytes.NewBuffer(nil)
	for i := 0; i < 10000; i++ {
		fmt.Fprintf(rulesBuf, "rule test%d : tag%d { meta: author = \"Hilko Bengen\" strings: $a = \"abc\" fullword condition: $a }", i, i)
	}
	r, err := Compile(string(rulesBuf.Bytes()), nil)
	if err != nil {
		t.Fatalf("compile text for bzip2 rule compression: %s", err)
	}
	cmd := exec.Command("bzip2", "-c")
	compressStream, _ := cmd.StdinPipe()
	buf := bytes.NewBuffer(nil)
	cmd.Stdout = buf
	if err := cmd.Start(); err != nil {
		t.Fatalf("start bzip2 process: %s", err)
	}
	if err := r.Write(compressStream); err != nil {
		t.Fatalf("pipe to bzip2 process: %s", err)
	}
	compressStream.Close()
	if err := cmd.Wait(); err != nil {
		t.Fatalf("wait for bzip2 process: %s", err)
	}
	if _, err := ReadRules(bzip2.NewReader(bytes.NewReader(buf.Bytes()))); err != nil {
		t.Fatalf("read using compress/bzip2: %s", err)
	}
}

// See https://github.com/hillu/go-yara/issues/5
func TestScanMemCgoPointer(t *testing.T) {
	r := makeRules(t,
		"rule test : tag1 { meta: author = \"Hilko Bengen\" strings: $a = \"abc\" fullword condition: $a }")
	buf := &bytes.Buffer{}
	buf.Write([]byte(" abc "))
	if err := func() (p interface{}) {
		defer func() { p = recover() }()
		r.ScanMem(buf.Bytes(), 0, 0)
		return nil
	}(); err != nil {
		t.Errorf("ScanMem panicked: %s", err)
	}
}

func TestRule(t *testing.T) {
	r := makeRules(t, `
		rule t1 : tag1 { meta: author = "Author One" strings: $a = "abc" fullword condition: $a }
        rule t2 : tag2 x y { meta: author = "Author Two" strings: $b = "def" condition: $b }
        rule t3 : tag3 x y z { meta: author = "Author Three" strings: $c = "ghi" condition: $c }
		rule t4 { strings: $d = "qwe" condition: $d }`)
	for _, r := range r.GetRules() {
		t.Logf("%s:%s %#v", r.Namespace(), r.Identifier(), r.Tags())
		switch r.Identifier() {
		case "t1":
			if !reflect.DeepEqual(r.Tags(), []string{"tag1"}) {
				t.Error("Got wrong tags for t1")
			}
			if !reflect.DeepEqual(r.Metas(), map[string]interface{}{"author": "Author One"}) {
				t.Error("Got wrong meta variables for t1")
			}
		case "t2":
			if !reflect.DeepEqual(r.Tags(), []string{"tag2", "x", "y"}) {
				t.Error("Got wrong tags for t2")
			}
			if !reflect.DeepEqual(r.Metas(), map[string]interface{}{"author": "Author Two"}) {
				t.Error("Got wrong meta variables for t2")
			}
		case "t3":
			if !reflect.DeepEqual(r.Tags(), []string{"tag3", "x", "y", "z"}) {
				t.Error("Got wrong tags for t3")
			}
			if !reflect.DeepEqual(r.Metas(), map[string]interface{}{"author": "Author Three"}) {
				t.Error("Got wrong meta variables for t3")
			}
		case "t4":
			if len(r.Tags()) != 0 {
				t.Error("Got tags for t4")
			}
			if !reflect.DeepEqual(r.Metas(), map[string]interface{}{}) {
				t.Error("Got wrong meta variables for t4")
			}
		default:
			t.Errorf("Found unexpected rule name: %#v", r.Identifier())
		}
	}
}

type callback struct {
	MatchingRules []*Rule
}

func (cb *callback) OnImportModule(module string) ([]byte, bool, error) {
	if module == "tests" {
		return []byte("test module data"), false, nil
	}
	return nil, false, nil
}

func (cb *callback) OnRuleMatching(r *Rule) (bool, error) {
	if cb.MatchingRules == nil {
		cb.MatchingRules = make([]*Rule, 0)
	}
	cb.MatchingRules = append(cb.MatchingRules, r)
	return false, nil
}

func TestImportModuleCallback(t *testing.T) {
	r := makeRules(t, `
		import "tests"
		rule t { condition: tests.module_data == "test module data" }`)
	buf := &bytes.Buffer{}
	buf.Write([]byte("not used"))

	cb := callback{}
	r.ScanMemWithCallback(buf.Bytes(), 0, 0, &cb)

	if len(cb.MatchingRules) != 1 {
		t.Errorf("Expecting one match, found %d", len(cb.MatchingRules))
	}
}
