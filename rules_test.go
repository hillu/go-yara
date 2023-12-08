// Copyright © 2015-2020 Hilko Bengen <bengen@hilluzination.de>
// All rights reserved.
//
// Use of this source code is governed by the license that can be
// found in the LICENSE file.

package yara

import (
	"bytes"
	"compress/bzip2"
	"fmt"
	"io/ioutil"
	"os"
	"os/exec"
	"reflect"
	"runtime"
	"testing"
)

func makeRules(t *testing.T, rule string) *Rules {
	c, err := NewCompiler()
	if c == nil || err != nil {
		t.Fatal("NewCompiler():", err)
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

func TestSimpleMatch(t *testing.T) {
	r := makeRules(t,
		"rule test : tag1 { meta: author = \"Hilko Bengen\" strings: $a = \"abc\" fullword condition: $a }")
	var m MatchRules
	err := r.ScanMem([]byte(" abc "), 0, 0, &m)
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
	var m MatchRules
	err := r.ScanFile(tf.Name(), 0, 0, &m)
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
	var m MatchRules
	err := r.ScanFileDescriptor(tf.Fd(), 0, 0, &m)
	if err != nil {
		t.Errorf("ScanFileDescriptor(%s): %s", tf.Name(), err)
	}
	t.Logf("Matches: %+v", m)
}

func TestEmpty(t *testing.T) {
	r, _ := Compile("rule test { condition: true }", nil)
	r.ScanMem([]byte{}, 0, 0, nil)
	t.Log("Scan of null-byte slice did not crash. Yay.")
}

func assertTrueRules(t *testing.T, rules []string, data []byte) {
	for _, rule := range rules {
		r := makeRules(t, rule)
		var m MatchRules
		if err := r.ScanMem(data, 0, 0, &m); len(m) == 0 {
			t.Errorf("Rule < %s > did not match data < %v >", rule, data)
		} else if err != nil {
			t.Errorf("Error %s", err)
		}
	}
}

func assertFalseRules(t *testing.T, rules []string, data []byte) {
	for _, rule := range rules {
		r := makeRules(t, rule)
		var m MatchRules
		if err := r.ScanMem(data, 0, 0, &m); len(m) > 0 {
			t.Errorf("Rule < %s > matched data < %v >", rule, data)
		} else if err != nil {
			t.Errorf("Error %s", err)
		}
	}
}

func TestLoad(t *testing.T) {
	r, err := LoadRules(compiledTestRulesPath)
	if r == nil || err != nil {
		t.Fatalf("LoadRules: %s", err)
	}
}

func TestReader(t *testing.T) {
	rd, err := os.Open(compiledTestRulesPath)
	if err != nil {
		t.Fatalf("os.Open: %s", err)
	}
	r, err := ReadRules(rd)
	if err != nil {
		t.Fatalf("ReadRules: %+v", err)
	}
	var m MatchRules
	if err := r.ScanMem([]byte(" abc "), 0, 0, &m); err != nil {
		t.Errorf("ScanMem: %s", err)
	}
	t.Logf("Matches: %+v", m)
}

func TestWriter(t *testing.T) {
	rd, err := os.Open(compiledTestRulesPath)
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
		r.ScanMem(buf.Bytes(), 0, 0, nil)
		return nil
	}(); err != nil {
		t.Errorf("ScanMem panicked: %s", err)
	}
}

type rule struct {
	identifier      string
	tags            []string
	metas           []Meta
	private, global bool
}

func TestRule(t *testing.T) {
	rs := makeRules(t, `
		rule t1 : tag1 { meta: author = "Author One" strings: $a = "abc" fullword condition: $a }
        rule t2 : tag2 x y { meta: author = "Author Two" strings: $b = "def" condition: $b }
        rule t3 : tag3 x y z { meta: author = "Author Three" strings: $c = "ghi" condition: $c }
		rule t4 { strings: $d = "qwe" condition: $d }
		private rule t5 { condition: false }
		global rule t6 { condition: false }`)
	expected := []rule{
		rule{"t1", []string{"tag1"}, []Meta{{"author", "Author One"}}, false, false},
		rule{"t2", []string{"tag2", "x", "y"}, []Meta{{"author", "Author Two"}}, false, false},
		rule{"t3", []string{"tag3", "x", "y", "z"}, []Meta{{"author", "Author Three"}}, false, false},
		rule{"t4", nil, nil, false, false},
		rule{"t5", nil, nil, true, false},
		rule{"t6", nil, nil, false, true},
	}
	var got []rule
	for _, r := range rs.GetRules() {
		got = append(got, rule{identifier: r.Identifier(), metas: r.Metas(), tags: r.Tags(), private: r.IsPrivate(), global: r.IsGlobal()})
	}
	if !reflect.DeepEqual(got, expected) {
		t.Errorf("Got %+v , expected %+v", got, expected)
	}
}

type testCallback struct {
	t              *testing.T
	finished       bool
	modules        map[string]struct{}
	matched        map[string]struct{}
	notMatched     map[string]struct{}
	logged         []string
	tooManyMatches []string
}

func newTestCallback(t *testing.T) *testCallback {
	return &testCallback{
		t, false,
		make(map[string]struct{}),
		make(map[string]struct{}),
		make(map[string]struct{}),
		nil,
		nil,
	}
}

func (c *testCallback) RuleMatching(_ *ScanContext, r *Rule) (bool, error) {
	c.t.Logf("RuleMatching callback called: rule=%s", r.Identifier())
	c.matched[r.Identifier()] = struct{}{}
	return false, nil
}
func (c *testCallback) RuleNotMatching(_ *ScanContext, r *Rule) (bool, error) {
	c.t.Logf("RuleNotMatching callback called: rule=%s", r.Identifier())
	c.notMatched[r.Identifier()] = struct{}{}
	return false, nil
}
func (c *testCallback) ScanFinished(*ScanContext) (bool, error) {
	c.t.Log("ScanFinished callback called")
	c.finished = true
	return false, nil
}
func (c *testCallback) ImportModule(_ *ScanContext, s string) ([]byte, bool, error) {
	c.t.Logf("ImportModule callback called: module=%s", s)
	c.modules[s] = struct{}{}
	if s == "tests" {
		return []byte("callback-data-for-tests-module"), false, nil
	}
	return nil, false, nil
}
func (c *testCallback) ModuleImported(*ScanContext, *Object) (bool, error) {
	c.t.Log("ModuleImported callback called")
	return false, nil
}
func (c *testCallback) ConsoleLog(_ *ScanContext, s string) {
	c.logged = append(c.logged, s)
}
func (c *testCallback) TooManyMatches(_ *ScanContext, r *Rule, s string) (bool, error) {
	c.tooManyMatches = append(c.logged, fmt.Sprintf("%s:%s", r.Identifier(), s))
	return false, nil
}

func TestImportDataCallback(t *testing.T) {
	cb := newTestCallback(t)
	r := makeRules(t, `
		import "tests"
		import "pe"
		rule t1 { condition: true }
		rule t2 { condition: false }
		rule t3 {
			condition: tests.module_data == "callback-data-for-tests-module"
		}`)
	if err := r.ScanMem([]byte(""), 0, 0, cb); err != nil {
		t.Error(err)
	}
	for _, module := range []string{"tests", "pe"} {
		if _, ok := cb.modules[module]; !ok {
			t.Errorf("ImportModule was not called for %s", module)
		}
	}
	for _, rule := range []string{"t1", "t3"} {
		if _, ok := cb.matched["t1"]; !ok {
			t.Errorf("RuleMatching was not called for %s", rule)
		}
	}
	if _, ok := cb.notMatched["t2"]; !ok {
		t.Errorf("RuleNotMatching was not called for %s", "t2")
	}
	if !cb.finished {
		t.Errorf("ScanFinished was not called")
	}
	runtime.GC()
}

func TestConsoleCallback(t *testing.T) {
	cb := newTestCallback(t)
	r := makeRules(t, `
        import "console"
		rule t { condition: console.log("hello world") }
        `)

	if err := r.ScanMem([]byte(""), 0, 0, cb); err != nil {
		t.Error(err)
	}
	if len(cb.logged) < 1 || cb.logged[0] != "hello world" {
		t.Errorf("console log does not containi expected hello world string: %v", cb.logged)
	}
}

func TestTooManyMatches(t *testing.T) {
	cb := newTestCallback(t)
	r := makeRules(t, `
		rule t { strings: $s1 = "\x00" condition: #s1 == 10000000 }
        `)

	if err := r.ScanMem(make([]byte, 10000000), 0, 0, cb); err != nil {
		t.Error(err)
	}
	if len(cb.tooManyMatches) != 1 || cb.tooManyMatches[0] != "t:$s1" {
		t.Errorf("too many matches does not contain regularly matching string: %v", cb.tooManyMatches)
	}
}

func TestXorKey(t *testing.T) {
	var m MatchRules
	r := makeRules(t, `
		rule t { strings: $s1 = "\x00\x01\x02\x03" xor condition: all of them }
        `)

	if err := r.ScanMem([]byte{0x10, 0x11, 0x12, 0x13}, 0, 0, &m); err != nil {
		t.Error(err)
	}
	if len(m) != 1 {
		t.Fatalf("expected 1 match, got %d", len(m))
	}
	if len(m[0].Strings) != 1 {
		t.Fatalf("expected 1 string, got %d", len(m[0].Strings))
	}
	if m[0].Strings[0].XorKey != 0x10 {
		t.Fatalf("expected xor key 0x10, got 0x%x", m[0].Strings[0].XorKey)
	}
}
