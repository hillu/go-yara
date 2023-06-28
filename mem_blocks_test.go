// Copyright © 2015-2020 Hilko Bengen <bengen@hilluzination.de>
// All rights reserved.
//
// Use of this source code is governed by the license that can be
// found in the LICENSE file.

package yara

import (
	"testing"
)

type block struct {
	base uint64
	data []byte
}

type testIter struct {
	data    []block
	current int
}

func (it *testIter) First() *MemoryBlock {
	it.current = 0
	return it.Next()
}

func (it *testIter) Next() *MemoryBlock {
	if it.current >= len(it.data) {
		return nil
	}
	data := it.data[it.current].data
	base := it.data[it.current].base
	it.current += 1
	return &MemoryBlock{
		Base:      base,
		Size:      uint64(len(data)),
		FetchData: func(buf []byte) { copy(buf, data) },
	}
}

type testIterWithFilesize struct {
	testIter
	filesize uint64
}

func (it *testIterWithFilesize) Filesize() uint64 {
	return it.filesize
}

func TestIterator(t *testing.T) {
	rs := MustCompile(`
rule t1 { condition: true }
//rule a { strings: $a = "aaaa" condition: all of them }
//rule b { strings: $b = "bbbb" condition: all of them }
rule t2 {
strings: $a = "aaaa" $b = "bbbb"
condition: $a at 0 and $b at 32 
}
rule t3 {
condition: filesize < 20 
}
rule t4 {
condition: filesize >= 20
}
`, nil)
	var mrs MatchRules
	if err := rs.ScanMemBlocks(&testIter{}, 0, 0, &mrs); err != nil {
		t.Errorf("simple iterator scan (no data): %v", err)
	} else {
		t.Logf("simple iterator scan (no data): %v", mrs)
	}
	mrs = nil
	if err := rs.ScanMemBlocks(&testIter{
		data: []block{{0, nil}},
	}, 0, 0, &mrs); err != nil {
		t.Errorf("simple iterator scan (empty block): %v", err)
	} else {
		t.Logf("simple iterator scan (empty block): %+v", mrs)
	}
	mrs = nil
	if err := rs.ScanMemBlocks(&testIterWithFilesize{
		testIter: testIter{
			data: []block{
				{0, []byte("aaaaaaaaaaaaaaaa")},
				{32, []byte("bbbbbbbbbbbbbbbb")},
			},
		},
		filesize: 64,
	}, 0, 0, &mrs); err != nil {
		t.Errorf("simple iterator scan (aaa..bbbb): %v", err)
	} else {
		t.Logf("simple iterator scan (aaa..bbb): %+v", mrs)
	}
}

type testPanicIter struct {
	data    []block
	current int
}

func (it *testPanicIter) First() *MemoryBlock {
	it.current = 0
	return it.Next()
}

func (it *testPanicIter) Next() *MemoryBlock {
	if it.current >= len(it.data) {
		return nil
	}
	data := it.data[it.current].data
	base := it.data[it.current].base
	it.current += 1
	return &MemoryBlock{
		Base: base,
		Size: uint64(len(data)),
		FetchData: func(buf []byte) {
			// Simulate a caught panic during data fetch
			func() {
				defer func() {
					recover() // Recover from panic
				}()
				// Cause a panic by writing to a nil pointer
				var nilPointer *int
				*nilPointer = 0
			}()
			copy(buf, data)
		},
	}
}

func TestIteratorWithPanic(t *testing.T) {
	rs := MustCompile(`
import "math"
rule t1 { condition: math.entropy(0, 10) < 0.5 }
`, nil)
	var mrs MatchRules
	if err := rs.ScanMemBlocks(&testPanicIter{
		data: []block{
			{0, []byte("aaaaaaaaaaaaaaaa")},
			{32, []byte("bbbbbbbbbbbbbbbb")},
		},
	}, 0, 0, &mrs); err != nil {
		t.Errorf("simple iterator scan (aaa..bbbb): %v", err)
	} else {
		t.Logf("simple iterator scan (aaa..bbb): %+v", mrs)
	}
}
