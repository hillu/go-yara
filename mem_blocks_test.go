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

func TestIterator(t *testing.T) {
	rs := MustCompile(`
rule t1 { condition: true }
//rule a { strings: $a = "aaaa" condition: all of them }
//rule b { strings: $b = "bbbb" condition: all of them }
rule t2 {
strings: $a = "aaaa" $b = "bbbb"
condition: $a at 0 and $b at 32 
}

`, nil)
	var mrs MatchRules
	if err := rs.ScanMemBlocksWithCallback(&testIter{}, 0, 0, &mrs); err != nil {
		t.Errorf("simple iterator scan (no data): %v", err)
	} else {
		t.Logf("simple iterator scan (no data): %v", mrs)
	}
	mrs = nil
	if err := rs.ScanMemBlocksWithCallback(&testIter{
		data: []block{{0, nil}},
	}, 0, 0, &mrs); err != nil {
		t.Errorf("simple iterator scan (empty block): %v", err)
	} else {
		t.Logf("simple iterator scan (empty block): %+v", mrs)
	}
	mrs = nil
	if err := rs.ScanMemBlocksWithCallback(&testIter{
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
