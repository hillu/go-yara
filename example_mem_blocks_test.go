// Copyright © 2015-2020 Hilko Bengen <bengen@hilluzination.de>
// All rights reserved.
//
// Use of this source code is governed by the license that can be
// found in the LICENSE file.

package yara_test

import (
	"bytes"
	"fmt"
	"io"

	"github.com/hillu/go-yara/v4"
)

type Iterator struct {
	blocksize int
	rs        io.ReadSeeker
	offset    int64
	length    int
}

func (s *Iterator) read(buf []byte) {
	s.rs.Seek(s.offset, io.SeekStart)
	s.rs.Read(buf)
}

func (s *Iterator) First() *yara.MemoryBlock {
	s.offset = 0
	return &yara.MemoryBlock{
		Base:      uint64(s.offset),
		Size:      uint64(s.length),
		FetchData: s.read,
	}
}

func (s *Iterator) Next() *yara.MemoryBlock {
	s.offset += int64(s.length)
	end, _ := s.rs.Seek(0, io.SeekEnd)
	s.length = int(end - s.offset)
	if s.length <= 0 {
		return nil
	}
	if s.length > s.blocksize {
		s.length = s.blocksize
	}
	return &yara.MemoryBlock{
		Base:      uint64(s.offset),
		Size:      uint64(s.length),
		FetchData: s.read,
	}
}

func (s *Iterator) Filesize() uint64 {
	end, _ := s.rs.Seek(0, io.SeekEnd)
	return uint64(end)
}

func Example_ScanMemBlocks() {
	// Set up a []byte-backed io.ReadSeeker
	buf := make([]byte, 65536)
	buf[0] = 0x7f
	buf[60000] = 0x7f
	copy(buf[10000:], []byte("abc"))
	copy(buf[20000:], []byte("def"))
	copy(buf[1022:], []byte("ghij"))

	it := &Iterator{blocksize: 1024, rs: bytes.NewReader(buf)}

	rs := yara.MustCompile(`
rule A {
	strings:
		$abc = "abc"
		$def = "def"
	condition:
		uint8(0) == 0x7f and uint8(60000) == 0x7f and $abc at 10000 and $def at 20000
}

// we do not expect rule B to be matched since the relevant value
// crosses the block boundary at 1024. (However, it does match when
// setting a blocksize that does not cause this value to be split.)
rule B {
    strings:
        $ghij = "ghij"
    condition:
        $ghij at 1022 or uint32be(1022) == 0x6768696a
}
	`, nil)

	var mrs yara.MatchRules
	err := rs.ScanMemBlocks(it, 0, 0, &mrs)
	if err != nil {
		fmt.Printf("error: %+v\n", err)
		return
	}
	for _, rule := range mrs {
		fmt.Printf("match: %s\n strings:\n", rule.Rule)
		for _, ms := range rule.Strings {
			fmt.Printf(" - %s at %d\n", ms.Name, ms.Base+ms.Offset)
		}
	}
	// Output:
	// match: A
	//  strings:
	//  - $abc at 10000
	//  - $def at 20000
}
