// Copyright © 2015-2019 Hilko Bengen <bengen@hilluzination.de>
// All rights reserved.
//
// Use of this source code is governed by the license that can be
// found in the LICENSE file.

package yara

/*
#include <stdio.h>
#include <unistd.h>
#include <yara.h>

int scanCallbackFunc(int, void*, void*);
*/
import "C"
import "runtime"

// Scanner contains a YARA scanner
type Scanner struct {
	*scanner
}

type scanner struct {
	cptr *C.YR_SCANNER
}

// NewScanner creates a YARA scanner.
func NewScanner() (*Scanner, error) {
	var yrScanner *C.YR_SCANNER
	s := &Scanner{scanner: &scanner{cptr: yrScanner}}
	return s, nil
}

func (s *scanner) finalize() {
	C.yr_scanner_destroy(s.cptr)
	runtime.SetFinalizer(s, nil)
}
