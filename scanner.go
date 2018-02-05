// Copyright © 2015-2017 Hilko Bengen <bengen@hilluzination.de>
// All rights reserved.
//
// Use of this source code is governed by the license that can be
// found in the LICENSE file.

// This file contains functionality that require libyara 3.8 or higher

//+build !yara3.3,!yara3.4,!yara3.5,!yara3.6,!yara.37

package yara

/*
#include <yara.h>

int scanCallbackFunc(int, void*, void*);
*/
import "C"
import "C"
import (
	"errors"
	"runtime"
	"time"
	"unsafe"
)

// A Scanner allows scanning files, in-memory data and processes using the
// compiled rules built with a Compiler.
type Scanner struct {
	*scanner

	// Rules that will be used with scanner. The Scanner struct must hold a pointer
	// to the Rules even if not used, this prevents the Rules structure from being
	// garbage-collected before the Scanner structure, which in turn would cause
	// the underlying YR_RULES to be destructed before YR_SCANNER.
	rules *Rules
}

type scanner struct {
	cptr *C.YR_SCANNER
}

// NewScanner creates a scanner for scanning files, in-memory data or processes
// with the provided Rules.
func NewScanner(r *Rules) (*Scanner, error) {
	var yrScanner *C.YR_SCANNER
	if err := newError(C.yr_scanner_create(r.cptr, &yrScanner)); err != nil {
		return nil, err
	}
	s := &Scanner{scanner: &scanner{cptr: yrScanner}, rules: r}
	runtime.SetFinalizer(s.scanner, (*scanner).finalize)
	return s, nil
}

func (s *scanner) finalize() {
	C.yr_scanner_destroy(s.cptr)
	runtime.SetFinalizer(s, nil)
}

// Destroy destroys the YARA data structure representing a scanner.
// Since a Finalizer for the underlying YR_SCANNER structure is
// automatically set up on creation, it should not be necessary to
// explicitly call this method.
func (s *Scanner) Destroy() {
	if s.scanner != nil {
		s.scanner.finalize()
		s.scanner = nil
	}
}

// ScanMem scans an in-memory buffer using the scanner, returning
// matches via a list of MatchRule objects.
func (s *Scanner) ScanMem(buf []byte, flags ScanFlags, timeout time.Duration) (matches []MatchRule, err error) {
	cb := MatchRules{}
	err = s.ScanMemWithCallback(buf, flags, timeout, &cb)
	matches = cb
	return
}

// ScanMemWithCallback scans an in-memory buffer using the scanner,
// calling methods on the ScanCallback object for the various events
// generated from libyara.
func (s *Scanner) ScanMemWithCallback(buf []byte, flags ScanFlags, timeout time.Duration, cb Callback) (err error) {
	var ptr *C.uint8_t
	if len(buf) > 0 {
		ptr = (*C.uint8_t)(unsafe.Pointer(&(buf[0])))
	}
	ctxid := callbackData.Put(&scanContext{callback: cb})
	defer callbackData.Delete(ctxid)
	C.yr_scanner_set_callback(
		s.cptr, C.YR_CALLBACK_FUNC(C.scanCallbackFunc), unsafe.Pointer(&ctxid))
	C.yr_scanner_set_timeout(s.cptr, C.int(timeout.Seconds()))
	C.yr_scanner_set_flags(s.cptr, C.int(flags)|C.SCAN_FLAGS_NO_TRYCATCH)
	err = newError(C.yr_scanner_scan_mem(s.cptr, ptr, C.size_t(len(buf))))
	keepAlive(ctxid)
	keepAlive(s)
	return
}

// DefineVariable defines a named variable for use by the scanner.
// Boolean, int64, float64, and string types are supported.
func (s *Scanner) DefineVariable(identifier string, value interface{}) (err error) {
	cid := C.CString(identifier)
	defer C.free(unsafe.Pointer(cid))
	switch value.(type) {
	case bool:
		var v int
		if value.(bool) {
			v = 1
		}
		err = newError(C.yr_scanner_define_boolean_variable(
			s.cptr, cid, C.int(v)))
	case int, int8, int16, int32, int64, uint, uint8, uint16, uint32, uint64:
		value := toint64(value)
		err = newError(C.yr_scanner_define_integer_variable(
			s.cptr, cid, C.int64_t(value)))
	case float64:
		err = newError(C.yr_scanner_define_float_variable(
			s.cptr, cid, C.double(value.(float64))))
	case string:
		cvalue := C.CString(value.(string))
		defer C.free(unsafe.Pointer(cvalue))
		err = newError(C.yr_scanner_define_string_variable(
			s.cptr, cid, cvalue))
	default:
		err = errors.New("wrong value type passed to DefineVariable; bool, int64, float64, string are accepted")
	}
	keepAlive(s)
	return
}
