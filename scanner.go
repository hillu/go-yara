// Copyright © 2015-2019 Hilko Bengen <bengen@hilluzination.de>
// All rights reserved.
//
// Use of this source code is governed by the license that can be
// found in the LICENSE file.

// +build !yara3.3,!yara3.4,!yara3.5,!yara3.6,!yara3.7

package yara

/*
#include <yara.h>

#ifdef _WIN32
#include <stdint.h>
int _yr_scanner_scan_fd(
    YR_SCANNER* scanner,
    int fd)
{
  return yr_scanner_scan_fd(scanner, (YR_FILE_DESCRIPTOR)(intptr_t)fd);
}
#else
#define _yr_scanner_scan_fd yr_scanner_scan_fd
#endif

int scanCallbackFunc(int, void*, void*);
*/
import "C"
import (
	"errors"
	"runtime"
	"time"
	"unsafe"
)

// Scanner contains a YARA scanner (YR_SCANNER). The main difference
// to Rules (YR_RULES) is that it is possible to set variables in a
// thread-safe manner (cf.
// https://github.com/VirusTotal/yara/issues/350)
type Scanner struct {
	*scanner
	// The Scanner struct has to hold a pointer to the rules
	// it wraps, as otherwise it may be be garbage collected.
	rules *Rules
	// current callback object, set by SetCallback
	cb ScanCallback
}

type scanner struct {
	cptr *C.YR_SCANNER
}

// NewScanner creates a YARA scanner.
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
// explicitly all this method.
func (s *Scanner) Destroy() {
	if s.scanner != nil {
		s.scanner.finalize()
		s.scanner = nil
	}
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
	case int, int8, int16, int32, int64, uint, uint8, uint32, uint64:
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

// SetFlags sets flags for the scanner.
func (s *Scanner) SetFlags(flags ScanFlags) *Scanner {
	C.yr_scanner_set_flags(s.cptr, C.int(flags))
	return s
}

// SetTimeout sets a timeout for the scanner.
func (s *Scanner) SetTimeout(timeout time.Duration) *Scanner {
	C.yr_scanner_set_timeout(s.cptr, C.int(timeout/time.Second))
	return s
}

// SetCallback sets a callback object for the scanner. For every event
// emitted by libyara during subsequent scan, the appropriate method
// on the ScanCallback object is called.
//
// For the common case where only a list of matched rules is relevant,
// setting a callback object is not necessary.
func (s *Scanner) SetCallback(cb ScanCallback) *Scanner {
	s.cb = cb
	return s
}

// putCallbackData stores the appropriate callback object (pre-set
// object or ad-hoc return-value-based ) into callbackData, returning
// a pointer. The object must be removed from callbackData by the
// calling ScanXxxx function.
func (s *Scanner) putCallbackData(matches *[]MatchRule) unsafe.Pointer {
	var c scanCallbackContainer
	if s.cb != nil {
		c.ScanCallback = s.cb
	} else {
		c.ScanCallback = (*MatchRules)(matches)
	}
	ptr := callbackData.Put(&c)
	C.yr_scanner_set_callback(s.cptr, C.YR_CALLBACK_FUNC(C.scanCallbackFunc), ptr)
	return ptr
}

// ScanMem scans an in-memory buffer using the scanner.
//
// If a callback object has been set for the scanner using
// SetCAllback, matches is nil and the callback object is used instead
// to collect scan events.
func (s *Scanner) ScanMem(buf []byte) (matches []MatchRule, err error) {
	var ptr *C.uint8_t
	if len(buf) > 0 {
		ptr = (*C.uint8_t)(unsafe.Pointer(&(buf[0])))
	}

	cbPtr := s.putCallbackData(&matches)
	defer callbackData.Delete(cbPtr)

	err = newError(C.yr_scanner_scan_mem(
		s.cptr,
		ptr,
		C.size_t(len(buf))))
	keepAlive(s)
	return
}

// ScanFile scans a file using the scanner.
//
// If a callback object has been set for the scanner using
// SetCAllback, matches is nil and the callback object is used instead
// to collect scan events.
func (s *Scanner) ScanFile(filename string) (matches []MatchRule, err error) {
	cfilename := C.CString(filename)
	defer C.free(unsafe.Pointer(cfilename))

	cbPtr := s.putCallbackData(&matches)
	defer callbackData.Delete(cbPtr)

	err = newError(C.yr_scanner_scan_file(
		s.cptr,
		cfilename,
	))
	keepAlive(s)
	return
}

// ScanFileDescriptor scans a file using the scanner.
//
// If a callback object has been set for the scanner using
// SetCAllback, matches is nil and the callback object is used instead
// to collect scan events.
func (s *Scanner) ScanFileDescriptor(fd uintptr) (matches []MatchRule, err error) {
	cbPtr := s.putCallbackData(&matches)
	defer callbackData.Delete(cbPtr)

	err = newError(C._yr_scanner_scan_fd(
		s.cptr,
		C.int(fd),
	))
	keepAlive(s)
	return
}

// ScanProc scans a live process using the scanner.
//
// If a callback object has been set for the scanner using
// SetCAllback, matches is nil and the callback object is used instead
// to collect scan events.
func (s *Scanner) ScanProc(pid int) (matches []MatchRule, err error) {
	cbPtr := s.putCallbackData(&matches)
	defer callbackData.Delete(cbPtr)

	err = newError(C.yr_scanner_scan_proc(
		s.cptr,
		C.int(pid),
	))
	keepAlive(s)
	return
}
