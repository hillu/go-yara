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

// Scanner contains a YARA scanner
type Scanner struct {
	*scanner
	rules *Rules
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

// ScanMem scans an in-memory buffer using the scanner, returning
// matches via a list of MatchRule objects.
func (s *Scanner) ScanMem(buf []byte, flags ScanFlags, timeout time.Duration) (matches []MatchRule, err error) {
	cb := MatchRules{}
	err = s.ScanMemWithCallback(buf, flags, timeout, &cb)
	matches = cb
	return
}

// ScanMemWithCallback scans an in-memory buffer using the scanner.
// For every event emitted by libyara, the appropriate method on the
// ScanCallback object is called.
func (s *Scanner) ScanMemWithCallback(buf []byte, flags ScanFlags, timeout time.Duration, cb ScanCallback) (err error) {
	var ptr *C.uint8_t
	if len(buf) > 0 {
		ptr = (*C.uint8_t)(unsafe.Pointer(&(buf[0])))
	}
	cbc := &scanCallbackContainer{ScanCallback: cb}
	defer cbc.destroy()
	id := callbackData.Put(cbc)
	defer callbackData.Delete(id)

	C.yr_scanner_set_flags(s.cptr, C.int(flags))
	C.yr_scanner_set_timeout(s.cptr, C.int(timeout/time.Second))
	C.yr_scanner_set_callback(s.cptr, C.YR_CALLBACK_FUNC(C.scanCallbackFunc), id)

	err = newError(C.yr_scanner_scan_mem(
		s.cptr,
		ptr,
		C.size_t(len(buf))))
	keepAlive(s)
	return
}

// ScanFile scans a file using the scanner, returning
// matches via a list of MatchRule objects.
func (s *Scanner) ScanFile(filename string, flags ScanFlags, timeout time.Duration) (matches []MatchRule, err error) {
	cb := MatchRules{}
	err = s.ScanFileWithCallback(filename, flags, timeout, &cb)
	matches = cb
	return
}

// ScanFileWithCallback scans a file using the scanner.
// For every event emitted by libyara, the appropriate method on the
// ScanCallback object is called.
func (s *Scanner) ScanFileWithCallback(filename string, flags ScanFlags, timeout time.Duration, cb ScanCallback) (err error) {
	cfilename := C.CString(filename)
	defer C.free(unsafe.Pointer(cfilename))
	cbc := &scanCallbackContainer{ScanCallback: cb}
	defer cbc.destroy()
	id := callbackData.Put(cbc)
	defer callbackData.Delete(id)

	C.yr_scanner_set_flags(s.cptr, C.int(flags))
	C.yr_scanner_set_timeout(s.cptr, C.int(timeout/time.Second))
	C.yr_scanner_set_callback(s.cptr, C.YR_CALLBACK_FUNC(C.scanCallbackFunc), id)

	err = newError(C.yr_scanner_scan_file(
		s.cptr,
		cfilename,
	))
	keepAlive(s)
	return
}

// ScanFileDescriptor scans a file using the scanner, returning
// matches via a list of MatchRule objects.
func (s *Scanner) ScanFileDescriptor(fd uintptr, flags ScanFlags, timeout time.Duration) (matches []MatchRule, err error) {
	cb := MatchRules{}
	err = s.ScanFileDescriptorWithCallback(fd, flags, timeout, &cb)
	matches = cb
	return
}

// ScanFileDescriptorWithCallback scans a file using the scanner. For every event
// emitted by libyara, the appropriate method on the ScanCallback
// object is called.
func (s *Scanner) ScanFileDescriptorWithCallback(fd uintptr, flags ScanFlags, timeout time.Duration, cb ScanCallback) (err error) {
	cbc := &scanCallbackContainer{ScanCallback: cb}
	defer cbc.destroy()
	id := callbackData.Put(cbc)
	defer callbackData.Delete(id)

	C.yr_scanner_set_flags(s.cptr, C.int(flags))
	C.yr_scanner_set_timeout(s.cptr, C.int(timeout/time.Second))
	C.yr_scanner_set_callback(s.cptr, C.YR_CALLBACK_FUNC(C.scanCallbackFunc), id)

	err = newError(C.yr_scanner_scan_fd(
		s.cptr,
		C.int(fd),
	))
	keepAlive(s)
	return
}

// ScanProc scans a live process using the scanner, returning matches
// via a list of MatchRule objects.
func (s *Scanner) ScanProc(pid int, flags ScanFlags, timeout time.Duration) (matches []MatchRule, err error) {
	cb := MatchRules{}
	err = s.ScanProcWithCallback(pid, flags, timeout, &cb)
	matches = cb
	return
}

// ScanProcWithCallback scans a live process using the scanner.
// For every event emitted by libyara, the appropriate method on the
// ScanCallback object is called.
func (s *Scanner) ScanProcWithCallback(pid int, flags ScanFlags, timeout time.Duration, cb ScanCallback) (err error) {
	cbc := &scanCallbackContainer{ScanCallback: cb}
	defer cbc.destroy()
	id := callbackData.Put(cbc)
	defer callbackData.Delete(id)

	C.yr_scanner_set_flags(s.cptr, C.int(flags))
	C.yr_scanner_set_timeout(s.cptr, C.int(timeout/time.Second))
	C.yr_scanner_set_callback(s.cptr, C.YR_CALLBACK_FUNC(C.scanCallbackFunc), id)

	err = newError(C.yr_scanner_scan_proc(
		s.cptr,
		C.int(pid),
	))
	keepAlive(s)
	return
}
