// Copyright © 2015-2017 Hilko Bengen <bengen@hilluzination.de>
// All rights reserved.
//
// Use of this source code is governed by the license that can be
// found in the LICENSE file.

// This file contains functionality that require libyara 3.4 or higher

// +build !yara3.3

package yara

/*
#include <yara.h>

#ifdef _WIN32
#include <stdint.h>
// Helper function that is merely used to cast fd from int to HANDLE.
// CGO treats HANDLE (void*) to an unsafe.Pointer. This confuses the
// go1.4 garbage collector, leading to runtime errors such as:
//
// runtime: garbage collector found invalid heap pointer *(0x5b80ff14+0x4)=0xa0 s=nil
int _yr_rules_scan_fd(
    YR_RULES* rules,
    int fd,
    int flags,
    YR_CALLBACK_FUNC callback,
    void* user_data,
    int timeout)
{
  return yr_rules_scan_fd(rules, (YR_FILE_DESCRIPTOR)(intptr_t)fd, flags, callback, user_data, timeout);
}
#else
#define _yr_rules_scan_fd yr_rules_scan_fd
#endif

size_t streamRead(void* ptr, size_t size, size_t nmemb, void* user_data);
size_t streamWrite(void* ptr, size_t size, size_t nmemb, void* user_data);

int scanCallbackFunc(int, void*, void*);
*/
import "C"
import (
	"io"
	"runtime"
	"time"
)

// ScanFileDescriptor scans a file using the ruleset, returning
// matches via a list of MatchRule objects.
func (r *Rules) ScanFileDescriptor(fd uintptr, flags ScanFlags, timeout time.Duration) (matches []MatchRule, err error) {
	cb := MatchRules{}
	err = r.ScanFileDescriptorWithCallback(fd, flags, timeout, &cb)
	matches = cb
	return
}

// ScanFileDescriptor scans a file using the ruleset. For every event
// emitted by libyara, the appropriate method on the ScanCallback
// object is called.
func (r *Rules) ScanFileDescriptorWithCallback(fd uintptr, flags ScanFlags, timeout time.Duration, cb ScanCallback) (err error) {
	cbc := &scanCallbackContainer{ScanCallback: cb}
	defer cbc.destroy()
	id := callbackData.Put(cbc)
	defer callbackData.Delete(id)
	err = newError(C._yr_rules_scan_fd(
		r.cptr,
		C.int(fd),
		C.int(flags),
		C.YR_CALLBACK_FUNC(C.scanCallbackFunc),
		id,
		C.int(timeout/time.Second)))
	keepAlive(r)
	return
}

// Write writes a compiled ruleset to an io.Writer.
func (r *Rules) Write(wr io.Writer) (err error) {
	id := callbackData.Put(wr)
	defer callbackData.Delete(id)

	stream := C.YR_STREAM{
		write: C.YR_STREAM_WRITE_FUNC(C.streamWrite),
		// The complaint from go vet about possible misuse of
		// unsafe.Pointer is wrong: user_data will be interpreted as
		// an uintptr on the other side of the callback
		user_data: id,
	}
	err = newError(C.yr_rules_save_stream(r.cptr, &stream))
	keepAlive(r)
	return
}

// ReadRules retrieves a compiled ruleset from an io.Reader
func ReadRules(rd io.Reader) (*Rules, error) {
	r := &Rules{rules: &rules{}}
	id := callbackData.Put(rd)
	defer callbackData.Delete(id)

	stream := C.YR_STREAM{
		read: C.YR_STREAM_READ_FUNC(C.streamRead),
		// The complaint from go vet about possible misuse of
		// unsafe.Pointer is wrong, see above.
		user_data: id,
	}
	if err := newError(C.yr_rules_load_stream(&stream,
		&(r.rules.cptr))); err != nil {
		return nil, err
	}
	runtime.SetFinalizer(r.rules, (*rules).finalize)
	return r, nil
}
