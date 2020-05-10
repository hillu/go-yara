// Copyright © 2015-2019 Hilko Bengen <bengen@hilluzination.de>
// All rights reserved.
//
// Use of this source code is governed by the license that can be
// found in the LICENSE file.

// Package yara provides bindings to the YARA library.
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

int scanCallbackFunc(YR_SCAN_CONTEXT*, int, void*, void*);
*/
import "C"
import (
	"errors"
	"io"
	"runtime"
	"time"
	"unsafe"
)

// Rules contains a compiled YARA ruleset.
//
// Since this type contains a C pointer to a YR_RULES structure that
// may be automatically freed, it should not be copied.
type Rules struct{ cptr *C.YR_RULES }

// A MatchRule represents a rule successfully matched against a block
// of data.
type MatchRule struct {
	Rule      string
	Namespace string
	Tags      []string
	Meta      map[string]interface{}
	Strings   []MatchString
}

// A MatchString represents a string declared and matched in a rule.
type MatchString struct {
	Name   string
	Base   uint64
	Offset uint64
	Data   []byte
}

// ScanFlags are used to tweak the behavior of Scan* functions.
type ScanFlags int

const (
	// ScanFlagsFastMode avoids multiple matches of the same string
	// when not necessary.
	ScanFlagsFastMode = C.SCAN_FLAGS_FAST_MODE
	// ScanFlagsProcessMemory causes the scanned data to be
	// interpreted like live, in-prcess memory rather than an on-disk
	// file.
	ScanFlagsProcessMemory = C.SCAN_FLAGS_PROCESS_MEMORY
)

// ScanMem scans an in-memory buffer using the ruleset, returning
// matches via a list of MatchRule objects.
func (r *Rules) ScanMem(buf []byte, flags ScanFlags, timeout time.Duration) (matches []MatchRule, err error) {
	cb := MatchRules{}
	err = r.ScanMemWithCallback(buf, flags, timeout, &cb)
	matches = cb
	return
}

// ScanMemWithCallback scans an in-memory buffer using the ruleset.
// For every event emitted by libyara, the appropriate method on the
// ScanCallback object is called.
func (r *Rules) ScanMemWithCallback(buf []byte, flags ScanFlags, timeout time.Duration, cb ScanCallback) (err error) {
	var ptr *C.uint8_t
	if len(buf) > 0 {
		ptr = (*C.uint8_t)(unsafe.Pointer(&(buf[0])))
	}
	cbc := makeScanCallbackContainer(cb)
	id := callbackData.Put(cbc)
	defer callbackData.Delete(id)
	err = newError(C.yr_rules_scan_mem(
		r.cptr,
		ptr,
		C.size_t(len(buf)),
		C.int(flags),
		C.YR_CALLBACK_FUNC(C.scanCallbackFunc),
		id,
		C.int(timeout/time.Second)))
	runtime.KeepAlive(r)
	return
}

// ScanFile scans a file using the ruleset, returning matches via a
// list of MatchRule objects.
func (r *Rules) ScanFile(filename string, flags ScanFlags, timeout time.Duration) (matches []MatchRule, err error) {
	cb := MatchRules{}
	err = r.ScanFileWithCallback(filename, flags, timeout, &cb)
	matches = cb
	return
}

// ScanFileWithCallback scans a file using the ruleset. For every
// event emitted by libyara, the appropriate method on the
// ScanCallback object is called.
func (r *Rules) ScanFileWithCallback(filename string, flags ScanFlags, timeout time.Duration, cb ScanCallback) (err error) {
	cfilename := C.CString(filename)
	defer C.free(unsafe.Pointer(cfilename))
	id := callbackData.Put(makeScanCallbackContainer(cb))
	defer callbackData.Delete(id)
	err = newError(C.yr_rules_scan_file(
		r.cptr,
		cfilename,
		C.int(flags),
		C.YR_CALLBACK_FUNC(C.scanCallbackFunc),
		id,
		C.int(timeout/time.Second)))
	runtime.KeepAlive(r)
	return
}

// ScanFileDescriptor scans a file using the ruleset, returning
// matches via a list of MatchRule objects.
func (r *Rules) ScanFileDescriptor(fd uintptr, flags ScanFlags, timeout time.Duration) (matches []MatchRule, err error) {
	cb := MatchRules{}
	err = r.ScanFileDescriptorWithCallback(fd, flags, timeout, &cb)
	matches = cb
	return
}

// ScanFileDescriptorWithCallback scans a file using the ruleset. For every event
// emitted by libyara, the appropriate method on the ScanCallback
// object is called.
func (r *Rules) ScanFileDescriptorWithCallback(fd uintptr, flags ScanFlags, timeout time.Duration, cb ScanCallback) (err error) {
	id := callbackData.Put(makeScanCallbackContainer(cb))
	defer callbackData.Delete(id)
	err = newError(C._yr_rules_scan_fd(
		r.cptr,
		C.int(fd),
		C.int(flags),
		C.YR_CALLBACK_FUNC(C.scanCallbackFunc),
		id,
		C.int(timeout/time.Second)))
	runtime.KeepAlive(r)
	return
}

// ScanProc scans a live process using the ruleset, returning matches
// via a list of MatchRule objects.
func (r *Rules) ScanProc(pid int, flags ScanFlags, timeout time.Duration) (matches []MatchRule, err error) {
	cb := MatchRules{}
	err = r.ScanProcWithCallback(pid, flags, timeout, &cb)
	matches = cb
	return
}

// ScanProcWithCallback scans a live process using the ruleset.  For
// every event emitted by libyara, the appropriate method on the
// ScanCallback object is called.
func (r *Rules) ScanProcWithCallback(pid int, flags ScanFlags, timeout time.Duration, cb ScanCallback) (err error) {
	id := callbackData.Put(makeScanCallbackContainer(cb))
	defer callbackData.Delete(id)
	err = newError(C.yr_rules_scan_proc(
		r.cptr,
		C.int(pid),
		C.int(flags),
		C.YR_CALLBACK_FUNC(C.scanCallbackFunc),
		id,
		C.int(timeout/time.Second)))
	runtime.KeepAlive(r)
	return
}

// Save writes a compiled ruleset to filename.
func (r *Rules) Save(filename string) (err error) {
	cfilename := C.CString(filename)
	defer C.free(unsafe.Pointer(cfilename))
	err = newError(C.yr_rules_save(r.cptr, cfilename))
	runtime.KeepAlive(r)
	return
}

// LoadRules retrieves a compiled ruleset from filename.
func LoadRules(filename string) (*Rules, error) {
	cfilename := C.CString(filename)
	defer C.free(unsafe.Pointer(cfilename))
	r := &Rules{}
	if err := newError(C.yr_rules_load(cfilename, &(r.cptr))); err != nil {
		return nil, err
	}
	runtime.SetFinalizer(r, (*Rules).Destroy)
	return r, nil
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
	runtime.KeepAlive(r)
	return
}

// ReadRules retrieves a compiled ruleset from an io.Reader.
func ReadRules(rd io.Reader) (*Rules, error) {
	id := callbackData.Put(rd)
	defer callbackData.Delete(id)

	stream := C.YR_STREAM{
		read: C.YR_STREAM_READ_FUNC(C.streamRead),
		// The complaint from go vet about possible misuse of
		// unsafe.Pointer is wrong, see above.
		user_data: id,
	}
	r := &Rules{}
	if err := newError(C.yr_rules_load_stream(&stream, &(r.cptr))); err != nil {
		return nil, err
	}
	runtime.SetFinalizer(r, (*Rules).Destroy)
	return r, nil
}

// Destroy destroys the YARA data structure representing a ruleset.
//
// It should not be necessary to call this method directly.
func (r *Rules) Destroy() {
	if r.cptr != nil {
		C.yr_rules_destroy(r.cptr)
		r.cptr = nil
	}
	runtime.SetFinalizer(r, nil)
}

// DefineVariable defines a named variable for use by the compiler.
// Boolean, int64, float64, and string types are supported.
func (r *Rules) DefineVariable(identifier string, value interface{}) (err error) {
	cid := C.CString(identifier)
	defer C.free(unsafe.Pointer(cid))
	switch value.(type) {
	case bool:
		var v int
		if value.(bool) {
			v = 1
		}
		err = newError(C.yr_rules_define_boolean_variable(
			r.cptr, cid, C.int(v)))
	case int, int8, int16, int32, int64, uint, uint8, uint16, uint32, uint64:
		value := toint64(value)
		err = newError(C.yr_rules_define_integer_variable(
			r.cptr, cid, C.int64_t(value)))
	case float64:
		err = newError(C.yr_rules_define_float_variable(
			r.cptr, cid, C.double(value.(float64))))
	case string:
		cvalue := C.CString(value.(string))
		defer C.free(unsafe.Pointer(cvalue))
		err = newError(C.yr_rules_define_string_variable(
			r.cptr, cid, cvalue))
	default:
		err = errors.New("wrong value type passed to DefineVariable; bool, int64, float64, string are accepted")
	}
	runtime.KeepAlive(r)
	return
}

// GetRules returns a slice of rule objects that are part of the
// ruleset.
func (r *Rules) GetRules() (rv []Rule) {
	// Equivalent to:
	// #define yr_rules_foreach(rules, rule) \
	//     for (rule = rules->rules_list_head; !RULE_IS_NULL(rule); rule++)
	// #define RULE_IS_NULL(x) \
	//     (((x)->g_flags) & RULE_GFLAGS_NULL)
	for p := r.cptr.rules_list_head; p.flags&C.RULE_FLAGS_NULL != 0; p = (*C.YR_RULE)(unsafe.Pointer(uintptr(unsafe.Pointer(p)) + unsafe.Sizeof(*p))) {
		rv = append(rv, Rule{(*C.YR_RULE)(p)})
	}
	return
}
