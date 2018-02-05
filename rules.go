// Copyright © 2015-2017 Hilko Bengen <bengen@hilluzination.de>
// All rights reserved.
//
// Use of this source code is governed by the license that can be
// found in the LICENSE file.

// Package yara provides bindings to the YARA library.
package yara

/*
#include <yara.h>

int scanCallbackFunc(int, void*, void*);
*/
import "C"
import (
	"errors"
	"runtime"
	"time"
	"unsafe"
)

// Rules contains a compiled YARA ruleset.
type Rules struct {
	*rules
}

type rules struct {
	cptr *C.YR_RULES
}

var dummy *[]MatchRule

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
	Offset uint64
	Data   []byte
}

// scanContext holds data required during the scan of a single memory buffer
// file or process.
type scanContext struct {
	cptrs    []unsafe.Pointer
	callback Callback
}

func newScanContext() *scanContext {
	ctx := &scanContext{}
	runtime.SetFinalizer(ctx, (*scanContext).finalize)
	return ctx
}

func (ctx *scanContext) finalize() {
	for _, cptr := range ctx.cptrs {
		C.free(cptr)
	}
	runtime.SetFinalizer(ctx, nil)
}

// freeOnFinalize receives a C pointer to a buffer allocated with C.malloc and
// frees it with C.free when the context is finalized.
func (ctx *scanContext) freeOnFinalize(cptr unsafe.Pointer) {
	ctx.cptrs = append(ctx.cptrs, cptr)
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

// ScanMemWithCallback scans an in-memory buffer using the ruleset,
// calling methods on the ScanCallback object for the various events
// generated from libyara.
func (r *Rules) ScanMemWithCallback(buf []byte, flags ScanFlags, timeout time.Duration, cb Callback) (err error) {
	var ptr *C.uint8_t
	if len(buf) > 0 {
		ptr = (*C.uint8_t)(unsafe.Pointer(&(buf[0])))
	}
	ctxid := callbackData.Put(&scanContext{callback: cb})
	defer callbackData.Delete(ctxid)
	err = newError(C.yr_rules_scan_mem(
		r.cptr,
		ptr,
		C.size_t(len(buf)),
		C.int(flags)|C.SCAN_FLAGS_NO_TRYCATCH,
		C.YR_CALLBACK_FUNC(C.scanCallbackFunc),
		unsafe.Pointer(&ctxid),
		C.int(timeout/time.Second)))
	keepAlive(ctxid)
	keepAlive(r)
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

// ScanFileWithCallback scans a file using the ruleset, calling
// methods on the ScanCallback object for the various events generated
// from libyara.
func (r *Rules) ScanFileWithCallback(filename string, flags ScanFlags, timeout time.Duration, cb Callback) (err error) {
	cfilename := C.CString(filename)
	defer C.free(unsafe.Pointer(cfilename))
	ctxid := callbackData.Put(&scanContext{callback: cb})
	defer callbackData.Delete(ctxid)
	err = newError(C.yr_rules_scan_file(
		r.cptr,
		cfilename,
		C.int(flags)|C.SCAN_FLAGS_NO_TRYCATCH,
		C.YR_CALLBACK_FUNC(C.scanCallbackFunc),
		unsafe.Pointer(&ctxid),
		C.int(timeout/time.Second)))
	keepAlive(ctxid)
	keepAlive(r)
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

// ScanProcWithCallback scans a live process using the ruleset,
// calling methods on the ScanCallback object for the various events
// generated from libyara.
func (r *Rules) ScanProcWithCallback(pid int, flags ScanFlags, timeout time.Duration, cb Callback) (err error) {
	ctxid := callbackData.Put(&scanContext{callback: cb})
	defer callbackData.Delete(ctxid)
	err = newError(C.yr_rules_scan_proc(
		r.cptr,
		C.int(pid),
		C.int(flags)|C.SCAN_FLAGS_NO_TRYCATCH,
		C.YR_CALLBACK_FUNC(C.scanCallbackFunc),
		unsafe.Pointer(&ctxid),
		C.int(timeout/time.Second)))
	keepAlive(ctxid)
	keepAlive(r)
	return
}

// Save writes a compiled ruleset to filename.
func (r *Rules) Save(filename string) (err error) {
	cfilename := C.CString(filename)
	defer C.free(unsafe.Pointer(cfilename))
	err = newError(C.yr_rules_save(r.cptr, cfilename))
	keepAlive(r)
	return
}

// LoadRules retrieves a compiled ruleset from filename.
func LoadRules(filename string) (*Rules, error) {
	r := &Rules{rules: &rules{}}
	cfilename := C.CString(filename)
	defer C.free(unsafe.Pointer(cfilename))
	if err := newError(C.yr_rules_load(cfilename,
		&(r.rules.cptr))); err != nil {
		return nil, err
	}
	runtime.SetFinalizer(r.rules, (*rules).finalize)
	return r, nil
}

func (r *rules) finalize() {
	C.yr_rules_destroy(r.cptr)
	runtime.SetFinalizer(r, nil)
}

// Destroy destroys the YARA data structure representing a ruleset.
// Since a Finalizer for the underlying YR_RULES structure is
// automatically set up on creation, it should not be necessary to
// explicitly call this method.
func (r *Rules) Destroy() {
	if r.rules != nil {
		r.rules.finalize()
		r.rules = nil
	}
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
	keepAlive(r)
	return
}

// GetRules returns a slice of rule objects that are part of the
// ruleset
func (r *Rules) GetRules() (rv []Rule) {
	for p := unsafe.Pointer(r.cptr.rules_list_head); (*C.YR_RULE)(p).g_flags&C.RULE_GFLAGS_NULL == 0; p = unsafe.Pointer(uintptr(p) + unsafe.Sizeof(*r.cptr.rules_list_head)) {
		rv = append(rv, Rule{(*C.YR_RULE)(p)})
	}
	return
}

func init() {
	_ = C.yr_initialize()
}
