// Copyright © 2015-2017 Hilko Bengen <bengen@hilluzination.de>
// All rights reserved.
//
// Use of this source code is governed by the license that can be
// found in the LICENSE file.

// Package yara provides bindings to the YARA library.
package yara

/*
#include <yara.h>

int stdScanCallback(int, void*, void*);
*/
import "C"
import (
	"errors"
	"reflect"
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

func init() {
	_ = C.yr_initialize()
}

//export newMatch
func newMatch(ctxID unsafe.Pointer, namespace, identifier *C.char) {
	ctx := callbackData.Get(*(*uintptr)(ctxID)).(*scanContext)
	*ctx.matches = append(*ctx.matches, MatchRule{
		Rule:      C.GoString(identifier),
		Namespace: C.GoString(namespace),
		Tags:      []string{},
		Meta:      map[string]interface{}{},
		Strings:   []MatchString{},
	})
}

//export addMetaInt
func addMetaInt(ctxID unsafe.Pointer, identifier *C.char, value C.int) {
	ctx := callbackData.Get(*(*uintptr)(ctxID)).(*scanContext)
	i := len(*ctx.matches) - 1
	(*ctx.matches)[i].Meta[C.GoString(identifier)] = int32(value)
}

//export addMetaString
func addMetaString(ctxID unsafe.Pointer, identifier *C.char, value *C.char) {
	ctx := callbackData.Get(*(*uintptr)(ctxID)).(*scanContext)
	i := len(*ctx.matches) - 1
	(*ctx.matches)[i].Meta[C.GoString(identifier)] = C.GoString(value)
}

//export addMetaBool
func addMetaBool(ctxID unsafe.Pointer, identifier *C.char, value C.int) {
	ctx := callbackData.Get(*(*uintptr)(ctxID)).(*scanContext)
	i := len(*ctx.matches) - 1
	(*ctx.matches)[i].Meta[C.GoString(identifier)] = bool(value != 0)
}

//export addTag
func addTag(ctxID unsafe.Pointer, tag *C.char) {
	ctx := callbackData.Get(*(*uintptr)(ctxID)).(*scanContext)
	i := len(*ctx.matches) - 1
	(*ctx.matches)[i].Tags = append((*ctx.matches)[i].Tags, C.GoString(tag))
}

//export addString
func addString(ctxID unsafe.Pointer, identifier *C.char, offset C.uint64_t, data unsafe.Pointer, length C.int) {
	ms := MatchString{
		Name:   C.GoString(identifier),
		Offset: uint64(offset),
		Data:   make([]byte, int(length)),
	}

	var tmpSlice []byte
	hdr := (*reflect.SliceHeader)(unsafe.Pointer(&tmpSlice))
	hdr.Data = uintptr(data)
	hdr.Len = int(length)
	copy(ms.Data, tmpSlice)

	ctx := callbackData.Get(*(*uintptr)(ctxID)).(*scanContext)
	i := len(*ctx.matches) - 1
	(*ctx.matches)[i].Strings = append((*ctx.matches)[i].Strings, ms)
}

//export getModuleData
func getModuleData(ctxID unsafe.Pointer, moduleName *C.char) (unsafe.Pointer, C.size_t) {
	ctx := callbackData.Get(*(*uintptr)(ctxID)).(*scanContext)
	data, ok := ctx.options.ModulesData[C.GoString(moduleName)]
	if ok {
		dataLen := C.size_t(len(data))
		b := C.malloc(dataLen)
		C.memcpy(b, unsafe.Pointer(&data[0]), dataLen)
		ctx.freeOnFinalize(b)
		return b, dataLen
	}
	return nil, 0
}

// scanContext holds data required during the scan of a single memory buffer
// file or process. The context is passed to the scan callback.
type scanContext struct {
	cptrs   []unsafe.Pointer
	options *ScanOptions
	matches *[]MatchRule
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

// ScanOptions contains the options used during the scanning with any of the
// Scan*WithOptions functions.
type ScanOptions struct {
	Flags       ScanFlags
	Timeout     time.Duration
	ModulesData map[string][]byte
}

// ScanMemWithOptions scans an in-memory buffer using the provided options.
func (r *Rules) ScanMemWithOptions(buf []byte, options ScanOptions) (matches []MatchRule, err error) {
	var ptr *C.uint8_t
	if len(buf) > 0 {
		ptr = (*C.uint8_t)(unsafe.Pointer(&(buf[0])))
	}
	ctx := scanContext{
		matches: &matches,
		options: &options,
	}
	ctxID := callbackData.Put(&ctx)
	defer callbackData.Delete(ctxID)
	err = newError(C.yr_rules_scan_mem(
		r.cptr,
		ptr,
		C.size_t(len(buf)),
		C.int(options.Flags)|C.SCAN_FLAGS_NO_TRYCATCH,
		C.YR_CALLBACK_FUNC(C.stdScanCallback),
		unsafe.Pointer(&ctxID),
		C.int(options.Timeout/time.Second)))
	keepAlive(ctxID)
	keepAlive(r)
	return
}

// ScanMem scans an in-memory buffer using the ruleset.
func (r *Rules) ScanMem(buf []byte, flags ScanFlags, timeout time.Duration) (matches []MatchRule, err error) {
	return r.ScanMemWithOptions(buf, ScanOptions{Flags: flags, Timeout: timeout})
}

// ScanFileWithOptions scans a file using the provided options.
func (r *Rules) ScanFileWithOptions(filename string, options ScanOptions) (matches []MatchRule, err error) {
	cfilename := C.CString(filename)
	defer C.free(unsafe.Pointer(cfilename))
	ctx := scanContext{
		matches: &matches,
		options: &options,
	}
	ctxID := callbackData.Put(&ctx)
	defer callbackData.Delete(ctxID)
	err = newError(C.yr_rules_scan_file(
		r.cptr,
		cfilename,
		C.int(options.Flags)|C.SCAN_FLAGS_NO_TRYCATCH,
		C.YR_CALLBACK_FUNC(C.stdScanCallback),
		unsafe.Pointer(&ctxID),
		C.int(options.Timeout/time.Second)))
	keepAlive(ctxID)
	keepAlive(r)
	return
}

// ScanFile scans a file using the ruleset.
func (r *Rules) ScanFile(filename string, flags ScanFlags, timeout time.Duration) (matches []MatchRule, err error) {
	return r.ScanFileWithOptions(filename, ScanOptions{Flags: flags, Timeout: timeout})
}

// ScanProcWithOptions scans a live process the provided options.
func (r *Rules) ScanProcWithOptions(pid int, options ScanOptions) (matches []MatchRule, err error) {
	ctx := scanContext{
		matches: &matches,
		options: &options,
	}
	ctxID := callbackData.Put(&ctx)
	defer callbackData.Delete(ctxID)
	err = newError(C.yr_rules_scan_proc(
		r.cptr,
		C.int(pid),
		C.int(options.Flags)|C.SCAN_FLAGS_NO_TRYCATCH,
		C.YR_CALLBACK_FUNC(C.stdScanCallback),
		unsafe.Pointer(&ctxID),
		C.int(options.Timeout/time.Second)))
	keepAlive(ctxID)
	keepAlive(r)
	return
}

// ScanProc scans a live process using the ruleset.
func (r *Rules) ScanProc(pid int, flags ScanFlags, timeout time.Duration) (matches []MatchRule, err error) {
	return r.ScanProcWithOptions(pid, ScanOptions{Flags: flags, Timeout: timeout})
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
func (r *Rules) DefineVariable(name string, value interface{}) (err error) {
	cname := C.CString(name)
	defer C.free(unsafe.Pointer(cname))
	switch value.(type) {
	case bool:
		var v int
		if value.(bool) {
			v = 1
		}
		err = newError(C.yr_rules_define_boolean_variable(
			r.cptr, cname, C.int(v)))
	case int, int8, int16, int32, int64, uint, uint8, uint16, uint32, uint64:
		value := toint64(value)
		err = newError(C.yr_rules_define_integer_variable(
			r.cptr, cname, C.int64_t(value)))
	case float64:
		err = newError(C.yr_rules_define_float_variable(
			r.cptr, cname, C.double(value.(float64))))
	case string:
		cvalue := C.CString(value.(string))
		defer C.free(unsafe.Pointer(cvalue))
		err = newError(C.yr_rules_define_string_variable(
			r.cptr, cname, cvalue))
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
