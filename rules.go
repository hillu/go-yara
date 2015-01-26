// Copyright © 2015 Hilko Bengen <bengen@hilluzination.de>. All rights reserved.
// Use of this source code is governed by the license that can be
// found in the LICENSE file.

// Package yara provides bindings to the YARA library.
package yara

/*
#cgo LDFLAGS: -lyara
#include <yara.h>

int callback(int message, void *message_data, void *user_data);
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
	r *C.YR_RULES
}

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
func newMatch(matches *[]MatchRule, namespace, identifier *C.char) {
	*matches = append(*matches, MatchRule{
		Rule:      C.GoString(identifier),
		Namespace: C.GoString(namespace),
		Tags:      []string{},
		Meta:      map[string]interface{}{},
		Strings:   []MatchString{},
	})
}

//export addMetaInt
func addMetaInt(matches *[]MatchRule, identifier *C.char, value C.int) {
	(*matches)[len(*matches)-1].Meta[C.GoString(identifier)] = int32(value)
}

//export addMetaString
func addMetaString(matches *[]MatchRule, identifier *C.char, value *C.char) {
	(*matches)[len(*matches)-1].Meta[C.GoString(identifier)] = C.GoString(value)
}

//export addMetaBool
func addMetaBool(matches *[]MatchRule, identifier *C.char, value C.int) {
	(*matches)[len(*matches)-1].Meta[C.GoString(identifier)] = bool(value != 0)
}

//export addTag
func addTag(matches *[]MatchRule, tag *C.char) {
	(*matches)[len(*matches)-1].Tags = append((*matches)[len(*matches)-1].Tags, C.GoString(tag))
}

//export addString
func addString(matches *[]MatchRule, identifier *C.char, offset C.uint64_t, data unsafe.Pointer, length C.int) {
	(*matches)[len(*matches)-1].Strings = append(
		(*matches)[len(*matches)-1].Strings,
		MatchString{
			Name:   C.GoString(identifier),
			Offset: uint64(offset),
			Data:   C.GoBytes(data, length),
		})
}

// ScanFlags are used to tweak the behavior of Scan* functions.
type ScanFlags int

const (
	// ScanFlagsFastMode avoids multiple matches of the same string when not necessary.
	ScanFlagsFastMode = C.SCAN_FLAGS_FAST_MODE
	// ScanFlagsProcessMemory causes the scanned data to be
	// interpreted like live, in-prcess memory rather than an on-disk
	// file.
	ScanFlagsProcessMemory = C.SCAN_FLAGS_PROCESS_MEMORY
)

// ScanMem scans an in-memory buffer using the ruleset.
func (r *Rules) ScanMem(buf []byte, flags ScanFlags, timeout time.Duration) (matches []MatchRule, err error) {
	err = newError(C.yr_rules_scan_mem(
		r.r,
		(*C.uint8_t)(unsafe.Pointer(&(buf[0]))),
		C.size_t(len(buf)),
		C.int(flags),
		C.YR_CALLBACK_FUNC(C.callback),
		unsafe.Pointer(&matches),
		C.int(timeout/time.Second)))
	return
}

// ScanFile scans a file using the ruleset.
func (r *Rules) ScanFile(filename string, flags ScanFlags, timeout time.Duration) (matches []MatchRule, err error) {
	err = newError(C.yr_rules_scan_file(
		r.r,
		C.CString(filename),
		C.int(flags),
		C.YR_CALLBACK_FUNC(C.callback),
		unsafe.Pointer(&matches),
		C.int(timeout/time.Second)))
	return
}

// ScanProc scans a live process using the ruleset.
func (r *Rules) ScanProc(pid int, flags int, timeout time.Duration) (matches []MatchRule, err error) {
	err = newError(C.yr_rules_scan_proc(
		r.r,
		C.int(pid),
		C.int(flags),
		C.YR_CALLBACK_FUNC(C.callback),
		unsafe.Pointer(&matches),
		C.int(timeout/time.Second)))
	return
}

// Save writes a compiled ruleset to filename.
func (r *Rules) Save(filename string) (err error) {
	err = newError(C.yr_rules_save(r.r, C.CString(filename)))
	return
}

// LoadRules retrieves compiled ruleset from filename.
func LoadRules(filename string) (rules *Rules, err error) {
	var r *C.YR_RULES
	err = newError(C.yr_rules_load(C.CString(filename), &r))
	if err == nil {
		rules = &Rules{r: r}
		runtime.SetFinalizer(rules, func(r *Rules) {
			C.yr_rules_destroy(r.r)
			r.r = nil
		})
	}
	return
}

// DefineVariable defines a named variable for use by the compiler.
// Boolean, int64, and string types are supported.
func (r *Rules) DefineVariable(name string, value interface{}) (err error) {
	switch value.(type) {
	case bool:
		var v int
		if value.(bool) {
			v = 1
		}
		err = newError(C.yr_rules_define_boolean_variable(
			r.r, C.CString(name), C.int(v)))
	case int64:
		err = newError(C.yr_rules_define_integer_variable(
			r.r, C.CString(name), C.int64_t(value.(int64))))
	case string:
		err = newError(C.yr_rules_define_string_variable(
			r.r, C.CString(name), C.CString(value.(string))))
	default:
		err = errors.New("wrong value type passed to DefineVariable; bool, int64, string are accepted.")
	}
	return
}
