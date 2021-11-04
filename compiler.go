// Copyright © 2015-2020 Hilko Bengen <bengen@hilluzination.de>
// All rights reserved.
//
// Use of this source code is governed by the license that can be
// found in the LICENSE file.

package yara

/*
#ifdef _WIN32
#define fdopen _fdopen
#define dup _dup
#endif
#include <stdio.h>
#include <unistd.h>

#include <yara.h>

void compilerCallback(int, char*, int, YR_RULE*, char*, void*);
char* includeCallback(char*, char*, char*, void*);
void freeCallback(char*, void*);
*/
import "C"
import (
	"errors"
	"os"
	"reflect"
	"runtime"
	"unsafe"
)

//export compilerCallback
func compilerCallback(errorLevel C.int, filename *C.char, linenumber C.int, rule *C.YR_RULE, message *C.char, userData unsafe.Pointer) {
	c := callbackData.Get(userData).(*Compiler)
	msg := CompilerMessage{
		Filename: C.GoString(filename),
		Line:     int(linenumber),
		Text:     C.GoString(message),
	}
	if rule != nil {
		// Rule object implicitly relies on the compiler object and is destroyed when the compiler is destroyed.
		// Save a reference to the compiler to prevent that from happening.
		msg.Rule = &Rule{cptr: rule, owner: c}
	}
	switch errorLevel {
	case C.YARA_ERROR_LEVEL_ERROR:
		c.Errors = append(c.Errors, msg)
	case C.YARA_ERROR_LEVEL_WARNING:
		c.Warnings = append(c.Warnings, msg)
	}
}

// A Compiler encapsulates the YARA compiler that transforms rules
// into YARA's internal, binary form which in turn is used for
// scanning files or memory blocks.
//
// Since this type contains a C pointer to a YR_COMPILER structure
// that may be automatically freed, it should not be copied.
type Compiler struct {
	Errors   []CompilerMessage
	Warnings []CompilerMessage
	// used for include callback
	callbackData unsafe.Pointer
	cptr         *C.YR_COMPILER
}

// A CompilerMessage contains an error or warning message produced
// while compiling sets of rules using AddString or AddFile.
type CompilerMessage struct {
	Filename string
	Line     int
	Text     string
	Rule     *Rule
}

// NewCompiler creates a YARA compiler.
func NewCompiler() (*Compiler, error) {
	var yrCompiler *C.YR_COMPILER
	if err := newError(C.yr_compiler_create(&yrCompiler)); err != nil {
		return nil, err
	}
	c := &Compiler{cptr: yrCompiler}
	runtime.SetFinalizer(c, (*Compiler).Destroy)
	return c, nil
}

// Destroy destroys the YARA data structure representing a compiler.
//
// It should not be necessary to call this method directly.
func (c *Compiler) Destroy() {
	if c.cptr != nil {
		C.yr_compiler_destroy(c.cptr)
		c.cptr = nil
	}
	runtime.SetFinalizer(c, nil)
}

func (c *Compiler) setCallbackData(ptr unsafe.Pointer) {
	if c.callbackData != nil {
		callbackData.Delete(c.callbackData)
	}
	c.callbackData = ptr
}

// AddFile compiles rules from a file. Rules are added to the
// specified namespace.
//
// If this function returns an error, the Compiler object will become
// unusable.
func (c *Compiler) AddFile(file *os.File, namespace string) (err error) {
	if c.cptr.errors != 0 {
		return errors.New("Compiler cannot be used after parse error")
	}
	var ns *C.char
	if namespace != "" {
		ns = C.CString(namespace)
		defer C.free(unsafe.Pointer(ns))
	}
	filename := C.CString(file.Name())
	defer C.free(unsafe.Pointer(filename))
	id := callbackData.Put(c)
	defer callbackData.Delete(id)
	C.yr_compiler_set_callback(c.cptr, C.YR_COMPILER_CALLBACK_FUNC(C.compilerCallback), id)
	numErrors := int(C.yr_compiler_add_fd(c.cptr, (C.YR_FILE_DESCRIPTOR)(file.Fd()), ns, filename))
	if numErrors > 0 {
		var buf [1024]C.char
		msg := C.GoString(C.yr_compiler_get_error_message(
			c.cptr, (*C.char)(unsafe.Pointer(&buf[0])), 1024))
		err = errors.New(msg)
	}
	runtime.KeepAlive(c)
	return
}

// AddString compiles rules from a string. Rules are added to the
// specified namespace.
//
// If this function returns an error, the Compiler object will become
// unusable.
func (c *Compiler) AddString(rules string, namespace string) (err error) {
	if c.cptr.errors != 0 {
		return errors.New("Compiler cannot be used after parse error")
	}
	var ns *C.char
	if namespace != "" {
		ns = C.CString(namespace)
		defer C.free(unsafe.Pointer(ns))
	}
	crules := C.CString(rules)
	defer C.free(unsafe.Pointer(crules))
	id := callbackData.Put(c)
	defer callbackData.Delete(id)
	C.yr_compiler_set_callback(c.cptr, C.YR_COMPILER_CALLBACK_FUNC(C.compilerCallback), id)
	numErrors := int(C.yr_compiler_add_string(c.cptr, crules, ns))
	if numErrors > 0 {
		var buf [1024]C.char
		msg := C.GoString(C.yr_compiler_get_error_message(
			c.cptr, (*C.char)(unsafe.Pointer(&buf[0])), 1024))
		err = errors.New(msg)
	}
	runtime.KeepAlive(c)
	return
}

// DefineVariable defines a named variable for use by the compiler.
// Boolean, int64, float64, and string types are supported.
func (c *Compiler) DefineVariable(identifier string, value interface{}) (err error) {
	cid := C.CString(identifier)
	defer C.free(unsafe.Pointer(cid))
	switch value.(type) {
	case bool:
		var v int
		if value.(bool) {
			v = 1
		}
		err = newError(C.yr_compiler_define_boolean_variable(
			c.cptr, cid, C.int(v)))
	case int, int8, int16, int32, int64, uint, uint8, uint16, uint32, uint64:
		value := toint64(value)
		err = newError(C.yr_compiler_define_integer_variable(
			c.cptr, cid, C.int64_t(value)))
	case float64:
		err = newError(C.yr_compiler_define_float_variable(
			c.cptr, cid, C.double(value.(float64))))
	case string:
		cvalue := C.CString(value.(string))
		defer C.free(unsafe.Pointer(cvalue))
		err = newError(C.yr_compiler_define_string_variable(
			c.cptr, cid, cvalue))
	default:
		err = errors.New("wrong value type passed to DefineVariable; bool, int64, float64, string are accepted")
	}
	runtime.KeepAlive(c)
	return
}

// GetRules returns the compiled ruleset.
func (c *Compiler) GetRules() (*Rules, error) {
	if c.cptr.errors != 0 {
		return nil, errors.New("Compiler cannot be used after parse error")
	}
	var yrRules *C.YR_RULES
	if err := newError(C.yr_compiler_get_rules(c.cptr, &yrRules)); err != nil {
		return nil, err
	}
	r := &Rules{cptr: yrRules}
	runtime.SetFinalizer(r, (*Rules).Destroy)
	runtime.KeepAlive(c)
	return r, nil
}

//export includeCallback
func includeCallback(name, filename, namespace *C.char, userData unsafe.Pointer) *C.char {
	callbackFunc := callbackData.Get(userData).(CompilerIncludeFunc)
	if buf := callbackFunc(
		C.GoString(name), C.GoString(filename), C.GoString(namespace),
	); buf != nil {
		ptr := C.calloc(1, C.size_t(len(buf)+1))
		if ptr == nil {
			return nil
		}
		outbuf := make([]byte, 0)
		hdr := (*reflect.SliceHeader)(unsafe.Pointer(&outbuf))
		hdr.Data, hdr.Len = uintptr(ptr), len(buf)+1
		copy(outbuf, buf)
		return (*C.char)(ptr)
	}
	return nil
}

//export freeCallback
func freeCallback(callbackResultPtr *C.char, userData unsafe.Pointer) {
	if callbackResultPtr != nil {
		C.free(unsafe.Pointer(callbackResultPtr))
	}
	return
}

// CompilerIncludeFunc is used with Compiler.SetIncludeCallback.
// Arguments are: name for the rule file to be included, filename for
// the file that contains the include statement, namespace for the rule
// namespace. The function returns a byte slice containing the
// contents of the included file. It must return a nil return value on
// error.
//
// See also: yr_compiler_set_include_callback in the YARA C API
// documentation.
type CompilerIncludeFunc func(name, filename, namespace string) []byte

// SetIncludeCallback registers an include function that is called
// (through Go glue code) by the YARA compiler for every include
// statement.
func (c *Compiler) SetIncludeCallback(cb CompilerIncludeFunc) {
	if cb == nil {
		c.DisableIncludes()
		return
	}
	id := callbackData.Put(cb)
	c.setCallbackData(id)
	C.yr_compiler_set_include_callback(
		c.cptr,
		C.YR_COMPILER_INCLUDE_CALLBACK_FUNC(C.includeCallback),
		C.YR_COMPILER_INCLUDE_FREE_FUNC(C.freeCallback),
		id,
	)
	runtime.KeepAlive(c)
	return
}

// DisableIncludes disables all include statements in the compiler.
// See yr_compiler_set_include_callbacks.
func (c *Compiler) DisableIncludes() {
	C.yr_compiler_set_include_callback(c.cptr, nil, nil, nil)
	c.setCallbackData(nil)
	runtime.KeepAlive(c)
	return
}

// Compile compiles rules and an (optional) set of variables into a
// Rules object in a single step.
func Compile(rules string, variables map[string]interface{}) (r *Rules, err error) {
	var c *Compiler
	if c, err = NewCompiler(); err != nil {
		return
	}
	defer c.Destroy()
	for k, v := range variables {
		if err = c.DefineVariable(k, v); err != nil {
			return
		}
	}
	if err = c.AddString(rules, ""); err != nil {
		return
	}
	r, err = c.GetRules()
	return
}

// MustCompile is like Compile but panics if the rules and optional
// variables can't be compiled. Like regexp.MustCompile, it allows for
// simple, safe initialization of global or test data.
func MustCompile(rules string, variables map[string]interface{}) (r *Rules) {
	r, err := Compile(rules, variables)
	if err != nil {
		panic(err)
	}
	return
}
