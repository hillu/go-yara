// Copyright © 2015-2017 Hilko Bengen <bengen@hilluzination.de>
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

void compilerCallback(int, char*, int, char*, void*);
*/
import "C"
import (
	"errors"
	"os"
	"runtime"
	"unsafe"
)

//export compilerCallback
func compilerCallback(errorLevel C.int, filename *C.char, linenumber C.int, message *C.char, userData unsafe.Pointer) {
	c := callbackData.Get(*(*uintptr)(userData)).(*Compiler)
	msg := CompilerMessage{
		Filename: C.GoString(filename),
		Line:     int(linenumber),
		Text:     C.GoString(message),
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
type Compiler struct {
	*compiler
	Errors   []CompilerMessage
	Warnings []CompilerMessage
}

type compiler struct {
	cptr *C.YR_COMPILER
}

// A CompilerMessage contains an error or warning message produced
// while compiling sets of rules using AddString or AddFile.
type CompilerMessage struct {
	Filename string
	Line     int
	Text     string
}

// NewCompiler creates a YARA compiler.
func NewCompiler() (*Compiler, error) {
	var yrCompiler *C.YR_COMPILER
	if err := newError(C.yr_compiler_create(&yrCompiler)); err != nil {
		return nil, err
	}
	c := &Compiler{compiler: &compiler{cptr: yrCompiler}}
	runtime.SetFinalizer(c.compiler, (*compiler).finalize)
	return c, nil
}

func (c *compiler) finalize() {
	C.yr_compiler_destroy(c.cptr)
	runtime.SetFinalizer(c, nil)
}

// Destroy destroys the YARA data structure representing a compiler.
// Since a Finalizer for the underlying YR_COMPILER structure is
// automatically set up on creation, it should not be necessary to
// explicitly call this method.
func (c *Compiler) Destroy() {
	if c.compiler != nil {
		c.compiler.finalize()
		c.compiler = nil
	}
}

// AddFile compiles rules from a file. Rules are added to the
// specified namespace.
func (c *Compiler) AddFile(file *os.File, namespace string) (err error) {
	fd := C.dup(C.int(file.Fd()))
	fh, err := C.fdopen(fd, C.CString("r"))
	if err != nil {
		return err
	}
	defer C.fclose(fh)
	var ns *C.char
	if namespace != "" {
		ns = C.CString(namespace)
		defer C.free(unsafe.Pointer(ns))
	}
	filename := C.CString(file.Name())
	defer C.free(unsafe.Pointer(filename))
	id := callbackData.Put(c)
	defer callbackData.Delete(id)
	C.yr_compiler_set_callback(c.cptr, C.YR_COMPILER_CALLBACK_FUNC(C.compilerCallback), unsafe.Pointer(&id))
	numErrors := int(C.yr_compiler_add_file(c.cptr, fh, ns, filename))
	if numErrors > 0 {
		var buf [1024]C.char
		msg := C.GoString(C.yr_compiler_get_error_message(
			c.cptr, (*C.char)(unsafe.Pointer(&buf[0])), 1024))
		err = errors.New(msg)
	}
	keepAlive(id)
	keepAlive(c)
	return
}

// AddString compiles rules from a string. Rules are added to the
// specified namespace.
func (c *Compiler) AddString(rules string, namespace string) (err error) {
	var ns *C.char
	if namespace != "" {
		ns = C.CString(namespace)
		defer C.free(unsafe.Pointer(ns))
	}
	crules := C.CString(rules)
	defer C.free(unsafe.Pointer(crules))
	id := callbackData.Put(c)
	defer callbackData.Delete(id)
	C.yr_compiler_set_callback(c.cptr, C.YR_COMPILER_CALLBACK_FUNC(C.compilerCallback), unsafe.Pointer(&id))
	numErrors := int(C.yr_compiler_add_string(c.cptr, crules, ns))
	if numErrors > 0 {
		var buf [1024]C.char
		msg := C.GoString(C.yr_compiler_get_error_message(
			c.cptr, (*C.char)(unsafe.Pointer(&buf[0])), 1024))
		err = errors.New(msg)
	}
	keepAlive(id)
	keepAlive(c)
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
	keepAlive(c)
	return
}

// GetRules returns the compiled ruleset.
func (c *Compiler) GetRules() (*Rules, error) {
	var yrRules *C.YR_RULES
	if err := newError(C.yr_compiler_get_rules(c.cptr, &yrRules)); err != nil {
		return nil, err
	}
	r := &Rules{rules: &rules{cptr: yrRules}}
	runtime.SetFinalizer(r.rules, (*rules).finalize)
	keepAlive(c)
	return r, nil
}

// Compile compiles rules and an (optional) set of variables into a
// Rules object in a single step.
func Compile(rules string, variables map[string]interface{}) (r *Rules, err error) {
	var c *Compiler
	if c, err = NewCompiler(); err != nil {
		return
	}
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
