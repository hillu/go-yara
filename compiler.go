// Copyright © 2015 Hilko Bengen <bengen@hilluzination.de>. All rights reserved.
// Use of this source code is governed by the license that can be
// found in the LICENSE file.

package yara

/*
#cgo LDFLAGS: -lyara
#include <yara.h>

void compiler_callback(int error_level, const char* file_name, int line_number, const char* message, void* user_data);
*/
import "C"
import (
	"errors"
	"os"
	"runtime"
	"unsafe"
)

//export compilerCallback
func compilerCallback(errorLevel C.int, filename *C.char, linenumber C.int, message *C.char, ptr unsafe.Pointer) {
	if ptr == nil {
		return
	}
	compiler := (*Compiler)(ptr)
	msg := CompilerMessage{
		Filename: C.GoString(filename),
		Line:     int(linenumber),
		Text:     C.GoString(message),
	}
	switch errorLevel {
	case C.YARA_ERROR_LEVEL_ERROR:
		compiler.Errors = append(compiler.Errors, msg)
	case C.YARA_ERROR_LEVEL_WARNING:
		compiler.Warnings = append(compiler.Warnings, msg)
	}
}

// A Compiler encapsulates the YARA compiler that transforms rules
// into YARA's internal, binary form which in turn is used for
// scanning files or memory blocks.
type Compiler struct {
	c        *C.YR_COMPILER
	Errors   []CompilerMessage
	Warnings []CompilerMessage
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
	var compiler *C.YR_COMPILER
	if err := newError(C.yr_compiler_create(&compiler)); err != nil {
		return nil, err
	}
	c := &Compiler{c: compiler}
	C.yr_compiler_set_callback(compiler, C.YR_COMPILER_CALLBACK_FUNC(C.compiler_callback), unsafe.Pointer(c))
	runtime.SetFinalizer(c, (*Compiler).Destroy)
	return c, nil
}

// Destroy destroys the YARA data structure representing a compiler.
// On creation, a Finalizer is automatically set up to do this.
func (c *Compiler) Destroy() {
	if c.c != nil {
		C.yr_compiler_destroy(c.c)
		c.c = nil
	}
	runtime.SetFinalizer(c, nil)
}

// AddFile compiles rules from an os.File. Rules are added to the
// specified namespace.
func (c *Compiler) AddFile(file os.File, namespace string) (err error) {
	fh, err := C.fdopen(C.int(file.Fd()), C.CString("r"))
	if err != nil {
		return err
	}
	defer C.free(unsafe.Pointer(fh))
	var ns *C.char
	if namespace != "" {
		ns = C.CString(namespace)
		defer C.free(unsafe.Pointer(ns))
	}
	filename := C.CString(file.Name())
	defer C.free(unsafe.Pointer(filename))
	numErrors := int(C.yr_compiler_add_file(c.c, fh, ns, filename))
	if numErrors > 0 {
		var buf [1024]C.char
		msg := C.GoString(C.yr_compiler_get_error_message(
			c.c, (*C.char)(unsafe.Pointer(&buf[0])), 1024))
		err = errors.New(msg)
	}
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
	numErrors := int(C.yr_compiler_add_string(c.c, crules, ns))
	if numErrors > 0 {
		var buf [1024]C.char
		msg := C.GoString(C.yr_compiler_get_error_message(
			c.c, (*C.char)(unsafe.Pointer(&buf[0])), 1024))
		err = errors.New(msg)
	}
	return
}

// DefineVariable defines a named variable for use by the compiler.
// Boolean, int64, and string types are supported.
func (c *Compiler) DefineVariable(name string, value interface{}) (err error) {
	cname := C.CString(name)
	defer C.free(unsafe.Pointer(cname))
	switch value.(type) {
	case bool:
		var v int
		if value.(bool) {
			v = 1
		}
		err = newError(C.yr_compiler_define_boolean_variable(
			c.c, cname, C.int(v)))
	case int64:
		err = newError(C.yr_compiler_define_integer_variable(
			c.c, cname, C.int64_t(value.(int64))))
	case string:
		cvalue := C.CString(value.(string))
		defer C.free(unsafe.Pointer(cvalue))
		err = newError(C.yr_compiler_define_string_variable(
			c.c, cname, cvalue))
	default:
		err = errors.New("wrong value type passed to DefineVariable; bool, int64, string are accepted.")
	}
	return
}

// GetRules returns the compiled ruleset.
func (c *Compiler) GetRules() (rules *Rules, err error) {
	var r *C.YR_RULES
	err = newError(C.yr_compiler_get_rules(c.c, &r))
	if err == nil {
		rules = &Rules{r: r}
		runtime.SetFinalizer(rules, (*Rules).Destroy)
	}
	return
}

// Compile compiles rules and an (optional) set of variables into a
// Rules object in a single step.
func Compile(rules string, variables map[string]interface{}) (r *Rules, err error) {
	var c *Compiler
	if c, err = NewCompiler(); err != nil {
		return
	}
	for k, v := range(variables) {
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
