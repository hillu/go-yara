// Copyright © 2015 Hilko Bengen <bengen@hilluzination.de>. All rights reserved.
// Use of this source code is governed by the license that can be
// found in the LICENSE file.

package yara

/*
#cgo LDFLAGS: -lyara
#include <yara.h>

void compiler_callback(int error_leve, const char* file_name, int line_number, const char* message);
*/
import "C"
import (
	"errors"
	"os"
	"runtime"
	"unsafe"
)

// A Compiler encapsulates the YARA compiler that transforms rules
// into YARA's internal, binary form which in turn is used for
// scanning files or memory blocks.
type Compiler struct {
	c *C.YR_COMPILER
}

// NewCompiler creates a YARA compiler.
func NewCompiler() (c *Compiler, err error) {
	var compiler *C.YR_COMPILER
	err = newError(C.yr_compiler_create(&compiler))
	C.yr_compiler_set_callback(compiler, C.YR_COMPILER_CALLBACK_FUNC(C.compiler_callback))
	if err == nil {
		c = &Compiler{c: compiler}
		runtime.SetFinalizer(c, func(c *Compiler) {
			C.yr_compiler_destroy(c.c)
			c.c = nil
		})
	}
	return
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
	}
	filename := C.CString(file.Name())
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
	}
	numErrors := int(C.yr_compiler_add_string(c.c, C.CString(rules), ns))
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
	switch value.(type) {
	case bool:
		var v int
		if value.(bool) {
			v = 1
		}
		err = newError(C.yr_compiler_define_boolean_variable(
			c.c, C.CString(name), C.int(v)))
	case int64:
		err = newError(C.yr_compiler_define_integer_variable(
			c.c, C.CString(name), C.int64_t(value.(int64))))
	case string:
		err = newError(C.yr_compiler_define_string_variable(
			c.c, C.CString(name), C.CString(value.(string))))
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
		runtime.SetFinalizer(rules, func(r *Rules) {
			C.yr_rules_destroy(r.r)
			r.r = nil
		})
	}
	return
}
