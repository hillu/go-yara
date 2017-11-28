// Copyright © 2015-2017 Hilko Bengen <bengen@hilluzination.de>
// All rights reserved.
//
// Use of this source code is governed by the license that can be
// found in the LICENSE file.

//+build !yara3.3,!yara3.4,!yara3.5,!yara3.6

package yara

/*
#include <yara.h>
#include <stdlib.h>
#include <string.h>

char* includeCallback(char*, char*, char*, void*);
void freeCallback(char*, void*);
*/
import "C"
import (
	"unsafe"
)

// CompilerIncludeFunc is the type of the function that can be
// registered through SetIncludeCallback. It is called for every
// include statement encountered by the compiler. The argument "name"
// specifies the rule file to be included, "filename" specifies the
// name of the rule file where the include statement has been
// encountered, and "namespace" specifies the rule namespace. The sole
// return value is a byte slice containing the contents of the
// included file. A return value of nil signals an error to the YARA
// compiler.
//
// See yr_compiler_set_include_callback
type CompilerIncludeFunc func(name, filename, namespace string) []byte

// DisableIncludes disables all include statements in the compiler.
// See yr_compiler_set_include_callbacks.
func (c *Compiler) DisableIncludes() {
	C.yr_compiler_set_include_callback(c.compiler.cptr, nil, nil, nil)
	keepAlive(c)
	return
}

//export includeCallback
func includeCallback(name, filename, namespace *C.char, user_data unsafe.Pointer) *C.char {
	id := *((*uintptr)(user_data))
	callbackFunc := callbackData.Get(id).(CompilerIncludeFunc)
	if buf := callbackFunc(
		C.GoString(name), C.GoString(filename), C.GoString(namespace),
	); buf != nil {
		outbuf := C.calloc(1, C.size_t(len(buf)+1))
		C.memcpy(outbuf, unsafe.Pointer(&buf[0]), C.size_t(len(buf)))
		return (*C.char)(outbuf)
	}
	return nil
}

//export freeCallback
func freeCallback(callback_result_ptr *C.char, user_data unsafe.Pointer) {
	if callback_result_ptr != nil {
		C.free(unsafe.Pointer(callback_result_ptr))
	}
	return
}

// SetIncludeCallback sets up cb as an include callback that is called
// (through Go glue code) by the YARA compiler for every include
// statement.
func (c *Compiler) SetIncludeCallback(cb CompilerIncludeFunc) {
	if cb == nil {
		c.DisableIncludes()
		return
	}
	id := callbackData.Put(cb)
	C.yr_compiler_set_include_callback(
		c.compiler.cptr,
		C.YR_COMPILER_INCLUDE_CALLBACK_FUNC(C.includeCallback),
		C.YR_COMPILER_INCLUDE_FREE_FUNC(C.freeCallback),
		unsafe.Pointer(&id),
	)
	keepAlive(c)
	return
}
