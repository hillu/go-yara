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
	"reflect"
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
// See also: yr_compiler_set_include_callback in the YARA C API
// documentation.
type CompilerIncludeFunc func(name, filename, namespace string) []byte

// DisableIncludes disables all include statements in the compiler.
// See yr_compiler_set_include_callbacks.
func (c *Compiler) DisableIncludes() {
	C.yr_compiler_set_include_callback(c.compiler.cptr, nil, nil, nil)
	c.setCallbackData(nil)
	keepAlive(c)
	return
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

// SetIncludeCallback sets up cb as an include callback that is called
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
		c.compiler.cptr,
		C.YR_COMPILER_INCLUDE_CALLBACK_FUNC(C.includeCallback),
		C.YR_COMPILER_INCLUDE_FREE_FUNC(C.freeCallback),
		id,
	)
	keepAlive(c)
	return
}
