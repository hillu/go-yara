// Copyright © 2015-2020 Hilko Bengen <bengen@hilluzination.de>
// All rights reserved.
//
// Use of this source code is governed by the license that can be
// found in the LICENSE file.

// +build !yara3.4,!yara3.5

package yara

/*
#include <yara.h>

#ifdef _WIN32
#include <stdint.h>
YR_API int _yr_compiler_add_fd(
    YR_COMPILER* compiler,
    int rules_fd,
    const char* namespace_,
    const char* file_name)
{
  return yr_compiler_add_fd(compiler, (YR_FILE_DESCRIPTOR)(intptr_t)rules_fd, namespace_, file_name);
}
#else
#define _yr_compiler_add_fd yr_compiler_add_fd
#endif

void compilerCallback(int, char*, int, char*, void*);
*/
import "C"
import (
	"errors"
	"os"
	"runtime"
	"unsafe"
)

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
	numErrors := int(C._yr_compiler_add_fd(c.cptr, (C.int)(file.Fd()), ns, filename))
	if numErrors > 0 {
		var buf [1024]C.char
		msg := C.GoString(C.yr_compiler_get_error_message(
			c.cptr, (*C.char)(unsafe.Pointer(&buf[0])), 1024))
		err = errors.New(msg)
	}
	runtime.KeepAlive(c)
	return
}
