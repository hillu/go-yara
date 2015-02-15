package yara

import (
	"io"
	"unsafe"
)

// #include <string.h>
import "C"

//export streamRead
func streamRead(ptr unsafe.Pointer, size, nmemb C.size_t, user_data unsafe.Pointer) C.size_t {
	if size == 0 || nmemb == 0 {
		return nmemb
	}
	dst := uintptr(ptr)
	buf := make([]byte, size)
	rd := (*io.Reader)(user_data)
	for i := 0; i < int(nmemb); i++ {
		rc, err := (*rd).Read(buf)
		if err != nil || rc < int(size) {
			return C.size_t(i)
		}
		C.memcpy(unsafe.Pointer(dst+uintptr(i)*uintptr(size)), unsafe.Pointer(&buf[0]), size)
	}
	return nmemb
}

//export streamWrite
func streamWrite(ptr unsafe.Pointer, size, nmemb C.size_t, user_data unsafe.Pointer) C.size_t {
	if size == 0 || nmemb == 0 {
		return nmemb
	}
	src := uintptr(ptr)
	buf := make([]byte, size)
	wr := (*io.Writer)(user_data)
	for i := 0; i < int(nmemb); i++ {
		C.memcpy(unsafe.Pointer(&buf[0]), unsafe.Pointer(src+uintptr(i)*uintptr(size)), size)
		rc, err := (*wr).Write(buf)
		if err != nil || rc < int(size) {
			return C.size_t(i)
		}
	}
	return nmemb
}
