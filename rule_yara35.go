// +build !yara3.4

package yara

// #include <yara.h>
import "C"
import "unsafe"

// Data returns the blob of data associated with the string match
func (m *Match) Data() []byte {
	return C.GoBytes(unsafe.Pointer(m.cptr.data), C.int(m.cptr.data_length))
}
