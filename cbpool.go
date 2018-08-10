// Copyright © 2018 Hilko Bengen <bengen@hilluzination.de>
// All rights reserved.
//
// Use of this source code is governed by the license that can be
// found in the LICENSE file.

package yara

import (
	"reflect"
	"runtime"
	"sync"
	"unsafe"
)

// #include <stdlib.h>
import "C"

// cbPoolPool implements a key/value store for data that is safe
// to pass as callback data through CGO functions.
//
// The keys are pointers which do not directly reference the stored
// values, therefore any "Go pointer to Go pointer" errors are avoided.
type cbPool struct {
	indices []int
	objects []interface{}
	m       sync.RWMutex
}

// MakePool creates a Pool that can hold n elements.
func makecbPool(n int) *cbPool {
	p := &cbPool{
		indices: make([]int, 0),
		objects: make([]interface{}, n),
	}
	hdr := (*reflect.SliceHeader)(unsafe.Pointer(&p.indices))
	hdr.Data = uintptr(C.calloc(C.size_t(n), C.size_t(unsafe.Sizeof(int(0)))))
	hdr.Len = n
	runtime.SetFinalizer(p, (*cbPool).Finalize)
	return p
}

// Put adds an element to the cbPool, returning a stable pointer
// suitable for passing through CGO. It panics if the pool is full.
func (p *cbPool) Put(obj interface{}) unsafe.Pointer {
	p.m.Lock()
	defer p.m.Unlock()
	for id, val := range p.indices {
		if val != 0 {
			continue
		}
		p.indices[id] = id + 1
		p.objects[id] = obj
		return unsafe.Pointer(&p.indices[id])
	}
	panic("cbPool storage exhausted")
}

func (p *cbPool) checkPointer(ptr unsafe.Pointer) {
	if uintptr(ptr) < uintptr(unsafe.Pointer(&p.indices[0])) ||
		uintptr(unsafe.Pointer(&p.indices[len(p.indices)-1])) < uintptr(ptr) {
		panic("Attempt to access pool using invalid pointer")
	}
}

// Put accesses an element stored in the cbPool, using a pointer
// previously returned by Put. It panics if the pointer is invalid or
// if it references an empty slot.
func (p *cbPool) Get(ptr unsafe.Pointer) interface{} {
	p.m.RLock()
	defer p.m.RUnlock()
	p.checkPointer(ptr)
	id := *(*int)(ptr) - 1
	if id == -1 {
		panic("Attempt to get nonexistent value from pool")
	}
	return p.objects[id]
}

// Delete removes an element from the cbPool, using a pointer previously
// returned by Put. It panics if the pointer is invalid or if it
// references an empty slot.
func (p *cbPool) Delete(ptr unsafe.Pointer) {
	p.m.Lock()
	defer p.m.Unlock()
	p.checkPointer(ptr)
	id := *(*int)(ptr) - 1
	if id == -1 {
		panic("Attempt to delete nonexistent value from pool")
	}
	p.indices[id] = 0
	p.objects[id] = nil
	return
}

func (p *cbPool) Finalize() {
	p.m.Lock()
	defer p.m.Unlock()
	if p.indices != nil {
		C.free(unsafe.Pointer(&p.indices[0]))
		p.indices = nil
	}
}
