// Copyright © 2015-2017 Hilko Bengen <bengen@hilluzination.de>. All rights reserved.
// Use of this source code is governed by the license that can be
// found in the LICENSE file.

// +build go1.7

package yara

import (
	"runtime"
)

// The post-Go-1.7 version of keepAlive() contains a "call" to
// runtime.KeepAlive which is recognized as a hint by the compiler.
func keepAlive(i interface{}) {
	runtime.KeepAlive(i)
}
