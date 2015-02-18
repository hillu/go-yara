// Copyright © 2015 Hilko Bengen <bengen@hilluzination.de>. All rights reserved.
// Use of this source code is governed by the license that can be
// found in the LICENSE file.

package yara

/*
// #cgo linux freebsd netbsd darwin CFLAGS: -I/path/to/include/
#cgo linux freebsd netbsd darwin LDFLAGS: -lyara

// Use something like the following with the MinGW-w64 cross compiler:

// #cgo windows       CFLAGS: -I/path/to/include/
// #cgo windows,386   LDFLAGS: /path/to/lib/libyara.a
// #cgo windows,amd64 LDFLAGS: /path/to/lib/libyara.a
*/
import "C"
