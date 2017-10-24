// Copyright © 2015-2017 Hilko Bengen <bengen@hilluzination.de>
// All rights reserved.
//
// Use of this source code is governed by the license that can be
// found in the LICENSE file.

package yara

// #cgo !no_pkg_config,!yara_static  pkg-config: yara
// #cgo !no_pkg_config,yara_static   pkg-config: --static yara
// #cgo no_pkg_config                LDFLAGS:    -lyara
import "C"
