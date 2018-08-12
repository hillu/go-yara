// Copyright © 2015-2017 Hilko Bengen <bengen@hilluzination.de>. All rights reserved.
// Use of this source code is governed by the license that can be
// found in the LICENSE file.

// +build !yara3.3,!yara3.4

package yara

// #include <yara.h>
import "C"
import "unsafe"

type ConfigName uint32

const (
	ConfigStackSize         ConfigName = C.YR_CONFIG_STACK_SIZE
	ConfigMaxStringsPerRule            = C.YR_CONFIG_MAX_STRINGS_PER_RULE
)

// SetCnofiguration sets a global YARA configuration option.
func SetConfiguration(name ConfigName, src interface{}) error {
	i, ok := src.(int)
	if !ok {
		return newError(C.ERROR_INTERNAL_FATAL_ERROR)
	}
	u := C.uint32_t(i)
	return newError(
		C.yr_set_configuration(C.YR_CONFIG_NAME(name), unsafe.Pointer(&u)))
}

// GetConfiguration gets a global YARA configuration option.
func GetConfiguration(name ConfigName) (interface{}, error) {
	var u C.uint32_t
	if err := newError(C.yr_get_configuration(
		C.YR_CONFIG_NAME(name), unsafe.Pointer(&u)),
	); err != nil {
		return nil, err
	}
	return int(u), nil
}
