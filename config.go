// Copyright © 2015-2020 Hilko Bengen <bengen@hilluzination.de>
// All rights reserved.
//
// Use of this source code is governed by the license that can be
// found in the LICENSE file.

package yara

// #include <yara.h>
import "C"
import "unsafe"

type ConfigName uint32

const (
	ConfigStackSize             ConfigName = C.YR_CONFIG_STACK_SIZE
	ConfigMaxMatchData                     = C.YR_CONFIG_MAX_MATCH_DATA
	ConfigMaxStringsPerRule                = C.YR_CONFIG_MAX_STRINGS_PER_RULE
	ConfigMaxProcessMemoryChunk            = C.YR_CONFIG_MAX_PROCESS_MEMORY_CHUNK
)

// SetConfiguration sets a global YARA configuration option.
//
// Deprecated. Use the specialized SetConfig* functions instead.
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
//
// Deprecated. Use the specialized GetConfig* functions instead.
func GetConfiguration(name ConfigName) (interface{}, error) {
	var u C.uint32_t
	if err := newError(C.yr_get_configuration(
		C.YR_CONFIG_NAME(name), unsafe.Pointer(&u)),
	); err != nil {
		return nil, err
	}
	return int(u), nil
}

// SetConfigStackSize sets the size of the stack used by the bytecode interpreter.
func SetConfigStackSize(val uint32) error {
	u := (C.uint32_t)(val)
	return newError(
		C.yr_set_configuration(C.YR_CONFIG_STACK_SIZE, unsafe.Pointer(&u)))
}

// GetConfigStackSize returns the size of the stack used by the bytecode interpreter.
func GetConfigStackSize() (uint32, error) {
	var u C.uint32_t
	if err := newError(C.yr_get_configuration(
		C.YR_CONFIG_STACK_SIZE, unsafe.Pointer(&u)),
	); err != nil {
		return 0, err
	}
	return uint32(u), nil
}

// SetConfigMaxMatchData sets the maximum number of data copies per scan.
func SetConfigMaxMatchData(val uint32) error {
	u := (C.uint32_t)(val)
	return newError(
		C.yr_set_configuration(C.YR_CONFIG_MAX_MATCH_DATA, unsafe.Pointer(&u)))
}

// GetConfigMaxMatchData returns the maximum number of data copies per scan.
func GetConfigMaxMatchData() (uint32, error) {
	var u C.uint32_t
	if err := newError(C.yr_get_configuration(
		C.YR_CONFIG_MAX_MATCH_DATA, unsafe.Pointer(&u)),
	); err != nil {
		return 0, err
	}
	return uint32(u), nil
}

// SetConfigMaxStringsPerRule sets the maximum number of string that can match per rule.
func SetConfigMaxStringsPerRule(val uint32) error {
	u := (C.uint32_t)(val)
	return newError(
		C.yr_set_configuration(C.YR_CONFIG_MAX_STRINGS_PER_RULE, unsafe.Pointer(&u)))
}

// GetConfigMaxStringsPerRule returns the maximum number of string that can match per rule.
func GetConfigMaxStringsPerRule() (uint32, error) {
	var u C.uint32_t
	if err := newError(C.yr_get_configuration(
		C.YR_CONFIG_MAX_STRINGS_PER_RULE, unsafe.Pointer(&u)),
	); err != nil {
		return 0, err
	}
	return uint32(u), nil
}

// SetConfigMaxProcessMemoryChunk sets the maximum size per scanned memory chunk.
func SetConfigMaxProcessMemoryChunk(val uint64) error {
	u := (C.uint32_t)(val)
	return newError(
		C.yr_set_configuration(C.YR_CONFIG_MAX_PROCESS_MEMORY_CHUNK, unsafe.Pointer(&u)))
}

// GetConfigMaxProcessMemoryChunk returns the maximum size per scanned memory chunk.
func GetConfigMaxProcessMemoryChunk() (uint64, error) {
	var u C.uint64_t
	if err := newError(C.yr_get_configuration(
		C.YR_CONFIG_MAX_PROCESS_MEMORY_CHUNK, unsafe.Pointer(&u)),
	); err != nil {
		return 0, err
	}
	return uint64(u), nil
}
