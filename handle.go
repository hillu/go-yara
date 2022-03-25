//+build go1.17

// This variant contains a trivial wrapper around "runtime/cgo".Handle.

package yara

import "runtime/cgo"

type cgoHandle cgo.Handle

func cgoNewHandle(v interface{}) cgoHandle { return cgo.NewHandle(v) }
