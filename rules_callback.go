package yara

/*
#include <stdlib.h>
#include <yara.h>

// Constant not defined until YARA 3.5
#ifndef CALLBACK_MSG_MODULE_IMPORTED
# define CALLBACK_MSG_MODULE_IMPORTED 5
#endif
*/
import "C"
import (
	"unsafe"
)

// ScanCallback is a placeholder for different interfaces that may be
// implemented by the callback object that is passed to the
// (*Rules).Scan*WithCallback methods.
type ScanCallback interface{}

// ScanCallbackMatch is used to record rules that matched during a
// scan. The RuleMatching method corresponds to YARA's
// CALLBACK_MSG_RULE_MATCHING message.
type ScanCallbackMatch interface {
	RuleMatching(*Rule) (bool, error)
}

// ScanCallbackNoMatch is used to record rules that did not match
// during a scan. The RuleNotMatching method corresponds to YARA's
// CALLBACK_MSG_RULE_NOT_MATCHING mssage.
type ScanCallbackNoMatch interface {
	RuleNotMatching(*Rule) (bool, error)
}

// ScanCallbackFinished is used to signal that a scan has finished.
// The ScanFinished method corresponds to YARA's
// CALLBACK_MSG_SCAN_FINISHED message.
type ScanCallbackFinished interface {
	ScanFinished() (bool, error)
}

// ScanCallbackModuleImport is used to provide data to a YARA module.
// The ImportModule method corresponds to YARA's
// CALLBACK_MSG_IMPORT_MODULE message.
//
// Deprecated: this variant leaks memory in form of the C copy of the returned module data []byte slice.
// See ScanCallbackModuleImportWrapped for the correct way to handle this callback.
type ScanCallbackModuleImport interface {
	ImportModule(string) ([]byte, bool, error)
}

// ScanCallbackModuleImportWrapped is used to provide data to a YARA module, same as ScanCallbackModuleImport
// The difference between the two is that the Wrapped variant returns a Wrapper over the C-allocated array,
// which you should create before scanning and Destroy() after you're done with scanning using that particular
// instance of ScanCallbackModuleImportWrapped.
//
// The ImportModuleWrapped method corresponds to YARA's
// CALLBACK_MSG_IMPORT_MODULE message.
type ScanCallbackModuleImportWrapped interface {
	ImportModuleWrapped(module_name string) (data *ModuleData, abort bool, err error)
}

// ScanCallbackModuleImportFinished can be used to free resources that
// have been used in the ScanCallbackModuleImport implementation. The
// ModuleImported method corresponds to YARA's
// CALLBACK_MSG_MODULE_IMPORTED message.
type ScanCallbackModuleImportFinished interface {
	ModuleImported(*Object) (bool, error)
}

//export scanCallbackFunc
func scanCallbackFunc(message C.int, messageData, userData unsafe.Pointer) C.int {
	cb := callbackData.Get(userData)
	var abort bool
	var err error
	switch message {
	case C.CALLBACK_MSG_RULE_MATCHING:
		if c, ok := cb.(ScanCallbackMatch); ok {
			r := (*C.YR_RULE)(messageData)
			abort, err = c.RuleMatching(&Rule{r})
		}
	case C.CALLBACK_MSG_RULE_NOT_MATCHING:
		if c, ok := cb.(ScanCallbackNoMatch); ok {
			r := (*C.YR_RULE)(messageData)
			abort, err = c.RuleNotMatching(&Rule{r})
		}
	case C.CALLBACK_MSG_SCAN_FINISHED:
		if c, ok := cb.(ScanCallbackFinished); ok {
			abort, err = c.ScanFinished()
		}
	case C.CALLBACK_MSG_IMPORT_MODULE:
		if c, ok := cb.(ScanCallbackModuleImportWrapped); ok {
			mi := (*C.YR_MODULE_IMPORT)(messageData)
			var data *ModuleData
			if data, abort, err = c.ImportModuleWrapped(C.GoString(mi.module_name)); data == nil || data.size == 0 {
				break
			}

			mi.module_data, mi.module_data_size = data.data, data.size
		} else if c, ok := cb.(ScanCallbackModuleImport); ok {
			mi := (*C.YR_MODULE_IMPORT)(messageData)
			var buf []byte
			if buf, abort, err = c.ImportModule(C.GoString(mi.module_name)); len(buf) == 0 {
				break
			}

			// Memory leak, fixed with ScanCallbackModuleImportWrapped
			mi.module_data, mi.module_data_size = cBytes(buf)
		}
	case C.CALLBACK_MSG_MODULE_IMPORTED:
		if c, ok := cb.(ScanCallbackModuleImportFinished); ok {
			obj := (*C.YR_OBJECT)(messageData)
			abort, err = c.ModuleImported(&Object{obj})
		}
	}

	if err != nil {
		return C.CALLBACK_ERROR
	}
	if abort {
		return C.CALLBACK_ABORT
	}
	return C.CALLBACK_CONTINUE
}

// MatchRules is used to collect matches that are returned by the
// simple (*Rules).Scan* methods.
type MatchRules []MatchRule

// RuleMatching implements the ScanCallbackMatch interface for
// MatchRules.
func (mr *MatchRules) RuleMatching(r *Rule) (abort bool, err error) {
	metas := r.Metas()
	// convert int to int32 for code that relies on previous behavior
	for s := range metas {
		if i, ok := metas[s].(int); ok {
			metas[s] = int32(i)
		}
	}
	*mr = append(*mr, MatchRule{
		Rule:      r.Identifier(),
		Namespace: r.Namespace(),
		Tags:      r.Tags(),
		Meta:      metas,
		Strings:   r.getMatchStrings(),
	})
	return
}

// ModuleData is a wrapper around byte array returned returned from ScanCallbackModuleImportWrapped
// Its purpose is to free memory allocated by the array in C code. You have to call Destroy() manually.
type ModuleData struct {
	data unsafe.Pointer
	size C.size_t
}

// Returns new ModuleData with your data
func NewModuleData(data []byte) *ModuleData {
	res := &ModuleData{}
	res.data, res.size = cBytes(data)
	// If there is no reference to ModuleData, the finalizer could run while the scanner is still scanning,
	// crashing the program. Better to leak than crash.
	// runtime.SetFinalizer(res, (*ModuleData).Destroy)
	return res
}

// Call to free memory associated with this module data. You have to call this method manually,
// otherwise the memory will be leaked.
func (d *ModuleData) Destroy() {
	if d.data != nil {
		C.free(d.data)
		d.data = nil
		d.size = 0
	}
}
