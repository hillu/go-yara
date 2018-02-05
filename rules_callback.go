package yara

/*
#include <stdlib.h>
#include <yara.h>
*/
import "C"
import (
	"unsafe"
)

// Callback is the interface for the callback object passed to the
// Scan*WithCallback functions.
type Callback interface{}

// RuleMatchingCallback is the interface that must satisfy the object passed
// to Scan*WithCallback in order to receive messages about matching rules.
type RuleMatchingCallback interface {
	OnRuleMatching(*Rule) (bool, error)
}

// RuleNotMatchingCallback is the interface that must satisfy the object passed
// to Scan*WithCallback in order to receive messages about not matching rules.
type RuleNotMatchingCallback interface {
	OnRuleNotMatching(*Rule) (bool, error)
}

// ScanFinishedCallback is the interface that must satisfy the object passed
// to Scan*WithCallback in order to receive a message when the scan finishes.
type ScanFinishedCallback interface {
	OnScanFinished() (bool, error)
}

// ImportModuleCallback is the interface that must satisfy the object passed
// to Scan*WithCallback in order to receive a message when a module is about
// to be loaded.
type ImportModuleCallback interface {
	OnImportModule(string) ([]byte, bool, error)
}

// ModuleImportedCallback is the interface that must satisfy the object passed
// to Scan*WithCallback in order to receive a message when a module has been
// imported.
type ModuleImportedCallback interface {
	OnModuleImported(*Object) (bool, error)
}

// MatchRules implements the RuleMatchingCallback interface and is used to
// collect matches that are returned by the simple (*Rules).Scan* methods.
type MatchRules []MatchRule

//export scanCallbackFunc
func scanCallbackFunc(message C.int, messageData, ctxID unsafe.Pointer) C.int {
	var abort bool
	var err error
	ctx := callbackData.Get(*(*uintptr)(ctxID)).(*scanContext)
	switch message {
	case C.CALLBACK_MSG_RULE_MATCHING:
		cb, ok := ctx.callback.(RuleMatchingCallback)
		if ok {
			r := (*C.YR_RULE)(messageData)
			abort, err = cb.OnRuleMatching(&Rule{r})
		}
	case C.CALLBACK_MSG_RULE_NOT_MATCHING:
		cb, ok := ctx.callback.(RuleNotMatchingCallback)
		if ok {
			r := (*C.YR_RULE)(messageData)
			abort, err = cb.OnRuleNotMatching(&Rule{r})
		}
	case C.CALLBACK_MSG_SCAN_FINISHED:
		cb, ok := ctx.callback.(ScanFinishedCallback)
		if ok {
			abort, err = cb.OnScanFinished()
		}
	case C.CALLBACK_MSG_IMPORT_MODULE:
		cb, ok := ctx.callback.(ImportModuleCallback)
		if ok {
			mi := (*C.YR_MODULE_IMPORT)(messageData)
			var moduleData []byte
			moduleData, abort, err = cb.OnImportModule(C.GoString(mi.module_name))
			if !abort && err == nil {
				l := C.size_t(len(moduleData))
				b := C.malloc(l)
				C.memcpy(b, unsafe.Pointer(&moduleData[0]), l)
				ctx.freeOnFinalize(b)
				mi.module_data = b
				mi.module_data_size = l
			}
		}
	case C.CALLBACK_MSG_MODULE_IMPORTED:
		cb, ok := ctx.callback.(ModuleImportedCallback)
		if ok {
			obj := (*C.YR_OBJECT)(messageData)
			abort, err = cb.OnModuleImported(&Object{obj})
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

func (mr *MatchRules) OnRuleMatching(r *Rule) (abort bool, err error) {
	*mr = append(*mr, MatchRule{
		Rule:      r.Identifier(),
		Namespace: r.Namespace(),
		Tags:      r.Tags(),
		Meta:      r.Metas(),
		Strings:   r.getMatchStrings(),
	})
	return
}
