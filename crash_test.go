package yara

import (
	"fmt"
	"runtime"
	"testing"
)

// Making a copy of Compiler struct should not cause a crash.
func TestCompilerFinalizer(t *testing.T) {
	var c Compiler
	func() {
		fmt.Println("Create compiler")
		c1, _ := NewCompiler()
		c = *c1
	}()
	fmt.Println("Trigger GC")
	runtime.GC()
	fmt.Println("Trigger Gosched")
	runtime.Gosched()
	fmt.Println("Manually call destructure on copy")
	c.Destroy()
	t.Log("Did not crash due to yr_*_destroy() being called twice. Yay.")
}

// Making a copy of Rules struct should not cause a crash.
func TestRulesFinalizer(t *testing.T) {
	var r Rules
	func() {
		fmt.Println("Create rules")
		r1, _ := Compile("rule test { condition: true }", nil)
		r = *r1
	}()
	fmt.Println("Trigger GC")
	runtime.GC()
	fmt.Println("Trigger Gosched")
	runtime.Gosched()
	fmt.Println("Manually call destructure on copy")
	r.Destroy()
	t.Log("Did not crash due to yr_*_destroy() being called twice. Yay.")
}

// Adapted from test in https://github.com/hillu/go-yara/issues/22
func TestCompilerCrash(t *testing.T) {
	done := make(chan bool)
	go func(t *testing.T, done <-chan bool) {
		for i := 0; ; i++ {
			select {
			case <-done:
				return
			default:
				t.Logf("GC %d", i)
				runtime.GC()
			}
		}
	}(t, done)
	for i := 0; i < 10000; i++ {
		t.Logf("compile %d", i)
		makeRules(t, "rule test { strings: $a = /a.*a/ condition: $a }")
	}
	close(done)
	t.Log("Callback data intact after compiler.AddString() invocation. Yay.")
	return
}
