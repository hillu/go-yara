// Copyright © 2018 Victor M. Alvarez <plusvic@gmail.com>
// All rights reserved.
//
// Use of this source code is governed by the license that can be
// found in the LICENSE file.

//+build !yara3.3,!yara3.4,!yara3.5,!yara3.6,!yara3.7

package yara

/*
#include <yara.h>
#include <stdlib.h>
#include <string.h>
*/
import "C"

// LoadAtomPrevalenceTable loads an atom prevalence table from a file.
func (c *Compiler) LoadAtomPrevalenceTable(path string) error {
	err := newError(C.yr_compiler_load_atom_prevalence_table(
		c.compiler.cptr,
		C.CString(path)))
	keepAlive(c)
	return err
}
