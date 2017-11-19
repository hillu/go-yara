// Copyright © 2015-2017 Hilko Bengen <bengen@hilluzination.de>
// All rights reserved.
//
// Use of this source code is governed by the license that can be
// found in the LICENSE file.

package yara

/*
#include <yara.h>

static const char* rule_identifier(YR_RULE* r) {
	return r->identifier;
}

static void rule_tags(YR_RULE* r, const char **tags, int *n) {
	const char *end;
	yr_rule_tags_foreach(r, end) {};
	*n = end - r->tags - 1;
	*tags = r->tags;
	return;
}

static const char* rule_namespace(YR_RULE* r) {
	return r->ns->name;
}
*/
import "C"

import (
	"strings"
)

// Rule represents a single rule as part of a ruleset
type Rule struct {
	cptr *C.YR_RULE
}

// Identifier returns the rule's name.
func (r *Rule) Identifier() string {
	return C.GoString(C.rule_identifier(r.cptr))
}

// Namespace returns the rule's namespace.
func (r *Rule) Namespace() string {
	return C.GoString(C.rule_namespace(r.cptr))
}

// Tags returns the rule's tags.
func (r *Rule) Tags() []string {
	var tags *C.char
	var size C.int
	C.rule_tags(r.cptr, &tags, &size)
	return strings.Split(C.GoStringN(tags, size), "\x00")
}
