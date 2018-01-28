// Copyright © 2015-2017 Hilko Bengen <bengen@hilluzination.de>
// All rights reserved.
//
// Use of this source code is governed by the license that can be
// found in the LICENSE file.

package yara

/*
#include <yara.h>

// rule_identifier is a union accessor function.
static const char* rule_identifier(YR_RULE* r) {
	return r->identifier;
}

// rule_namespace is a union accessor function.
static const char* rule_namespace(YR_RULE* r) {
	return r->ns->name;
}

// rule_tags returns pointers to the tag names associated with a rule,
// using YARA's own implementation
static void rule_tags(YR_RULE* r, const char *tags[], int *n) {
	const char *tag;
	int i = 0;
	yr_rule_tags_foreach(r, tag) {
		if (i < *n)
			tags[i] = tag;
		i++;
	};
	*n = i;
	return;
}

// rule_tags returns pointers to the meta variables associated with a
// rule, using YARA's own implementation
static void rule_metas(YR_RULE* r, const YR_META *metas[], int *n) {
	const YR_META *meta;
	int i = 0;
	yr_rule_metas_foreach(r, meta) {
		if (i < *n)
			metas[i] = meta;
		i++;
	};
	*n = i;
	return;
}

// meta_get is an accessor function for unions that are not directly
// accessible from Go because CGO does not understand them.
static void meta_get(YR_META *m, const char** identifier, char** string) {
	*identifier = m->identifier;
	*string = m->string;
	return;
}
*/
import "C"

// Rule represents a single rule as part of a ruleset
type Rule struct{ cptr *C.YR_RULE }

// Identifier returns the rule's name.
func (r *Rule) Identifier() string {
	return C.GoString(C.rule_identifier(r.cptr))
}

// Namespace returns the rule's namespace.
func (r *Rule) Namespace() string {
	return C.GoString(C.rule_namespace(r.cptr))
}

// Tags returns the rule's tags.
func (r *Rule) Tags() (tags []string) {
	var size C.int
	C.rule_tags(r.cptr, nil, &size)
	if size == 0 {
		return
	}
	tagptrs := make([]*C.char, int(size))
	C.rule_tags(r.cptr, &tagptrs[0], &size)
	for _, t := range tagptrs {
		tags = append(tags, C.GoString(t))
	}
	return
}

// Metas returns a map containing the rule's meta variables. Values
// can be of type string, int, bool, or nil.
func (r *Rule) Metas() (metas map[string]interface{}) {
	metas = make(map[string]interface{})
	var size C.int
	C.rule_metas(r.cptr, nil, &size)
	if size == 0 {
		return
	}
	mptrs := make([]*C.YR_META, int(size))
	C.rule_metas(r.cptr, &mptrs[0], &size)
	for _, m := range mptrs {
		var id, str *C.char
		C.meta_get(m, &id, &str)
		switch m._type {
		case C.META_TYPE_NULL:
			metas[C.GoString(id)] = nil
		case C.META_TYPE_STRING:
			metas[C.GoString(id)] = C.GoString(str)
		case C.META_TYPE_INTEGER:
			metas[C.GoString(id)] = int(m.integer)
		case C.META_TYPE_BOOLEAN:
			metas[C.GoString(id)] = m.integer != 0
		}
	}
	return
}
