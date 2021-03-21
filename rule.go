// Copyright © 2015-2020 Hilko Bengen <bengen@hilluzination.de>
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
// using YARA's own implementation.
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
// rule, using YARA's own implementation.
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
// accessible from Go because CGO does not understand the union types
// generated using the DECLARE_REFERENCE macro.
static void meta_get(YR_META *m, const char** identifier, char** string) {
	*identifier = m->identifier;
	*string = m->string;
	return;
}

// rule_strings returns pointers to the matching strings associated
// with a rule, using YARA's macro-based implementation.
static void rule_strings(YR_RULE* r, const YR_STRING *strings[], int *n) {
	const YR_STRING *string;
	int i = 0;
	yr_rule_strings_foreach(r, string) {
		if (i < *n)
			strings[i] = string;
		i++;
	}
	*n = i;
	return;
}

// string_identifier is a union accessor function.
static const char* string_identifier(YR_STRING* s) {
	return s->identifier;
}

// string_matches returns pointers to the string match objects
// associated with a string, using YARA's macro-based implementation.
static void string_matches(YR_STRING* s, const YR_MATCH *matches[], int *n) {
	const YR_MATCH *match;
	int i = 0;
	yr_string_matches_foreach(s, match) {
		if (i < *n)
			matches[i] = match;
		i++;
	};
	*n = i;
	return;
}

*/
import "C"

// Rule represents a single rule as part of a ruleset.
type Rule struct {
	cptr *C.YR_RULE
	// Save underlying YR_RULES from being cleaned due to GC
	rules *Rules
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

// Meta represents a rule meta variable. Value can be of type string,
// int, boolean, or nil.
type Meta struct {
	Identifier string
	Value      interface{}
}

// MetaList returns the rule's meta variables as a list of Meta
// objects. It does not share the limitation of Metas().
func (r *Rule) MetaList() (metas []Meta) {
	var size C.int
	C.rule_metas(r.cptr, nil, &size)
	if size == 0 {
		return
	}
	mptrs := make([]*C.YR_META, int(size))
	C.rule_metas(r.cptr, &mptrs[0], &size)
	for _, cptr := range mptrs {
		var cid, cstr *C.char
		C.meta_get(cptr, &cid, &cstr)
		id := C.GoString(cid)
		var val interface{}
		switch cptr._type {
		case C.META_TYPE_NULL:
			val = nil
		case C.META_TYPE_STRING:
			val = C.GoString(cstr)
		case C.META_TYPE_INTEGER:
			val = int(cptr.integer)
		case C.META_TYPE_BOOLEAN:
			val = (cptr.integer != 0)
		}
		metas = append(metas, Meta{id, val})
	}
	return
}

// MetaMap returns a map containing the rule's meta variables, with
// the variable names as keys. Values are collected into lists, this
// allows for multiple variables with the same; individual values can
// be of type string, int, bool, or nil.
func (r *Rule) MetaMap() (metas map[string][]interface{}) {
	metas = make(map[string][]interface{})
	for _, m := range r.MetaList() {
		metas[m.Identifier] = append(metas[m.Identifier], m.Value)
	}
	return
}

// Metas returns a map containing the rule's meta variables, with the
// variable names as keys. Values can be of type string, int, bool, or
// nil.
//
// Deprecated: If there are multiple meta variables with the same
// name, the returned map contains only the last variable.
//
// Use MetaList or MetaMap instead.
func (r *Rule) Metas() (metas map[string]interface{}) {
	metas = make(map[string]interface{})
	for _, m := range r.MetaList() {
		metas[m.Identifier] = m.Value
	}
	return
}

// IsPrivate returns true if the rule is marked as private.
func (r *Rule) IsPrivate() bool {
	return (r.cptr.g_flags & C.RULE_GFLAGS_PRIVATE) != 0
}

// IsGlobal returns true if the rule is marked as global.
func (r *Rule) IsGlobal() bool {
	return (r.cptr.g_flags & C.RULE_GFLAGS_GLOBAL) != 0
}

// String represents a string as part of a rule.
type String struct {
	cptr *C.YR_STRING
	// Save underlying YR_RULES from being cleaned due to GC
	rules *Rules
}

// Strings returns the rule's strings.
func (r *Rule) Strings() (strs []String) {
	var size C.int
	C.rule_strings(r.cptr, nil, &size)
	if size == 0 {
		return
	}
	ptrs := make([]*C.YR_STRING, int(size))
	C.rule_strings(r.cptr, &ptrs[0], &size)
	for _, ptr := range ptrs {
		strs = append(strs, String{ptr, r.rules})
	}
	return
}

// Identifier returns the string's name.
func (s *String) Identifier() string {
	return C.GoString(C.string_identifier(s.cptr))
}

// Match represents a string match.
type Match struct {
	cptr *C.YR_MATCH
	// Save underlying YR_RULES from being cleaned due to GC
	rules *Rules
}

// Matches returns all matches that have been recorded for the string.
func (s *String) Matches() (matches []Match) {
	var size C.int
	C.string_matches(s.cptr, nil, &size)
	ptrs := make([]*C.YR_MATCH, int(size))
	if size == 0 {
		return
	}
	C.string_matches(s.cptr, &ptrs[0], &size)
	for _, ptr := range ptrs {
		matches = append(matches, Match{ptr, s.rules})
	}
	return
}

// Base returns the base offset of the memory block in which the
// string match occurred.
func (m *Match) Base() int64 {
	return int64(m.cptr.base)
}

// Offset returns the offset at which the string match occurred.
func (m *Match) Offset() int64 {
	return int64(m.cptr.offset)
}

func (r *Rule) getMatchStrings() (matchstrings []MatchString) {
	for _, s := range r.Strings() {
		for _, m := range s.Matches() {
			matchstrings = append(matchstrings, MatchString{
				Name:   s.Identifier(),
				Base:   uint64(m.Base()),
				Offset: uint64(m.Offset()),
				Data:   m.Data(),
			})
		}
	}
	return
}
