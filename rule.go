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

static const char* rule_namespace(YR_RULE* r) {
	return r->ns->name;
}

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

static int32_t meta(YR_META *m, const char** identifier, char** string, int64_t *integer) {
	*identifier = m->identifier;
	*string = m->string;
	*integer = m->integer;
	return m->type;
}
*/
import "C"

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
		var n C.int64_t
		switch C.meta(m, &id, &str, &n) {
		case C.META_TYPE_NULL:
			metas[C.GoString(id)] = nil
		case C.META_TYPE_STRING:
			metas[C.GoString(id)] = C.GoString(str)
		case C.META_TYPE_INTEGER:
			metas[C.GoString(id)] = int(n)
		case C.META_TYPE_BOOLEAN:
			metas[C.GoString(id)] = n != 0
		}
	}
	return
}
