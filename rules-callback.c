/*
  Copyright © 2015-2017 Hilko Bengen <bengen@hilluzination.de>
  All rights reserved.

  Use of this source code is governed by the license that can be
  found in the LICENSE file.
*/

#include <yara.h>
#include "_cgo_export.h"

int stdScanCallback(int message, void *message_data, void *user_data) {
  if (message == CALLBACK_MSG_RULE_MATCHING) {
    YR_RULE* rule = (YR_RULE*) message_data;
    char* ns = rule->ns->name;
    if(ns == NULL) {
      ns = "";
    }
    newMatch(user_data, ns, (char*)rule->identifier);
    YR_META* meta;
    yr_rule_metas_foreach(rule, meta) {
      switch (meta->type) {
      case META_TYPE_INTEGER:
        addMetaInt(user_data, (char*)meta->identifier, meta->integer);
        break;
      case META_TYPE_STRING:
        addMetaString(user_data, (char*)meta->identifier, meta->string);
        break;
      case META_TYPE_BOOLEAN:
        addMetaBool(user_data, (char*)meta->identifier, meta->integer);
        break;
      }
    }
    const char* tag_name;
    yr_rule_tags_foreach(rule, tag_name) {
      addTag(user_data, (char*)tag_name);
    }
    YR_STRING* string;
    YR_MATCH* m;
    yr_rule_strings_foreach(rule, string) {
      yr_string_matches_foreach(string, m) {
#if YR_VERSION_HEX >= 0x030500
        /* YR_MATCH members have been renamed in YARA 3.5 */
        addString(user_data, string->identifier, m->offset, (char*)m->data, (int)m->data_length);
#else
        addString(user_data, string->identifier, m->offset, m->data, (int)m->length);
#endif
      }
    }
  }
  return CALLBACK_CONTINUE;
}
