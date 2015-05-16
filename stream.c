/*
  Copyright © 2015 Hilko Bengen <bengen@hilluzination.de>. All rights reserved.
  Use of this source code is governed by the license that can be
  found in the LICENSE file.
*/

#include <stddef.h>
#include <yara/stream.h>
#include "_cgo_export.h"

size_t stream_read(void* ptr, size_t size, size_t nmemb, void* user_data) {
  return streamRead(ptr, size, nmemb, user_data);
}

size_t stream_write(void* ptr, size_t size, size_t nmemb, void* user_data) {
  return streamWrite(ptr, size, nmemb, user_data);
}
