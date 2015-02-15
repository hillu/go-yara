#include <stddef.h>
#include <yara/stream.h>

size_t stream_read(void* ptr, size_t size, size_t nmemb, void* user_data) {
  return streamRead(ptr, size, nmemb, user_data);
}

size_t stream_write(void* ptr, size_t size, size_t nmemb, void* user_data) {
  return streamWrite(ptr, size, nmemb, user_data);
}
