/*
  Copyright © 2015 Hilko Bengen <bengen@hilluzination.de>. All rights reserved.
  Use of this source code is governed by the license that can be
  found in the LICENSE file.
*/

#include <yara.h>

void compiler_callback(int error_level, const char* file_name, int line_number, const char* message) {
  compilerCallback(error_level, file_name, line_number, message);
}
