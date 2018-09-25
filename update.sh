#!/bin/bash

# This script updates the current repository to the latest version of
# yara.
git submodule init
git submodule update

# Apply patches to submodule tree
cd yara_src/
echo Resetting the yara source tree.
git reset --hard

echo Applying patches.
patch -p1 < ../yara_src.diff
cd -

echo Copying files to golag tree.
cp yara_src/libyara/*.c .
cp yara_src/libyara/*.h .
cp yara_src/libyara/include/yara.h .
cp -r yara_src/libyara/include/yara/ .
cp -r yara_src/libyara/modules/ .
cp -r yara_src/libyara/modules/tests* .
cp -r yara_src/libyara/modules/pe* .
cp -r yara_src/libyara/modules/elf* .
cp -r yara_src/libyara/modules/math* .
cp -r yara_src/libyara/modules/time* .

cp yara_src/libyara/proc/linux.c proc_linux.c
cp yara_src/libyara/proc/windows.c proc_windows.c
cp yara_src/libyara/proc/mach.c proc_darwin.c
