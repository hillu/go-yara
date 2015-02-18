# go-yara

[![GoDoc](https://godoc.org/github.com/hillu/go-yara?status.svg)](https://godoc.org/github.com/hillu/go-yara)

Go bindings for [YARA](http://plusvic.github.io/yara/), staying as
close as sensible to the library's C-API while taking inspiration from
the `yara-python` implementation.

The current master of YARA after 3.3.0, with read stream support (merged on 2015-02-12) is required.

## Installation

    go get github.com/hillu/go-yara

On a Unix system with libyara properly installed, this should work,
provided that `GOPATH` is set:

    go install github.com/hillu/go-yara

Depending on what location libyara and its headers have been
installed, modifications to `cgo.go` may be needed.

I have not yet built go-yara *on* Windows, only used the MinGW-w64
provided on Debian so far. This configure line for cross-compiling
yara looked like this:

    ./configure --host=i686-w64-mingw32 --disable-magic --disable-cuckoo --without-crypto CFLAGS=-D__MINGW_USE_VC2005_COMPAT

I found that the `CFLAGS` parameter was necessary to avoid problems
due to a missing `time32` symbol when linking 32bit Windows
executables.

## License

BSD 2-clause, see LICENSE file in the source distribution.

## Author

Hilko Bengen <bengen@hilluzination.de>
