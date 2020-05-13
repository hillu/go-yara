![Logo](/goyara-logo.png)

# go-yara

[![GoDoc](https://godoc.org/github.com/hillu/go-yara?status.svg)](https://godoc.org/github.com/hillu/go-yara)
[![Travis](https://travis-ci.org/hillu/go-yara.svg?branch=master)](https://travis-ci.org/hillu/go-yara)
[![Go Report Card](https://goreportcard.com/badge/github.com/hillu/go-yara)](https://goreportcard.com/report/github.com/hillu/go-yara)

Go bindings for [YARA](https://virustotal.github.io/yara/), staying as
close as sensible to the library's C-API while taking inspiration from
the `yara-python` implementation.

## Installation

### Unix

On a Unix system with _libyara_, its header files, and _pkg-config_
installed, the following should simply work, provided that `GOPATH` is
set:

```
go get github.com/hillu/go-yara
go install github.com/hillu/go-yara
```

The _pkg-config_ program should be able to output the correct compiler
and linker flags from the `yara.pc` file that has been generated and
installed by _YARA_'s build system. If _libyara_ has been installed to
a custom location, the `PKG_CONFIG_PATH` environment variable can be
used to point _pkg-config_ at the right `yara.pc` file. If
_pkg-config_ cannot be used at all, please refer to the "Build Tags" section.

Linker errors in the compiler output such as

    undefined reference to `yr_compiler_add_file'

indicate that the linker is probably looking at an old version of
_libyara_. Please refer to the "Build Tags" section below on how to
work with old YARA versions.

### Cross-building

_go-yara_ can be cross-built for a different CPU
architecture/operating system platform, provided a C cross-compiler
for the target platform is available to be used by the _cgo_ tool.

After the _yara_ library has been built from its source tree using the
proper C cross-compiler through the usual `configure / make / make
install` steps, _go-yara_ can be built and installed. Some environment
variables need to be set when running `go build` or `go install`:

- `GOOS`, `GOARCH` indicate the cross compilation target.
- `CGO_ENABLED` has to be set to 1 beacuse it defaults to 0 when
  cross-compiling.
- `CC` has to specified because _cgo_ has no prior knowledge about
  what C compiler to chose for cross-compiling. (it defaults to the
  system C compiler, usually gcc).
- `PKG_CONFIG_PATH` has to be set in so that _pkg-config_ which is run
  by _cgo_ for determining compiler and linker flags can find the
  `yara.pc` file generated while cross-building _yara_.

#### Example: Cross-building for Windows on Debian/streach

Install the MinGW C compiler `gcc-mingw-w64-i686`,
`gcc-mingw-w64-x86-64` for Win32, Win64, respectively.

Build _libyara_ and _go-yara_ for Win32:
```
$ cd ${YARA_SRC} \
  && ./bootstrap.sh \
  && ./configure --host=i686-w64-mingw32 --disable-magic --disable-cuckoo --without-crypto --prefix=${YARA_SRC}/i686-w64-mingw32 \
  && make -C ${YARA_SRC} \
  && make -C ${YARA_SRC} install 
$ GOOS=windows GOARCH=amd64 CGO_ENABLED=1 \
  CC=i686-w64-mingw32-gcc \
  PKG_CONFIG_PATH=${YARA_SRC}/i686-w64-mingw32/lib/pkgconfig \
  go inxstall -ldflags '-extldflags "-static"' github.com/hillu/go-yara
```

Build _libyara_ and _go-yara_ for Win64:
```
$ cd ${YARA_SRC} \
  && ./bootstrap.sh \
  && ./configure --host=x86_64-w64-mingw32 --disable-magic --disable-cuckoo --without-crypto --prefix=${YARA_SRC}/x86_64-w64-mingw32 \
  && make -C ${YARA_SRC} \
  && make -C ${YARA_SRC} install 
$ GOOS=windows GOARCH=amd64 CGO_ENABLED=1 \
  CC=x86_64-w64-mingw32-gcc \
  PKG_CONFIG_PATH=${YARA_SRC}/x86_64-w64-mingw32/lib/pkgconfig \
  go install -ldflags '-extldflags "-static"' github.com/hillu/go-yara
```

## Build Tags

_go-yara_ is tested with the latest stable version of YARA, currently
3.11. If you need to to build with an older version of YARA, certain
features that are not present in older versions can be excluded by
passing a build tag such as `yara3.7`, `yara3.6`, `yara3.5`, etc.. You
also need to pass the tag when you build your own project.

The build tag `yara_static` can be used to tell the Go toolchain to
run _pkg-config_ with the `--static` switch. This is not enough for a
static build; the appropriate linker flags (e.g. `-extldflags
"-static"`) still need to be passed to the _go_ tool.

The build tag `no_pkg_config` can be used to tell the Go toolchain not
to use _pkg-config_'s output. In this case, any compiler or linker
flags have to be set via the `CGO_CFLAGS` and `CGO_LDFLAGS`
environment variables, e.g.:

```
export CGO_CFLAGS="-I${YARA_SRC}/libyara/include"
export CGO_LDFLAGS="-L${YARA_SRC}/libyara/.libs -lyara"
go install -tags no_pkg_config github.com/hillu/go-yara
```

## License

BSD 2-clause, see LICENSE file in the source distribution.

## Author

Hilko Bengen <bengen@hilluzination.de>
