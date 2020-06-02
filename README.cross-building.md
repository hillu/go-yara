# Cross-building _go-yara_

_go-yara_ can be cross-built for a different CPU
architecture/operating system platform, provided a C cross-compiler
for the target platform is available to be used by the _cgo_ tool.

After the _yara_ library has been built using the proper C
cross-compiler through the usual `configure / make / make install`
steps, _go-yara_ can be built and installed. The following environment
variables need to be set when running `go build` or `go install`:

- `GOOS`, `GOARCH` indicate the cross compilation target.
- `CGO_ENABLED` has to be set to 1 beacuse it defaults to 0 when
  cross-compiling.
- `CC` has to be set to the C cross compiler. (It defaults to the
  system C compiler, usually gcc).
- `PKG_CONFIG_PATH` has to be set to the _pkg-config_ directory where
  the `yara.pc` file has been installed. (Alternatively, the
  `yara_no_pkg_config` build tag can be used togethere with
  `CGO_CFLAGS` and `CGO_LDFLAGS` environment variables.)

## Example: Cross-building for Windows on Debian-based systems

Install the MinGW C compiler `gcc-mingw-w64-i686`,
`gcc-mingw-w64-x86-64` for Win32, Win64, respectively.

Build _libyara_ and _go-yara_ for Win32:
``` shell
( cd ${YARA_BUILD_WIN32} && \
  ${YARA_SRC}/configure --host=i686-w64-mingw32 --prefix=${PREFIX_WIN32} )
make -C ${YARA_BUILD_WIN32}
make -C ${YARA_BUILD_WIN32} install

GOOS=windows GOARCH=386 CGO_ENABLED=1 \
  CC=i686-w64-mingw32-gcc \
  PKG_CONFIG_PATH=${PREFIX_WIN32}/lib/pkgconfig \
      go install -ldflags '-extldflags "-static"' github.com/hillu/go-yara
```

Build _libyara_ and _go-yara_ for Win64:
``` shell
( cd ${YARA_BUILD_WIN64} && \
  ${YARA_SRC}/configure --host=x86_64-w64-mingw32 --prefix=${PREFIX_WIN64} )
make -C ${YARA_BUILD_WIN64}
make -C ${YARA_BUILD_WIN64} install

GOOS=windows GOARCH=amd64 CGO_ENABLED=1 \
  CC=i686-w64-mingw32-gcc \
  PKG_CONFIG_PATH=${PREFIX_WIN64}/lib/pkgconfig \
      go install -ldflags '-extldflags "-static"' github.com/hillu/go-yara
```
