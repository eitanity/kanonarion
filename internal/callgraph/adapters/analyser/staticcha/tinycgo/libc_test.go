package tinycgo

import (
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

// The want column is TinyGo v0.44.0's compileopts/config.go LibcCFlags (and
// v0.43.0's, which is the same), with TINYGOROOT /tg and the cache /c; the
// directory names are LibraryPath's (Copyright (c) 2018-2026 The TinyGo
// Authors, BSD-3-Clause).
func TestLibcCFlags_AreTinyGos(t *testing.T) {
	for _, tc := range []struct {
		name          string
		spec          TargetSpec
		triple, arch  string
		want          []string
		wantCacheIncl string
	}{
		{"darwin-libSystem", TargetSpec{Libc: "darwin-libSystem", CPU: "x86-64"}, "x86_64-apple-macosx10.12.0", "amd64",
			[]string{"-nostdlibinc", "-isystem", "/tg/lib/macos-minimal-sdk/src/usr/include"}, ""},
		{"picolibc", TargetSpec{Libc: "picolibc", CPU: "cortex-m0plus"}, "thumbv6m-unknown-unknown-eabi", "arm",
			[]string{"-nostdlibinc",
				"-isystem", "/c/picolibc-thumbv6m-unknown-unknown-eabi-cortex-m0plus-v2/include",
				"-isystem", "/tg/lib/picolibc/libc/include",
				"-isystem", "/tg/lib/picolibc/libc/stdio",
				"-D__PICOLIBC_ERRNO_FUNCTION=__errno_location"},
			"/c/picolibc-thumbv6m-unknown-unknown-eabi-cortex-m0plus-v2/include"},
		{"musl", TargetSpec{Libc: "musl", CPU: "generic", SoftFloat: true}, "armv7-unknown-linux-gnueabihf", "arm",
			[]string{"-nostdlibinc",
				"-isystem", "/c/musl-armv7-unknown-linux-gnueabihf-generic-softfloat-v3/include",
				"-isystem", "/tg/lib/musl/arch/arm",
				"-isystem", "/tg/lib/musl/arch/generic",
				"-isystem", "/tg/lib/musl/include"},
			"/c/musl-armv7-unknown-linux-gnueabihf-generic-softfloat-v3/include"},
		{"wasi-libc", TargetSpec{Libc: "wasi-libc", CPU: "generic"}, "wasm32-unknown-wasi", "wasm",
			[]string{"-nostdlibinc", "-isystem", "/c/wasi-libc-wasm32-unknown-wasi-generic/include"},
			"/c/wasi-libc-wasm32-unknown-wasi-generic/include"},
		{"wasi-libc with boehm", TargetSpec{Libc: "wasi-libc", CPU: "generic", GC: "boehm"}, "wasm32-unknown-wasi", "wasm",
			[]string{"-nostdlibinc", "-isystem", "/c/wasi-libc+malloc-wasm32-unknown-wasi-generic/include"},
			"/c/wasi-libc+malloc-wasm32-unknown-wasi-generic/include"},
		{"wasmbuiltins", TargetSpec{Libc: "wasmbuiltins", CPU: "generic"}, "wasm32-unknown-unknown", "wasm", nil, ""},
		{"mingw-w64 386", TargetSpec{Libc: "mingw-w64", CPU: "pentium4"}, "i686-unknown-windows-gnu", "386",
			[]string{"-nostdlibinc",
				"-isystem", "/c/mingw-w64-i686-unknown-windows-gnu-pentium4/include",
				"-isystem", "/tg/lib/mingw-w64/mingw-w64-headers/crt",
				"-isystem", "/tg/lib/mingw-w64/mingw-w64-headers/include",
				"-isystem", "/tg/lib/mingw-w64/mingw-w64-headers/defaults/include",
				"-D__MSVCRT_VERSION__=0x700", "-D_WIN32_WINNT=0x0501"},
			"/c/mingw-w64-i686-unknown-windows-gnu-pentium4/include"},
		{"mingw-w64 amd64", TargetSpec{Libc: "mingw-w64", CPU: "x86-64", ABI: "lp64"}, "x86_64-unknown-windows-gnu", "amd64",
			[]string{"-nostdlibinc",
				"-isystem", "/c/mingw-w64-x86_64-unknown-windows-gnu-x86-64-lp64/include",
				"-isystem", "/tg/lib/mingw-w64/mingw-w64-headers/crt",
				"-isystem", "/tg/lib/mingw-w64/mingw-w64-headers/include",
				"-isystem", "/tg/lib/mingw-w64/mingw-w64-headers/defaults/include",
				"-D_UCRT", "-D_WIN32_WINNT=0x0a00"},
			"/c/mingw-w64-x86_64-unknown-windows-gnu-x86-64-lp64/include"},
		{"none", TargetSpec{}, "thumbv6m-unknown-unknown-eabi", "arm", nil, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			lc, err := libcCFlags(&tc.spec, "/tg", tc.triple, tc.arch, "/c")
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(lc.flags, tc.want) || lc.cacheInclude != tc.wantCacheIncl || lc.name != tc.spec.Libc {
				t.Errorf("libcCFlags = %q (cache %q), want %q (cache %q)", lc.flags, lc.cacheInclude, tc.want, tc.wantCacheIncl)
			}
		})
	}
	if _, err := libcCFlags(&TargetSpec{Libc: "newlib"}, "/tg", "x", "arm", "/c"); err == nil || !strings.Contains(err.Error(), `"newlib"`) {
		t.Errorf("an unknown libc = %v, want it refused by name", err)
	}
}

func TestCanonicalArchName(t *testing.T) {
	for triple, want := range map[string]string{
		"arm64-apple-macosx": "aarch64", "armv7-unknown-linux": "arm", "thumbv6m-unknown-unknown-eabi": "arm",
		"mipsel-unknown-linux": "mips", "x86_64-unknown-linux": "x86_64",
	} {
		if got := canonicalArchName(triple); got != want {
			t.Errorf("%s: %q, want %q", triple, got, want)
		}
	}
}

// The libc's flags follow the definition's cflags and precede the triple, as
// in TinyGo's CFlags; with no libc the flags are those of a target without.
func TestCFlags_PlaceTheLibcsFlagsAsTinyGoDoes(t *testing.T) {
	spec := &TargetSpec{CFlags: []string{"-mbulk-memory"}, CPU: "generic", Libc: "wasi-libc"}
	lc, err := libcCFlags(spec, "/tg", "wasm32-unknown-wasi", "wasm", "/c")
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"-mbulk-memory", "-nostdlibinc", "-isystem", "/c/wasi-libc-wasm32-unknown-wasi-generic/include",
		"--target=wasm32-unknown-wasi", "-mcpu=generic"}
	if got := cFlags(spec, "/tg", "wasm32-unknown-wasi", "wasm", lc); !reflect.DeepEqual(got, want) {
		t.Errorf("cFlags = %q, want %q", got, want)
	}
	spec.Libc = ""
	lc, err = libcCFlags(spec, "/tg", "wasm32-unknown-wasi", "wasm", "/c")
	if err != nil {
		t.Fatal(err)
	}
	if got := cFlags(spec, "/tg", "wasm32-unknown-wasi", "wasm", lc); !reflect.DeepEqual(got,
		[]string{"-mbulk-memory", "--target=wasm32-unknown-wasi", "-mcpu=generic"}) {
		t.Errorf("with no libc, cFlags = %q", got)
	}
}

func TestTinyGoCacheDir_IsTinyGosUnderTheUserCache(t *testing.T) {
	t.Setenv("XDG_CACHE_HOME", "/xdg")
	if dir, err := tinyGoCacheDir(); err != nil || dir != "/xdg/tinygo" {
		t.Errorf("tinyGoCacheDir = %q, %v", dir, err)
	}
	t.Setenv("XDG_CACHE_HOME", "")
	t.Setenv("HOME", "")
	if _, err := tinyGoCacheDir(); err == nil {
		t.Error("no cache directory was refused")
	}
}

// clang's refusal names the headers it was read with; with the libc's cache
// include directory absent it is the host's, naming the directory.
func TestCompiler_RejectedStatesTheLibc(t *testing.T) {
	diag := errors.New("main.go:4:10: fatal error: 'stdio.h' file not found")
	absent := filepath.Join(t.TempDir(), "wasi-libc-wasm32-unknown-wasi-generic", "include")
	c := compiler{target: "wasip1", libc: libcHeaders{name: "wasi-libc", flags: []string{"-nostdlibinc"}, cacheInclude: absent}}
	want := "TinyGo has not built wasi-libc for target wasip1 on this host: " + absent +
		" does not exist, so clang could not read the preamble of example.com/app (" + diag.Error() + ")"
	if got := c.rejected("example.com/app", diag); got.Error() != want || !errors.Is(got, diag) {
		t.Errorf("absent: %v, want %q", got, want)
	}
	if err := os.MkdirAll(absent, 0o750); err != nil {
		t.Fatal(err)
	}
	if got := c.rejected("example.com/app", diag).Error(); got != "clang rejected the preamble, read with TinyGo's wasi-libc headers: "+diag.Error() {
		t.Errorf("present: %v", got)
	}
	if got := (compiler{}).rejected("example.com/app", diag).Error(); got != "clang rejected the preamble, read with no libc headers: "+diag.Error() {
		t.Errorf("no libc: %v", got)
	}
}
