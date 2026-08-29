package domain_test

import (
	"testing"

	"github.com/eitanity/kanonarion/internal/native/domain"
)

func TestIsNativeSource(t *testing.T) {
	native := []string{
		"sqlite3-binding.c", "sqlite3-binding.h", "a/b/impl.cc", "impl.cpp", "impl.cxx",
		"api.hh", "api.hpp", "api.hxx", "ca.m", "ca.mm", "zunk2.f", "D1MACH.F", "mod.f90",
	}
	for _, f := range native {
		if !domain.IsNativeSource(f) {
			t.Errorf("IsNativeSource(%q) = false, want true", f)
		}
	}
	// Assembly is excluded by decision: a .s in a Go package directory is
	// ordinarily Go's own assembler input, and the extension does not tell the
	// two apart.
	notNative := []string{"main.go", "asm.s", "asm.S", "README.md", "Makefile", "lib.a", "c"}
	for _, f := range notNative {
		if domain.IsNativeSource(f) {
			t.Errorf("IsNativeSource(%q) = true, want false", f)
		}
	}
}

func TestIsBuildableGoSource(t *testing.T) {
	if !domain.IsBuildableGoSource("sqlite3.go") {
		t.Error("a non-test .go file must decide whether its package uses cgo")
	}
	// A package whose only import "C" is in a test file compiles its C into the
	// test binary and into nothing a consumer ships.
	if domain.IsBuildableGoSource("sqlite3_test.go") {
		t.Error("a _test.go file must not make its package count as cgo-compiled")
	}
	if domain.IsBuildableGoSource("sqlite3.c") {
		t.Error("only .go files carry Go imports")
	}
}

func TestIsIgnoredPath(t *testing.T) {
	// The go tool never compiles anything under these, so nothing under them
	// can reach a binary. This is what keeps modernc.org/sqlite — a pure-Go
	// transpilation whose only .c files sit under testdata/ — out of the
	// results entirely.
	ignored := []string{
		"testdata/mptest.c", "testdata/tcl/atrc.c",
		"_example/mod_regexp/sqlite3_mod_regexp.c",
		"_example/mod_vtable/picojson.h",
		".github/scripts/helper.c",
		"a/testdata/b/c.c",
	}
	for _, f := range ignored {
		if !domain.IsIgnoredPath(f) {
			t.Errorf("IsIgnoredPath(%q) = false, want true", f)
		}
	}
	kept := []string{
		"sqlite3-binding.c", "unix/gccgo_c.c",
		"example/movingtriangle/internal/ca/ca.m",
		"mathext/internal/amos/amoslib/d1mach.f",
	}
	for _, f := range kept {
		if domain.IsIgnoredPath(f) {
			t.Errorf("IsIgnoredPath(%q) = true, want false", f)
		}
	}
	// A file whose own name begins with "_" is still compiled when its
	// directory is not ignored: the rule is about path elements, and the
	// filename is not one of them.
	if domain.IsIgnoredPath("_helper.c") {
		t.Error(`IsIgnoredPath("_helper.c") = true: the rule reads directories, not file names`)
	}
}

func TestDeclaresCgo(t *testing.T) {
	if !domain.DeclaresCgo([]string{"database/sql/driver", "C", "unsafe"}) {
		t.Error(`an import set containing "C" declares cgo`)
	}
	if domain.DeclaresCgo([]string{"modernc.org/libc", "unsafe"}) {
		t.Error("a pure-Go import set must not declare cgo")
	}
	if domain.DeclaresCgo(nil) {
		t.Error("an empty import set must not declare cgo")
	}
	// A package path that merely ends in C is a different package.
	if domain.DeclaresCgo([]string{"example.com/C"}) {
		t.Error(`only the pseudo-package "C" declares cgo`)
	}
}

func TestDirOf(t *testing.T) {
	for path, want := range map[string]string{
		"sqlite3-binding.c":            ".",
		"unix/gccgo_c.c":               "unix",
		"example/internal/ca/ca.m":     "example/internal/ca",
		"arrow/cdata/trampoline.c":     "arrow/cdata",
		"x/mongo/driver/gss_wrapper.h": "x/mongo/driver",
	} {
		if got := domain.DirOf(path); got != want {
			t.Errorf("DirOf(%q) = %q, want %q", path, got, want)
		}
	}
}
