package domain

import (
	"path"
	"strings"
)

// CgoImportPath is the pseudo-package a Go file imports to declare that its
// package is compiled with cgo.
const CgoImportPath = "C"

// nativeExtensions are the source extensions the cgo build hands to the C,
// C++, Objective-C or Fortran compiler when it builds a package.
//
// Assembly is deliberately absent. A .s or .S file in a Go package directory is
// ordinarily input to Go's own assembler, and telling that apart from
// cgo-preprocessed assembly needs the build's rules rather than the extension.
// Recording it as a native component would state something the extension does
// not establish.
var nativeExtensions = map[string]bool{
	".c": true, ".cc": true, ".cpp": true, ".cxx": true,
	".h": true, ".hh": true, ".hpp": true, ".hxx": true,
	".m": true, ".mm": true,
	".f": true, ".F": true, ".f90": true,
}

// IsNativeSource reports whether rel is a file the cgo build compiles as
// native code, judged by its extension alone.
func IsNativeSource(rel string) bool {
	return nativeExtensions[path.Ext(rel)]
}

// IsBuildableGoSource reports whether rel is a Go file whose imports decide
// whether its package uses cgo.
//
// Test files are excluded. A package whose only `import "C"` is in a _test.go
// file compiles its C sources into the test binary and into nothing else, and
// the scope of this context is what a consumer's binary ends up containing.
func IsBuildableGoSource(rel string) bool {
	return strings.HasSuffix(rel, ".go") && !strings.HasSuffix(rel, "_test.go")
}

// IsIgnoredPath reports whether the go tool ignores rel outright, so nothing
// under it is ever compiled into any binary.
//
// The rules are the go tool's own: a path element beginning with "_" or "." is
// not part of any package, and a "testdata" element holds fixtures rather than
// code. This is what keeps a pure-Go module out of the results even when it
// ships C — modernc.org/sqlite is a transpilation of SQLite that links no C at
// all, and the .c files in its zip sit under testdata/ where the toolchain will
// never look at them.
func IsIgnoredPath(rel string) bool {
	for _, seg := range strings.Split(path.Dir(rel), "/") {
		if seg == "." || seg == "" {
			continue
		}
		if seg == "testdata" || strings.HasPrefix(seg, "_") || strings.HasPrefix(seg, ".") {
			return true
		}
	}
	return false
}

// DeclaresCgo reports whether an import set makes its package a cgo package.
//
// `import "C"` is the test because it is the only thing that makes the go tool
// hand a directory's C sources to a C compiler. Shipping a .c file does not:
// a module can carry C it never builds, and several in any real store do. The
// import is a declaration by the package itself, visible in the artefact, and
// needs neither a toolchain nor a build to read.
func DeclaresCgo(imports []string) bool {
	for _, imp := range imports {
		if imp == CgoImportPath {
			return true
		}
	}
	return false
}

// DirOf returns the package directory a module-relative path sits in, using
// "." for the module root, so the cgo declaration and the native sources it
// governs are keyed the same way.
func DirOf(rel string) string {
	return path.Dir(rel)
}
