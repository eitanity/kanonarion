package gosource_test

import (
	"slices"
	"strings"
	"testing"

	"github.com/eitanity/kanonarion/internal/native/adapters/gosource"
	"github.com/eitanity/kanonarion/internal/native/domain"
)

func TestReader_ReadsTheImportBlock(t *testing.T) {
	src := []byte(`package sqlite3

import (
	"database/sql"
	_ "unsafe"
)
`)
	got, err := gosource.New().ImportPaths("sqlite3.go", src)
	if err != nil {
		t.Fatalf("ImportPaths: %v", err)
	}
	want := []string{"database/sql", "unsafe"}
	if !slices.Equal(got, want) {
		t.Errorf("ImportPaths = %v, want %v", got, want)
	}
	if domain.DeclaresCgo(got) {
		t.Error("a pure-Go file must not read as declaring cgo")
	}
}

// The cgo preamble is a comment attached to the import, so a reader that
// stopped at the first non-import token would miss the declaration entirely.
func TestReader_ReadsCgoThroughItsPreamble(t *testing.T) {
	src := []byte(`package sqlite3

/*
#include <sqlite3-binding.h>
#include <stdlib.h>
*/
import "C"

import "database/sql"
`)
	got, err := gosource.New().ImportPaths("sqlite3.go", src)
	if err != nil {
		t.Fatalf("ImportPaths: %v", err)
	}
	if !domain.DeclaresCgo(got) {
		t.Fatalf("ImportPaths = %v, and the file declares cgo", got)
	}
}

// Parsing stops at the end of the import block, so a file whose body does not
// compile still answers what it imports.
func TestReader_AnswersDespiteAnUnparseableBody(t *testing.T) {
	src := []byte("package p\n\nimport \"C\"\n\nfunc broken( { }\n")
	got, err := gosource.New().ImportPaths("p.go", src)
	if err != nil {
		t.Fatalf("ImportPaths: %v", err)
	}
	if !domain.DeclaresCgo(got) {
		t.Errorf("ImportPaths = %v, want the cgo declaration to survive an unparseable body", got)
	}
}

// A header that cannot be parsed is an error, never an empty import set:
// reading it as importing nothing would read it as not using cgo, and would
// drop a whole native component in silence.
func TestReader_RefusesAnUnparseableHeader(t *testing.T) {
	if _, err := gosource.New().ImportPaths("p.go", []byte("this is not Go at all\n")); err == nil {
		t.Fatal("ImportPaths accepted a file with no package clause; a silent empty import set reads as not-cgo")
	}
}

// The preamble is what carries the `#cgo` directives, and the directive lines
// must come back verbatim: they are recorded as the evidence for a claim about
// what the binary links.
func TestReader_ReadsTheCgoPreambleVerbatim(t *testing.T) {
	src := []byte(`package sqlite3

/*
#cgo linux,amd64 LDFLAGS: ${SRCDIR}/../target/release/libpdf_oxide.a -lm
#include <stdlib.h>
*/
import "C"

import "database/sql"
`)
	got, err := gosource.New().CgoPreamble("sqlite3.go", src)
	if err != nil {
		t.Fatalf("CgoPreamble: %v", err)
	}
	want := "#cgo linux,amd64 LDFLAGS: ${SRCDIR}/../target/release/libpdf_oxide.a -lm"
	if !strings.Contains(got, want) {
		t.Errorf("CgoPreamble = %q, want it to carry %q verbatim", got, want)
	}
	libs := domain.LinkedLibrariesIn("sqlite3.go", got)
	if len(libs) != 2 || libs[0].Name != "pdf_oxide" || libs[1].Name != "m" {
		t.Errorf("linked = %+v, want the archive and the C runtime", libs)
	}
}

// A `//`-comment preamble is the other spelling cgo accepts, and a directive in
// it must be read the same way.
func TestReader_ReadsALineCommentPreamble(t *testing.T) {
	src := []byte("package p\n\n// #cgo LDFLAGS: -licui18n\n// #include <unicode/ucol.h>\nimport \"C\"\n")
	got, err := gosource.New().CgoPreamble("p.go", src)
	if err != nil {
		t.Fatalf("CgoPreamble: %v", err)
	}
	libs := domain.LinkedLibrariesIn("p.go", got)
	if len(libs) != 1 || libs[0].Name != "icui18n" {
		t.Errorf("linked = %+v, want icui18n", libs)
	}
}

// The preamble is the comment attached to `import "C"`, not any comment in the
// file. A block that is not attached to it is not a build directive, and
// reading it as one would name a library the build never links.
func TestReader_IgnoresACommentNotAttachedToTheImport(t *testing.T) {
	src := []byte(`package p

/*
#cgo LDFLAGS: -lnot_the_preamble
*/

// unrelated
import "C"
`)
	got, err := gosource.New().CgoPreamble("p.go", src)
	if err != nil {
		t.Fatalf("CgoPreamble: %v", err)
	}
	if libs := domain.LinkedLibrariesIn("p.go", got); len(libs) != 0 {
		t.Errorf("linked = %+v, want none: a detached comment is not the preamble", libs)
	}
}

// A grouped import block attaches the preamble to the spec, not the
// declaration, and the two must not be confused.
func TestReader_ReadsThePreambleInsideAnImportGroup(t *testing.T) {
	src := []byte(`package p

import (
	"database/sql"

	// #cgo LDFLAGS: -lsqlite3
	"C"
)
`)
	got, err := gosource.New().CgoPreamble("p.go", src)
	if err != nil {
		t.Fatalf("CgoPreamble: %v", err)
	}
	libs := domain.LinkedLibrariesIn("p.go", got)
	if len(libs) != 1 || libs[0].Name != "sqlite3" {
		t.Errorf("linked = %+v, want sqlite3", libs)
	}
}

// A file that does not use cgo has no preamble, and that is a measured answer
// rather than a failure.
func TestReader_APureGoFileHasNoPreamble(t *testing.T) {
	got, err := gosource.New().CgoPreamble("p.go", []byte("package p\n\nimport \"fmt\"\n"))
	if err != nil {
		t.Fatalf("CgoPreamble: %v", err)
	}
	if got != "" {
		t.Errorf("CgoPreamble = %q, want empty", got)
	}
}

// A cgo file with no preamble at all links nothing it declares, which is not
// the same as a file that could not be read.
func TestReader_CgoWithNoPreambleIsEmptyNotAnError(t *testing.T) {
	got, err := gosource.New().CgoPreamble("p.go", []byte("package p\n\nimport \"C\"\n"))
	if err != nil {
		t.Fatalf("CgoPreamble: %v", err)
	}
	if got != "" {
		t.Errorf("CgoPreamble = %q, want empty", got)
	}
}

// A header that cannot be parsed is an error here too: an empty preamble would
// read as "links nothing", which is the silence this context exists to remove.
func TestReader_CgoPreambleRefusesAnUnparseableHeader(t *testing.T) {
	if _, err := gosource.New().CgoPreamble("p.go", []byte("this is not Go at all\n")); err == nil {
		t.Fatal("CgoPreamble accepted a file with no package clause")
	}
}
