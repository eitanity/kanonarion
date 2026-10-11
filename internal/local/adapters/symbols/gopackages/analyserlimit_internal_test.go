package gopackages

import (
	"testing"

	"golang.org/x/tools/go/packages"
)

// The two errors a go1.26-built binary attached to a go 1.27 package, as
// measured, are read as the binary's limit; a compile error is not.
func TestAnalyserLimit_ReadsTheLoadersOwnErrors(t *testing.T) {
	t.Parallel()
	dep := &packages.Package{ID: "example.com/dep", Errors: []packages.Error{{
		Pos: "-", Msg: "This application uses version go1.26 of the source-processing packages but runs version go1.27 of 'go list'.",
	}}}
	root := &packages.Package{ID: "example.com/probe", Imports: map[string]*packages.Package{"example.com/dep": dep},
		Errors: []packages.Error{{Pos: "main.go:1:1", Msg: "package requires newer Go version go1.27 (application built with go1.26)"}}}
	if l, ok := analyserLimit([]*packages.Package{root}); !ok || l.Required != "go1.27" || l.Built != "go1.26" {
		t.Errorf("analyserLimit = %+v, %v; want go1.27 over go1.26", l, ok)
	}
	broken := &packages.Package{ID: "example.com/b", Errors: []packages.Error{{Pos: "b.go:1:1", Msg: "undefined: x"}}}
	if _, ok := analyserLimit([]*packages.Package{broken}); ok {
		t.Error("a compile error was read as the analyser limit")
	}
}
