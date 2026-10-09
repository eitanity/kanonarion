package staticcha_test

import (
	"os/exec"
	"testing"

	"github.com/eitanity/kanonarion/internal/callgraph/domain"
)

// exportDirectiveFiles carries every directive a host build reads as a plain
// comment, so one linux load sees them all. Each function calls something so
// it is a node.
func exportDirectiveFiles() map[string]string {
	return map[string]string{
		"go.mod": "module example.com/cgtestmod\n\ngo 1.21\n",
		"exports/exports.go": `package exports

import "strings"

//go:wasmexport parse
func parse(s string) string { return strings.ToUpper(s) }

//go:export tinyExport
func tinyExport() { _ = strings.ToLower("A") }

//go:interrupt
func handleIRQ() { _ = strings.TrimSpace(" ") }

//export
func nameless() { _ = strings.Repeat("a", 1) }

type T struct{}

//export method
func (T) Method() { _ = strings.ToTitle("a") }

// plain mentions //export in prose and carries no directive.
func plain() { _ = strings.Fields("a") }
`,
		"exports/exports_test.go": `package exports

import (
	"strings"
	"testing"
)

//go:wasmexport testOnly
func testOnly() { _ = strings.ToUpper("a") }

func TestNothing(t *testing.T) {}
`,
	}
}

func TestExportDirective_RecordedOnTheNode(t *testing.T) {
	rec := analyseFiles(t, exportDirectiveFiles())

	const pkg = "example.com/cgtestmod/exports."
	tests := []struct {
		id       string
		want     domain.ExportDirective
		wantTest bool
	}{
		{id: pkg + "parse", want: domain.ExportDirective{Kind: domain.ExportWasm, Name: "parse"}},
		{id: pkg + "tinyExport", want: domain.ExportDirective{Kind: domain.ExportC, Name: "tinyExport"}},
		{id: pkg + "handleIRQ", want: domain.ExportDirective{Kind: domain.ExportInterrupt}},
		// No toolchain exports a nameless //export or a method.
		{id: pkg + "nameless"},
		{id: pkg + "(T).Method"},
		{id: pkg + "plain"},
		// A test-file directive is recorded; the test axis decides who roots at it.
		{id: pkg + "testOnly", want: domain.ExportDirective{Kind: domain.ExportWasm, Name: "testOnly"}, wantTest: true},
	}
	for _, tt := range tests {
		t.Run(tt.id, func(t *testing.T) {
			n, ok := nodeByID(rec, tt.id)
			if !ok {
				t.Fatalf("%s is not a node in the graph", tt.id)
			}
			if n.ExportDirective != tt.want {
				t.Errorf("ExportDirective = %+v, want %+v", n.ExportDirective, tt.want)
			}
			if n.IsTest != tt.wantTest {
				t.Errorf("IsTest = %v, want %v", n.IsTest, tt.wantTest)
			}
		})
	}
}

// TestExportDirective_CgoExportSurvivesCgoProcessing pins that the syntax the
// load hands over is cgo's rewritten file, and the doc comment is still on it.
func TestExportDirective_CgoExportSurvivesCgoProcessing(t *testing.T) {
	if _, err := exec.LookPath("gcc"); err != nil {
		t.Skip("no C compiler on PATH, so cgo cannot process the fixture")
	}
	rec := analyseFiles(t, map[string]string{
		"go.mod": "module example.com/cgtestmod\n\ngo 1.21\n",
		"main.go": `package main

/*
extern int goParse(int);
static int callFromC(void) { return goParse(1); }
*/
import "C"

import "strings"

//export goParse
func goParse(n C.int) C.int {
	_ = strings.ToUpper("a")
	return n
}

func main() { C.callFromC() }
`,
	})
	n, ok := nodeByID(rec, "example.com/cgtestmod.goParse")
	if !ok {
		t.Fatal("goParse is not a node in the graph")
	}
	want := domain.ExportDirective{Kind: domain.ExportC, Name: "goParse"}
	if n.ExportDirective != want {
		t.Errorf("ExportDirective = %+v, want %+v", n.ExportDirective, want)
	}
}
