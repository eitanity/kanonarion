package godoc_test

import (
	"context"
	"strings"
	"testing"
	"testing/fstest"

	"github.com/eitanity/kanonarion/internal/gotoolchain"
	domain2 "github.com/eitanity/kanonarion/internal/iface/domain"
)

// unreadable stands in for a generic method, which a go1.26 parser refuses: the
// suite runs on one toolchain, so it uses a file no parser reads, under a
// directive newer than the Go the seam reports.
const unreadable = "package m\n\nfunc (b Box) Map[T any](f func(int) T) T { return f(b.V) \n"

func limitTree(directive string) fstest.MapFS {
	return fstest.MapFS{
		"go.mod":      &fstest.MapFile{Data: []byte("module example.com/m\n\ngo " + directive + "\n")},
		"box.go":      &fstest.MapFile{Data: []byte("package m\n\n// Box holds a value.\ntype Box struct{ V int }\n")},
		"genmeth.go":  &fstest.MapFile{Data: []byte(unreadable)},
		"sub/only.go": &fstest.MapFile{Data: []byte(unreadable)},
		"ok/ok.go":    &fstest.MapFile{Data: []byte("package ok\n\n// Ok is fine.\nfunc Ok() {}\n")},
	}
}

// Under a go directive newer than this binary's Go, a file the parser refuses
// is this binary's limit: named on the record, not filed as the module's
// parse failure, and the package it belongs to still listed.
func TestExtract_AnalyserLimitIsNotAModuleParseFailure(t *testing.T) {
	restore := gotoolchain.SetAnalysingGo("go1.26.6")
	defer restore()

	r, err := makeExtractor().Extract(context.Background(), limitTree("1.27.2"), coord(t))
	if err != nil {
		t.Fatalf("Extract: %v", err)
	}
	if r.AnalyserLimit == nil {
		t.Fatalf("no analyser limit recorded; detail %q", r.FailureDetail)
	}
	want := gotoolchain.AnalyserLimit{Required: "go1.27.2", Built: "go1.26.6"}
	if r.AnalyserLimit.Limit != want || strings.Join(r.AnalyserLimit.Files, ",") != "genmeth.go,sub/only.go" {
		t.Errorf("analyser limit = %+v, want %+v over genmeth.go,sub/only.go", *r.AnalyserLimit, want)
	}
	for _, p := range r.Packages {
		if len(p.ParseFailures) > 0 {
			t.Errorf("%s carries parse failures %v: the module was not judged", p.ImportPath, p.ParseFailures)
		}
	}
	if r.OverallStatus != domain2.InterfaceStatusPartial {
		t.Errorf("status = %s, want Partial: the API is short of the unread files", r.OverallStatus)
	}
	if !strings.HasPrefix(r.FailureDetail, "not analysed: 2 files (genmeth.go, sub/only.go)") ||
		strings.Contains(r.FailureDetail, "parse failures") {
		t.Errorf("detail = %q", r.FailureDetail)
	}
	paths := map[string]bool{}
	for _, p := range r.Packages {
		paths[p.ImportPath] = true
	}
	if !paths["example.com/m"] || !paths["example.com/m/sub"] || !paths["example.com/m/ok"] {
		t.Errorf("packages = %v, want all three listed", paths)
	}
}

// The control: the same refusal under a directive this binary's Go covers is
// the module's own parse failure, exactly as before.
func TestExtract_ParseFailureUnderAnOlderDirectiveIsTheModules(t *testing.T) {
	restore := gotoolchain.SetAnalysingGo("go1.26.6")
	defer restore()

	r, err := makeExtractor().Extract(context.Background(), limitTree("1.26.6"), coord(t))
	if err != nil {
		t.Fatalf("Extract: %v", err)
	}
	if r.AnalyserLimit != nil {
		t.Errorf("analyser limit = %+v under a directive the binary covers", *r.AnalyserLimit)
	}
	if !strings.HasPrefix(r.FailureDetail, "parse failures in 2 package(s)") {
		t.Errorf("detail = %q", r.FailureDetail)
	}
}

// A tree with no go.mod claims no limit: absence of a directive is not a newer one.
func TestExtract_NoGoModClaimsNoLimit(t *testing.T) {
	restore := gotoolchain.SetAnalysingGo("go1.26.6")
	defer restore()
	tree := limitTree("1.27.2")
	delete(tree, "go.mod")
	r, err := makeExtractor().Extract(context.Background(), tree, coord(t))
	if err != nil {
		t.Fatalf("Extract: %v", err)
	}
	if r.AnalyserLimit != nil {
		t.Errorf("analyser limit without a go.mod: %+v", *r.AnalyserLimit)
	}
}

// A binary that reads every file records no limit and the record is the one
// it always wrote.
func TestExtract_NoRefusalNoLimit(t *testing.T) {
	tree := limitTree("1.99")
	delete(tree, "genmeth.go")
	delete(tree, "sub/only.go")
	r, err := makeExtractor().Extract(context.Background(), tree, coord(t))
	if err != nil {
		t.Fatalf("Extract: %v", err)
	}
	if r.AnalyserLimit != nil || r.OverallStatus != domain2.InterfaceStatusExtracted || r.FailureDetail != "" {
		t.Errorf("clean tree: limit %v, status %s, detail %q", r.AnalyserLimit, r.OverallStatus, r.FailureDetail)
	}
}
