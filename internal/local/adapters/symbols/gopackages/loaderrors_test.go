package gopackages

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/tools/go/packages"
)

// -- splitPos --

func TestSplitPos(t *testing.T) {
	cases := []struct {
		pos  string
		file string
		line int
		col  int
		ok   bool
	}{
		{"/a/b.go:5:18", "/a/b.go", 5, 18, true},
		{"./b.go:5:18", "./b.go", 5, 18, true},
		{"b.go:5", "b.go", 5, 0, true},
		{"b.go", "b.go", 0, 0, true},
		{"", "", 0, 0, false},
		{"-", "", 0, 0, false},
		{"/weird:dir/b.go:3:1", "/weird:dir/b.go", 3, 1, true},
		// A colon whose right-hand side is not a number ends the scan: the
		// whole string is the file name.
		{"/weird:dir/b.go", "/weird:dir/b.go", 0, 0, true},
		// Numbers with no file left in front of them are not a position.
		{":5:18", "", 0, 0, false},
	}
	for _, c := range cases {
		file, line, col, ok := splitPos(c.pos)
		if file != c.file || line != c.line || col != c.col || ok != c.ok {
			t.Errorf("splitPos(%q) = (%q, %d, %d, %v), want (%q, %d, %d, %v)",
				c.pos, file, line, col, ok, c.file, c.line, c.col, c.ok)
		}
	}
}

// -- splitPosPrefix --

func TestSplitPosPrefix(t *testing.T) {
	cases := []struct{ line, pos, msg string }{
		{"./b.go:5:18: cannot use x", "./b.go:5:18", "cannot use x"},
		{"b.go:5: cannot use x", "b.go:5", "cannot use x"},
		// No line number, so nothing here is a position: the whole text is the
		// message, colon and all.
		{"no required module provides package example.com/x: add it", "", "no required module provides package example.com/x: add it"},
		{"# example.com/pb", "", "# example.com/pb"},
	}
	for _, c := range cases {
		pos, msg := splitPosPrefix(c.line)
		if pos != c.pos || msg != c.msg {
			t.Errorf("splitPosPrefix(%q) = (%q, %q), want (%q, %q)", c.line, pos, msg, c.pos, c.msg)
		}
	}
}

// -- flattenMessage --

func TestFlattenMessage_KeepsEveryPart(t *testing.T) {
	got := flattenMessage("too many arguments in call to Fn\n\thave (number, number)\n\twant (int)")
	want := "too many arguments in call to Fn have (number, number) want (int)"
	if got != want {
		t.Errorf("flattenMessage = %q, want %q", got, want)
	}
}

// -- reportLoadErrors --

// report renders pkgs against root and returns the lines written.
func report(t *testing.T, root string, pkgs []*packages.Package) []string {
	t.Helper()
	var buf bytes.Buffer
	n := reportLoadErrors(&buf, root, pkgs)
	out := strings.Split(strings.TrimSuffix(buf.String(), "\n"), "\n")
	if buf.Len() == 0 {
		out = nil
	}
	if n != len(out) {
		t.Fatalf("reportLoadErrors returned %d but wrote %d lines: %q", n, len(out), buf.String())
	}
	return out
}

// listError is the driver's account of a package's problems: the go command's
// whole stderr block in one message, with no position of its own.
func listError(block string) packages.Error {
	return packages.Error{Msg: block, Kind: packages.ListError}
}

func typeError(pos, msg string) packages.Error {
	return packages.Error{Pos: pos, Msg: msg, Kind: packages.TypeError}
}

func TestReportLoadErrors_OneProblemSpelledThreeWaysIsOneLine(t *testing.T) {
	root := "/w"
	pkgs := []*packages.Package{{
		ID:      "example.com/pb",
		PkgPath: "example.com/pb",
		Errors: []packages.Error{
			listError("# example.com/pb\n./prod.go:4:27: cannot use \"nope\" as int value"),
			typeError("/w/prod.go:4:27", "cannot use \"nope\" as int value"),
		},
	}}
	got := report(t, root, pkgs)
	want := []string{`prod.go:4:27: cannot use "nope" as int value`}
	if len(got) != 1 || got[0] != want[0] {
		t.Errorf("lines = %q, want %q", got, want)
	}
}

func TestReportLoadErrors_TwoDistinctProblemsInOneFileAreTwoLines(t *testing.T) {
	pkgs := []*packages.Package{{
		ID:      "example.com/pb",
		PkgPath: "example.com/pb",
		Errors: []packages.Error{
			listError("# example.com/pb\n./prod.go:4:27: cannot use \"nope\" as int value\n./prod.go:6:21: cannot use 42 as string value"),
			typeError("/w/prod.go:4:27", `cannot use "nope" as int value`),
			typeError("/w/prod.go:6:21", "cannot use 42 as string value"),
		},
	}}
	got := report(t, "/w", pkgs)
	want := []string{
		`prod.go:4:27: cannot use "nope" as int value`,
		"prod.go:6:21: cannot use 42 as string value",
	}
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Errorf("lines = %q, want %q", got, want)
	}
}

func TestReportLoadErrors_SameProblemInTwoFilesIsTwoLines(t *testing.T) {
	pkgs := []*packages.Package{{
		ID:      "example.com/pb",
		PkgPath: "example.com/pb",
		Errors: []packages.Error{
			listError("# example.com/pb\n./a.go:5:16: cannot use \"nope\" as int value\n./b.go:3:16: cannot use \"nope\" as int value"),
			typeError("/w/a.go:5:16", `cannot use "nope" as int value`),
			typeError("/w/b.go:3:16", `cannot use "nope" as int value`),
		},
	}}
	got := report(t, "/w", pkgs)
	want := []string{
		`a.go:5:16: cannot use "nope" as int value`,
		`b.go:3:16: cannot use "nope" as int value`,
	}
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Errorf("lines = %q, want %q", got, want)
	}
}

// Two accounts of the same position that do not say the same thing are two
// lines. Collapsing them would be a guess, and the guess that loses a real
// second problem.
func TestReportLoadErrors_DifferentMessagesAtOnePositionAreBothKept(t *testing.T) {
	pkgs := []*packages.Package{{
		ID:      "example.com/pb",
		PkgPath: "example.com/pb",
		Errors: []packages.Error{
			listError("./m.go:3:8: no required module provides package example.com/nowhere"),
			typeError("/w/m.go:3:8", `could not import example.com/nowhere (invalid package name: "")`),
		},
	}}
	if got := report(t, "/w", pkgs); len(got) != 2 {
		t.Errorf("lines = %q, want both accounts", got)
	}
}

// The type checker and the go command wrap a signature mismatch over three
// lines each. Folded onto one line the two renderings are the same problem.
func TestReportLoadErrors_MultiLineMessagesFoldAndCollapse(t *testing.T) {
	pkgs := []*packages.Package{{
		ID:      "example.com/pb",
		PkgPath: "example.com/pb",
		Errors: []packages.Error{
			listError("# example.com/pb\n./h.go:7:23: too many arguments in call to Fn\n\thave (number, number)\n\twant (int)"),
			typeError("/w/h.go:7:23", "too many arguments in call to Fn\n\thave (number, number)\n\twant (int)"),
		},
	}}
	got := report(t, "/w", pkgs)
	want := "h.go:7:23: too many arguments in call to Fn have (number, number) want (int)"
	if len(got) != 1 || got[0] != want {
		t.Errorf("lines = %q, want [%q]", got, want)
	}
}

// A problem attributed to no file is still reported, named by its package.
func TestReportLoadErrors_PlacelessProblemNamesItsPackage(t *testing.T) {
	pkgs := []*packages.Package{{
		ID:      "example.com/pb",
		PkgPath: "example.com/pb",
		Errors:  []packages.Error{listError("build constraints exclude all Go files")},
	}}
	got := report(t, "/w", pkgs)
	want := "example.com/pb: build constraints exclude all Go files"
	if len(got) != 1 || got[0] != want {
		t.Errorf("lines = %q, want [%q]", got, want)
	}
}

// The banner is dropped when file-attributed problems stand beneath it, and
// kept — named by its package — when it is all the package had to say.
func TestReportLoadErrors_BannerOnlyPackageIsStillReported(t *testing.T) {
	pkgs := []*packages.Package{{
		ID:      "example.com/pb",
		PkgPath: "example.com/pb",
		Errors:  []packages.Error{listError("# example.com/pb")},
	}}
	got := report(t, "/w", pkgs)
	want := "example.com/pb: # example.com/pb"
	if len(got) != 1 || got[0] != want {
		t.Errorf("lines = %q, want [%q]", got, want)
	}
}

// One module error is attached to every package of that module; it is reported
// once, named by the module.
func TestReportLoadErrors_ModuleErrorReportedOncePerModule(t *testing.T) {
	mod := &packages.Module{Path: "example.com/pb", Error: &packages.ModuleError{Err: "missing go.sum entry"}}
	pkgs := []*packages.Package{
		{ID: "example.com/pb/a", PkgPath: "example.com/pb/a", Module: mod},
		{ID: "example.com/pb/b", PkgPath: "example.com/pb/b", Module: mod},
	}
	got := report(t, "/w", pkgs)
	want := "example.com/pb: missing go.sum entry"
	if len(got) != 1 || got[0] != want {
		t.Errorf("lines = %q, want [%q]", got, want)
	}
}

// A file outside the analysis root keeps the absolute path: relativising it
// would produce a ../.. chain no reader can act on.
func TestReportLoadErrors_FileOutsideRootKeepsAbsolutePath(t *testing.T) {
	pkgs := []*packages.Package{{
		ID:      "example.com/other",
		PkgPath: "example.com/other",
		Errors:  []packages.Error{typeError("/elsewhere/x.go:1:1", "boom")},
	}}
	got := report(t, "/w", pkgs)
	want := "/elsewhere/x.go:1:1: boom"
	if len(got) != 1 || got[0] != want {
		t.Errorf("lines = %q, want [%q]", got, want)
	}
}

// -- against a real load --

// writeOneErrorFixture builds a workspace with exactly one type error, in a
// known file at a known line and column, and a local replace dependency the
// analysis must still report.
func writeOneErrorFixture(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	files := map[string]string{
		"go.mod": "module example.com/app\n\ngo 1.22\n\nrequire example.com/dep v0.0.0\n\nreplace example.com/dep => ./dep\n",
		"app.go": "package app\n\nimport \"example.com/dep\"\n\nvar bad int = \"nope\"\n\n" +
			"// Run uses the dependency.\nfunc Run() string { return dep.Hello() }\n",
		"dep/go.mod": "module example.com/dep\n\ngo 1.22\n",
		"dep/dep.go": "package dep\n\n// Hello returns a greeting.\nfunc Hello() string { return \"hi\" }\n",
	}
	for name, content := range files {
		full := filepath.Join(root, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(full), 0o750); err != nil {
			t.Fatalf("creating %s: %v", filepath.Dir(full), err)
		}
		if err := os.WriteFile(full, []byte(content), 0o600); err != nil {
			t.Fatalf("writing %s: %v", name, err)
		}
	}
	return root
}

// One type error is one line, naming a file, a line and a column. Before this
// renderer the same error printed three times: a "-:" banner naming no file,
// the go command's relative rendering, and the type checker's absolute one.
func TestReportLoadErrors_RealLoadOneErrorIsOneLine(t *testing.T) {
	root := writeOneErrorFixture(t)
	pkgs, err := packages.Load(&packages.Config{
		Mode: loadMode, Dir: root, Tests: true, Context: context.Background(),
	}, "./...")
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	got := report(t, root, pkgs)
	if len(got) != 1 {
		t.Fatalf("lines = %q, want exactly one", got)
	}
	if !strings.HasPrefix(got[0], "app.go:5:15: ") {
		t.Errorf("line = %q, want it to open at app.go:5:15", got[0])
	}
	if !strings.Contains(got[0], "cannot use") {
		t.Errorf("line = %q, want the type checker's message", got[0])
	}
}

// Control: the load stays non-fatal. A tree that does not type-check still
// returns its dependencies and no error.
func TestAnalyseSymbols_TypeErrorIsNonFatalAndStillReportsDependencies(t *testing.T) {
	mods, err := New().AnalyseSymbols(context.Background(), writeOneErrorFixture(t))
	if err != nil {
		t.Fatalf("AnalyseSymbols returned an error for a tree with a type error: %v", err)
	}
	if len(mods) != 1 || mods[0].Path != "example.com/dep" {
		t.Fatalf("modules = %v, want the replaced dependency", mods)
	}
	if len(mods[0].UsedSymbols) == 0 {
		t.Errorf("UsedSymbols is empty; partial results were not emitted")
	}
}

// The synthesised package go/packages returns for a pattern that resolved to
// nothing has no import path. Its problems are named by whatever identity is
// left, never dropped for want of one.
func TestReportLoadErrors_PackageWithoutPathIsNamedByWhatItHas(t *testing.T) {
	cases := []struct {
		name string
		pkg  *packages.Package
		want string
	}{
		{"id stands in for path", &packages.Package{ID: "command-line-arguments"}, "command-line-arguments: nothing to build"},
		{"no identity at all", &packages.Package{}, "-: nothing to build"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			c.pkg.Errors = []packages.Error{listError("nothing to build")}
			got := report(t, "/w", []*packages.Package{c.pkg})
			if len(got) != 1 || got[0] != c.want {
				t.Errorf("lines = %q, want [%q]", got, c.want)
			}
		})
	}
}

// A module error on a module with no path of its own is still attributed.
func TestReportLoadErrors_ModuleErrorWithoutPathFallsBackToPackage(t *testing.T) {
	pkgs := []*packages.Package{{
		ID:      "example.com/pb",
		PkgPath: "example.com/pb",
		Module:  &packages.Module{Error: &packages.ModuleError{Err: "missing go.sum entry"}},
	}}
	got := report(t, "/w", pkgs)
	want := "example.com/pb: missing go.sum entry"
	if len(got) != 1 || got[0] != want {
		t.Errorf("lines = %q, want [%q]", got, want)
	}
}

// A position with no column, or no line at all, still names its file.
func TestReportLoadErrors_PartialPositionsStillNameTheirFile(t *testing.T) {
	cases := []struct{ pos, want string }{
		{"/w/a.go:5", "a.go:5: boom"},
		{"/w/a.go", "a.go: boom"},
	}
	for _, c := range cases {
		pkgs := []*packages.Package{{
			ID: "example.com/pb", PkgPath: "example.com/pb",
			Errors: []packages.Error{typeError(c.pos, "boom")},
		}}
		got := report(t, "/w", pkgs)
		if len(got) != 1 || got[0] != c.want {
			t.Errorf("pos %q: lines = %q, want [%q]", c.pos, got, c.want)
		}
	}
}

// A blank line inside the driver's block is layout, not a problem.
func TestReportLoadErrors_BlankLinesInDriverBlockAreNotProblems(t *testing.T) {
	pkgs := []*packages.Package{{
		ID: "example.com/pb", PkgPath: "example.com/pb",
		Errors: []packages.Error{listError("# example.com/pb\n\n./a.go:1:1: boom\n\n")},
	}}
	got := report(t, "/w", pkgs)
	want := "a.go:1:1: boom"
	if len(got) != 1 || got[0] != want {
		t.Errorf("lines = %q, want [%q]", got, want)
	}
}
