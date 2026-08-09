package staticcha

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/tools/go/packages"
)

// TestTargetCoordinate_FallsBackToTheCoordinate covers the two trees that
// declare nothing usable. Neither is an error: a module published before Go
// modules whose synthesis was declined has no go.mod at all, and a go.mod the
// loader is about to reject with a line number should be rejected by the loader,
// not pre-empted here with a worse message.
func TestTargetCoordinate_FallsBackToTheCoordinate(t *testing.T) {
	t.Parallel()
	coord := mustCoord(t, "example.com/mod", "v1.0.0")

	if got := targetCoordinate(t.TempDir(), coord); got != coord {
		t.Errorf("no go.mod: target = %s, want the coordinate %s", got, coord)
	}

	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "go.mod"), []byte("this is not a go.mod\n"), 0o600); err != nil {
		t.Fatalf("writing go.mod: %v", err)
	}
	if got := targetCoordinate(dir, coord); got != coord {
		t.Errorf("unparseable go.mod: target = %s, want the coordinate %s", got, coord)
	}

	dir = t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "go.mod"), []byte("module example.com/other\n\ngo 1.17\n"), 0o600); err != nil {
		t.Fatalf("writing go.mod: %v", err)
	}
	got := targetCoordinate(dir, coord)
	if got.Path() != "example.com/other" || got.Version() != coord.Version() {
		t.Errorf("target = %s, want example.com/other at the requested version", got)
	}
}

// TestDescribeEmptyTargetSet_NamesWhatWasSoughtAndFound holds the three facts
// that settle this failure between them: what the loader was looking for, what
// it found instead, and what it said went wrong. The list is bounded for
// readability, and the bound must never hide the size of the population — the
// count comes first and the overflow is stated.
func TestDescribeEmptyTargetSet_NamesWhatWasSoughtAndFound(t *testing.T) {
	t.Parallel()
	coord := mustCoord(t, "example.com/mod", "v1.0.0")

	pkg := func(path string) *packages.Package { return &packages.Package{PkgPath: path} }

	// A driver that reported through the packages: no import path, one error.
	got := describeEmptyTargetSet(coord, []*packages.Package{pkg("")}, []string{"go.mod file not found"})
	for _, want := range []string{"no package under example.com/mod", "0 package(s)", "go.mod file not found"} {
		if !strings.Contains(got, want) {
			t.Errorf("detail %q does not name %q", got, want)
		}
	}

	// Fewer than the bound: every path is named and there is no overflow note.
	got = describeEmptyTargetSet(coord, []*packages.Package{pkg("example.com/other"), pkg("example.com/other")}, nil)
	if !strings.Contains(got, "1 package(s) (example.com/other)") || strings.Contains(got, "more") {
		t.Errorf("detail %q should name the one deduplicated path and claim no overflow", got)
	}

	// More than the bound: the count is the population, the list is the sample.
	many := make([]*packages.Package, 0, maxNamedPackages+3)
	for _, s := range []string{"a", "b", "c", "d", "e", "f", "g", "h"} {
		many = append(many, pkg("example.com/other/"+s))
	}
	got = describeEmptyTargetSet(coord, many, nil)
	if !strings.Contains(got, "8 package(s)") {
		t.Errorf("detail %q does not state the whole population", got)
	}
	if !strings.Contains(got, "+3 more") {
		t.Errorf("detail %q does not state how many it withheld", got)
	}
}

// TestMetaLoadErrors_DeduplicatesAndOrders keeps the diagnosis stable. The same
// module-graph failure is attached to every package that could not resolve
// through it, and a detail repeating it three times reports one fact as three.
func TestMetaLoadErrors_DeduplicatesAndOrders(t *testing.T) {
	t.Parallel()
	same := packages.Error{Msg: "missing go.sum entry"}
	pkgs := []*packages.Package{
		{PkgPath: "example.com/mod/b", Errors: []packages.Error{{Msg: "zebra"}, same}},
		{PkgPath: "example.com/mod/a", Errors: []packages.Error{same, {Msg: ""}}},
	}
	got := metaLoadErrors(pkgs)
	if len(got) != 2 {
		t.Fatalf("errors = %v, want the two distinct messages", got)
	}
	if got[0] > got[1] {
		t.Errorf("errors = %v, want a stable order", got)
	}
}
