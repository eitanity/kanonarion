package staticcha

import (
	"strings"
	"testing"

	"github.com/eitanity/kanonarion/internal/coordinate"

	"golang.org/x/tools/go/callgraph"
	"golang.org/x/tools/go/callgraph/cha"
	"golang.org/x/tools/go/packages"
	"golang.org/x/tools/go/ssa"
	"golang.org/x/tools/go/ssa/ssautil"
)

func wrapperCoord(t *testing.T) coordinate.ModuleCoordinate {
	t.Helper()
	coord, err := coordinate.NewModuleCoordinate("example.com/wrapprobe", "v1.0.0")
	if err != nil {
		t.Fatalf("coord: %v", err)
	}
	return coord
}

// TestWrapperAdmission_IsReachabilityNotMembership pins the constraint the
// membership change had to leave alone.
//
// SSA gives a method wrapper no package, so fnInModule answers false for one —
// and that answer is load-bearing, not an oversight. recordedCallerNodes
// compensates by REACHABILITY: admitReachedWrappers admits the wrappers a
// recorded caller actually reaches, and only those. Answering fnInModule through
// the wrapped object instead would admit every wrapper of every in-module type
// and attach a floating subgraph of callees to nodes nothing reaches.
//
// The test states both halves against the same program: the reached wrapper is
// in, the unreached wrapper is out, and neither is decided by membership.
func TestWrapperAdmission_IsReachabilityNotMembership(t *testing.T) {
	prog := buildWrapperProg(t)
	mem := membershipByPrefix(wrapperCoord(t))

	var reached, unreached *ssa.Function
	for fn := range ssautil.AllFunctions(prog) {
		switch {
		case strings.HasSuffix(fn.Name(), "Save$bound"):
			reached = fn
		case fnIsMethodWrapper(fn) && fn.Name() == "Ping":
			unreached = fn
		}
	}
	if reached == nil {
		t.Fatal("no interface-method $bound wrapper in the built program; the fixture no longer materialises one")
	}
	if unreached == nil {
		t.Fatal("no unreached Ping wrapper in the built program; the control has nothing to assert against")
	}

	// Neither wrapper belongs to a package, so membership declines both. This is
	// the assertion that breaks if fnInModule is ever taught to resolve the nil
	// case through the wrapped object.
	if fnInModule(reached, mem) {
		t.Errorf("fnInModule(%s) = true: the package-less wrapper is being decided by membership", reached)
	}
	if fnInModule(unreached, mem) {
		t.Errorf("fnInModule(%s) = true: the package-less wrapper is being decided by membership", unreached)
	}

	cg := cha.CallGraph(prog)
	recorded := recordedCallerNodes(cg, mem)

	if !isRecorded(cg, recorded, reached) {
		t.Errorf("%s is not a recorded caller: the wrapper a recorded caller reaches lost its outgoing edges", reached)
	}
	if isRecorded(cg, recorded, unreached) {
		t.Errorf("%s is a recorded caller: wrappers are being admitted by type membership rather than by reachability", unreached)
	}
}

func isRecorded(cg *callgraph.Graph, recorded map[*callgraph.Node]bool, fn *ssa.Function) bool {
	node := cg.Nodes[fn]
	return node != nil && recorded[node]
}

// TestModuleMembership_LabelsWhatItDecidedByPrefix pins the fallback's
// visibility. A package the loader places in a module is decided by that answer;
// a package it places in no module at all — the pre-modules case — falls back to
// the path prefix, and every path decided that way is named.
//
// The silent version of this is the failure mode: a record that says "in module"
// with no note that it guessed reads exactly like one that measured.
func TestModuleMembership_LabelsWhatItDecidedByPrefix(t *testing.T) {
	coord, err := coordinate.NewModuleCoordinate("example.com/mod", "v1.0.0")
	if err != nil {
		t.Fatalf("coord: %v", err)
	}
	mem := newModuleMembership(coord, []*packages.Package{
		// Placed by the loader, in the analysed module.
		{PkgPath: "example.com/mod/inside", Module: &packages.Module{Path: "example.com/mod"}},
		// Placed by the loader, in a DIFFERENT module whose path nests under it.
		{PkgPath: "example.com/mod/nested/pkg", Module: &packages.Module{Path: "example.com/mod/nested"}},
		// Placed in no module: only the prefix can decide it.
		{PkgPath: "example.com/mod/unplaced"},
		// Placed in no module and outside the prefix — the standard library's case.
		{PkgPath: "net/http"},
	})

	for _, tc := range []struct {
		pkgPath string
		want    bool
	}{
		{"example.com/mod/inside", true},
		{"example.com/mod/nested/pkg", false},
		{"example.com/mod/unplaced", true},
		{"net/http", false},
		{"", false},
	} {
		if got := mem.contains(tc.pkgPath); got != tc.want {
			t.Errorf("contains(%q) = %v, want %v", tc.pkgPath, got, tc.want)
		}
	}

	got := mem.prefixAttributed()
	want := []string{"example.com/mod/unplaced"}
	if len(got) != len(want) || (len(got) == 1 && got[0] != want[0]) {
		t.Errorf("prefixAttributed() = %v, want %v", got, want)
	}
}

// TestModuleMembership_ForeignModulesNamesTheModuleAndItsVersion pins the claim
// the record now makes about the packages it built that belong to someone else.
//
// The version is the point. The parent record names only its own coordinate, so
// a route through a nested module's nodes was a route through a version nobody
// stated; the loader resolved one, and this is where it survives.
func TestModuleMembership_ForeignModulesNamesTheModuleAndItsVersion(t *testing.T) {
	coord, err := coordinate.NewModuleCoordinate("example.com/mod", "v1.0.0")
	if err != nil {
		t.Fatalf("coord: %v", err)
	}
	mem := newModuleMembership(coord, []*packages.Package{
		{PkgPath: "example.com/mod/inside", Module: &packages.Module{Path: "example.com/mod", Version: "v1.0.0"}},
		{PkgPath: "example.com/mod/nested/pkg", Module: &packages.Module{Path: "example.com/mod/nested", Version: "v0.3.0"}},
		{PkgPath: "example.com/mod/nested/other", Module: &packages.Module{Path: "example.com/mod/nested", Version: "v0.3.0"}},
		// Placed in no module: the prefix decides membership, and a prefix cannot
		// tell a nested module from the analysed one — which is the confusion this
		// set exists to state rather than reproduce. It is never reported foreign.
		{PkgPath: "example.com/mod/unplaced"},
		{PkgPath: "net/http"},
	})

	built := []string{
		"example.com/mod/inside",
		"example.com/mod/nested/pkg",
		"example.com/mod/nested/other",
		"example.com/mod/unplaced",
	}
	got := mem.foreignModules(built)
	if len(got) != 1 {
		t.Fatalf("foreignModules() = %+v, want exactly one entry", got)
	}
	if got[0].Path != "example.com/mod/nested" || got[0].Version != "v0.3.0" {
		t.Errorf("foreignModules() = %+v, want example.com/mod/nested@v0.3.0", got[0])
	}

	// A build that reached nothing foreign records the empty set, which is a
	// different statement from a record predating the field — the record's schema
	// version is what separates those, so this one must be nil, not a guess.
	if own := mem.foreignModules([]string{"example.com/mod/inside", "example.com/mod/unplaced"}); own != nil {
		t.Errorf("a build of the module's own packages reported foreign modules: %+v", own)
	}

	// A package the loader never saw is not evidence of anything, and must not be
	// invented into the set.
	if unseen := mem.foreignModules([]string{"example.com/mod/never/loaded"}); unseen != nil {
		t.Errorf("an unloaded package produced a foreign module: %+v", unseen)
	}
}
