package reachability_test

import (
	"context"
	"errors"
	"slices"
	"testing"

	"code.eitanity.com/kanonarion/internal/coordinate"
	"code.eitanity.com/kanonarion/internal/coordinate/coordinatetest"

	callgraphdomain "code.eitanity.com/kanonarion/internal/callgraph/domain"
	cgports "code.eitanity.com/kanonarion/internal/callgraph/ports"

	"code.eitanity.com/kanonarion/internal/vuln/adapters/reachability"
	"code.eitanity.com/kanonarion/internal/vuln/ports"
)

// fakeStore is a cgports.CallGraphStore that serves one record. Only
// GetCallGraphRecord is exercised; the rest satisfy the interface.
type fakeStore struct {
	record callgraphdomain.CallGraphRecord
	found  bool
	err    error
}

func (s *fakeStore) GetCallGraphRecord(_ context.Context, _ coordinate.ModuleCoordinate, _ string) (callgraphdomain.CallGraphRecord, bool, error) {
	return s.record, s.found, s.err
}

func (s *fakeStore) PutCallGraphRecord(context.Context, callgraphdomain.CallGraphRecord) error {
	return nil
}

func (s *fakeStore) ListCallGraphRecords(context.Context, cgports.CallGraphFilter) ([]cgports.CallGraphSummary, error) {
	return nil, nil
}

func (s *fakeStore) FindCallers(context.Context, string, string, coordinate.ModuleSet, cgports.EdgeQueryOptions) ([]cgports.CallEdgeRef, error) {
	return nil, nil
}

func (s *fakeStore) FindCallees(context.Context, string, string, coordinate.ModuleSet, cgports.EdgeQueryOptions) ([]cgports.CallEdgeRef, error) {
	return nil, nil
}

var loaderCoord = coordinatetest.MustNew("github.com/foo/bar", "v1.0.0")

func TestLoad_ProjectsRecord(t *testing.T) {
	rec := callgraphdomain.CallGraphRecord{
		Algorithm:       callgraphdomain.AlgorithmCHA,
		Completeness:    callgraphdomain.CompletenessBuiltWithBodies,
		ArtifactKind:    callgraphdomain.ArtifactApplication,
		PipelineVersion: "p1",
		Nodes: []callgraphdomain.CallNode{{
			ID: "github.com/foo/bar.Fn", Module: "github.com/foo/bar",
			Package: "github.com/foo/bar", Symbol: "Fn", Receiver: "T", IsExportedAPI: true,
		}, {
			ID: "github.com/foo/bar_test.TestFn", Module: "github.com/foo/bar",
			Package: "github.com/foo/bar_test", Symbol: "TestFn", IsExportedAPI: true, IsTest: true,
		}, {
			ID: "github.com/foo/bar.parse", Module: "github.com/foo/bar", Package: "github.com/foo/bar", Symbol: "parse",
			ExportDirective: callgraphdomain.ExportDirective{Kind: callgraphdomain.ExportWasm, Name: "parse"},
		}},
		Edges:              []callgraphdomain.CallEdge{{FromID: "github.com/foo/bar.Fn", ToID: "net/http.Get"}},
		StdlibPackages:     []string{"net/http"},
		DependencyPackages: []string{"golang.org/x/text/language"},
	}
	l := reachability.NewCallGraphStoreLoader(&fakeStore{record: rec, found: true}, "p1")

	proj, err := l.Load(t.Context(), loaderCoord)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	// ArtifactKind must survive the projection: reachability rooting reads it
	// here, so dropping it would silently restore the library-only rooting that
	// leaves an application's dynamically dispatched code unreachable.
	if proj.ArtifactKind != string(callgraphdomain.ArtifactApplication) {
		t.Errorf("ArtifactKind = %q, want %q", proj.ArtifactKind, callgraphdomain.ArtifactApplication)
	}
	if proj.Completeness != string(callgraphdomain.CompletenessBuiltWithBodies) {
		t.Errorf("Completeness = %q", proj.Completeness)
	}
	if proj.Algorithm != string(callgraphdomain.AlgorithmCHA) {
		t.Errorf("Algorithm = %q", proj.Algorithm)
	}
	// The generation an answer read from this graph will name.
	if proj.PipelineVersion != "p1" {
		t.Errorf("PipelineVersion = %q, want p1", proj.PipelineVersion)
	}
	// IsTest must survive the projection too: the root selection reads it here,
	// and a dropped axis would reach the selector as "not a test" rather than as
	// the fact the graph recorded.
	want := []ports.CallGraphNode{{
		ID: "github.com/foo/bar.Fn", Module: "github.com/foo/bar",
		Package: "github.com/foo/bar", Symbol: "Fn", Receiver: "T", IsExportedAPI: true,
	}, {
		ID: "github.com/foo/bar_test.TestFn", Module: "github.com/foo/bar",
		Package: "github.com/foo/bar_test", Symbol: "TestFn", IsExportedAPI: true, IsTest: true,
	}, {
		// The export directive survives for the same reason: the entry-point
		// selector reads it here.
		ID: "github.com/foo/bar.parse", Module: "github.com/foo/bar", Package: "github.com/foo/bar", Symbol: "parse",
		ExportKind: "wasmexport", ExportName: "parse",
	}}
	if !slices.Equal(proj.Nodes, want) {
		t.Errorf("Nodes = %+v, want %+v", proj.Nodes, want)
	}
	if len(proj.Edges) != 1 || proj.Edges[0].FromID != "github.com/foo/bar.Fn" || proj.Edges[0].ToID != "net/http.Get" {
		t.Errorf("Edges = %+v", proj.Edges)
	}
	// Both closures survive: a joined search restricts the other graph to them.
	if !slices.Equal(proj.StdlibPackages, rec.StdlibPackages) || !slices.Equal(proj.DependencyPackages, rec.DependencyPackages) {
		t.Errorf("closures = %v / %v, want %v / %v", proj.StdlibPackages, proj.DependencyPackages, rec.StdlibPackages, rec.DependencyPackages)
	}
}

func TestLoad_NotFound(t *testing.T) {
	l := reachability.NewCallGraphStoreLoader(&fakeStore{}, "p1")

	if _, err := l.Load(t.Context(), loaderCoord); !errors.Is(err, ports.ErrCallGraphNotFound) {
		t.Errorf("err = %v, want ErrCallGraphNotFound", err)
	}
}

func TestLoad_StoreError(t *testing.T) {
	storeErr := errors.New("store unavailable")
	l := reachability.NewCallGraphStoreLoader(&fakeStore{err: storeErr}, "p1")

	if _, err := l.Load(t.Context(), loaderCoord); !errors.Is(err, storeErr) {
		t.Errorf("err = %v, want it to wrap %v", err, storeErr)
	}
}

// TestLoad_PicksOutOnlyTheReflectiveDispatchSites is where the population is
// decided: a site is a call to a reflective method lookup, or to a
// standard-library function that makes one, from outside package reflect.
//
// The callee alone decides. The reflect_dispatch attribute is set on calls that
// hide nothing (reflect.TypeOf) and unset on lookups that do (the *rtype
// receiver), so reading it either way gets the population wrong.
func TestLoad_PicksOutOnlyTheReflectiveDispatchSites(t *testing.T) {
	edge := func(to string, flagged bool, file string, line int) callgraphdomain.CallEdge {
		return callgraphdomain.CallEdge{
			FromID:          "github.com/foo/bar.bind",
			ToID:            to,
			CallSite:        callgraphdomain.SourcePosition{File: file, Line: line},
			Confidence:      callgraphdomain.ConfidenceUnknown,
			ReflectDispatch: flagged,
		}
	}
	rec := callgraphdomain.CallGraphRecord{
		Completeness: callgraphdomain.CompletenessBuiltWithBodies,
		ArtifactKind: callgraphdomain.ArtifactLibrary,
		Nodes: []callgraphdomain.CallNode{{
			ID: "github.com/foo/bar.bind", Module: "github.com/foo/bar",
			Package: "github.com/foo/bar", Symbol: "bind",
		}},
		Edges: []callgraphdomain.CallEdge{
			edge("reflect.(Value).MethodByName", true, "bind.go", 10),
			// The analyser stores Type lookups Direct and unflagged, and they are
			// lookups all the same.
			edge("reflect.(*rtype).MethodByName", false, "bind.go", 11),
			// Flagged, and bounds perfectly. This is the one a count of the
			// attribute alone gets wrong.
			edge("reflect.TypeOf", true, "bind.go", 12),
			edge("reflect.DeepEqual", true, "bind.go", 14),
			// These take a value or a field, not a method: a function reaches Call
			// only through a Reference edge the search follows.
			edge("reflect.(Value).Call", true, "bind.go", 16),
			edge("reflect.(Value).CallSlice", true, "bind.go", 17),
			edge("reflect.(Value).FieldByName", true, "bind.go", 18),
			// A plain call between the module's own functions.
			edge("github.com/foo/bar.helper", false, "bind.go", 20),
		},
	}

	l := reachability.NewCallGraphStoreLoader(&fakeStore{record: rec, found: true}, "p1")
	proj, err := l.Load(context.Background(), loaderCoord)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if len(proj.Edges) != 8 {
		t.Fatalf("the projection carries %d edges, want all 8 — nothing is dropped here", len(proj.Edges))
	}
	want := []ports.CallGraphReflectSite{
		{CallerID: "github.com/foo/bar.bind", CalleeID: "reflect.(Value).MethodByName", File: "bind.go", Line: 10},
		{CallerID: "github.com/foo/bar.bind", CalleeID: "reflect.(*rtype).MethodByName", File: "bind.go", Line: 11},
	}
	if !slices.Equal(proj.ReflectiveDispatch, want) {
		t.Errorf("the projection names %+v as reflective dispatch, want %+v", proj.ReflectiveDispatch, want)
	}
}

// TestLoad_ReflectsOwnLookupIsNotASite: in a joined standard-library graph,
// reflect's (Value).MethodByName calls (*rtype).MethodByName. That call is the
// lookup's implementation, and only a caller's own lookup is a site.
func TestLoad_ReflectsOwnLookupIsNotASite(t *testing.T) {
	const caller = "reflect.(Value).MethodByName"
	const callee = "reflect.(*rtype).MethodByName"
	rec := callgraphdomain.CallGraphRecord{
		Completeness: callgraphdomain.CompletenessBuiltWithBodies,
		ArtifactKind: callgraphdomain.ArtifactLibrary,
		Nodes: []callgraphdomain.CallNode{
			{ID: caller, Module: "stdlib", Package: "reflect", Receiver: "Value", Symbol: "MethodByName"},
			{ID: "reflect.dev/mirror.Lookup", Module: "reflect.dev/mirror", Package: "reflect.dev/mirror", Symbol: "Lookup"},
		},
		Edges: []callgraphdomain.CallEdge{
			{FromID: caller, ToID: callee, Confidence: callgraphdomain.ConfidenceDirect},
			// A module whose path merely starts with the word is not package reflect.
			{FromID: "reflect.dev/mirror.Lookup", ToID: callee, Confidence: callgraphdomain.ConfidenceDirect},
		},
	}
	l := reachability.NewCallGraphStoreLoader(&fakeStore{record: rec, found: true}, "p1")
	proj, err := l.Load(context.Background(), loaderCoord)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	want := []ports.CallGraphReflectSite{{CallerID: "reflect.dev/mirror.Lookup", CalleeID: callee}}
	if !slices.Equal(proj.ReflectiveDispatch, want) {
		t.Errorf("reflective dispatch = %+v, want %+v", proj.ReflectiveDispatch, want)
	}
}

// TestLoad_EveryLookupIsASiteWithoutTheAttribute walks the whole list so an
// entry dropped from it fails here, on the attribute value the analyser really
// stores for that callee as well as the other.
func TestLoad_EveryLookupIsASiteWithoutTheAttribute(t *testing.T) {
	for _, callee := range []string{
		"reflect.(Value).Method", "reflect.(Value).MethodByName", "reflect.(Value).Methods",
		"reflect.(*rtype).Method", "reflect.(*rtype).MethodByName", "reflect.(*rtype).Methods",
		"text/template.(*Template).Execute", "text/template.(*Template).ExecuteTemplate",
		"html/template.(*Template).Execute", "html/template.(*Template).ExecuteTemplate",
		"net/rpc.Register", "net/rpc.RegisterName", "net/rpc.(*Server).Register", "net/rpc.(*Server).RegisterName",
	} {
		for _, flagged := range []bool{false, true} {
			rec := callgraphdomain.CallGraphRecord{
				Completeness: callgraphdomain.CompletenessBuiltWithBodies,
				ArtifactKind: callgraphdomain.ArtifactLibrary,
				Nodes:        []callgraphdomain.CallNode{{ID: "m.f", Module: "m", Package: "m", Symbol: "f"}},
				Edges:        []callgraphdomain.CallEdge{{FromID: "m.f", ToID: callee, ReflectDispatch: flagged}},
			}
			l := reachability.NewCallGraphStoreLoader(&fakeStore{record: rec, found: true}, "p1")
			proj, err := l.Load(context.Background(), loaderCoord)
			if err != nil {
				t.Fatalf("Load: %v", err)
			}
			if len(proj.ReflectiveDispatch) != 1 || proj.ReflectiveDispatch[0].CalleeID != callee {
				t.Errorf("callee %s, flagged %t: sites = %+v, want the one call", callee, flagged, proj.ReflectiveDispatch)
			}
		}
	}
}
