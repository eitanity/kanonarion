package reachability_test

import (
	"context"
	"errors"
	"slices"
	"testing"

	"github.com/eitanity/kanonarion/internal/coordinate"
	"github.com/eitanity/kanonarion/internal/coordinate/coordinatetest"

	callgraphdomain "github.com/eitanity/kanonarion/internal/callgraph/domain"
	cgports "github.com/eitanity/kanonarion/internal/callgraph/ports"

	"github.com/eitanity/kanonarion/internal/vuln/adapters/reachability"
	"github.com/eitanity/kanonarion/internal/vuln/ports"
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
		Algorithm:    callgraphdomain.AlgorithmCHA,
		Completeness: callgraphdomain.CompletenessBuiltWithBodies,
		ArtifactKind: callgraphdomain.ArtifactApplication,
		Nodes: []callgraphdomain.CallNode{{
			ID: "github.com/foo/bar.Fn", Module: "github.com/foo/bar",
			Package: "github.com/foo/bar", Symbol: "Fn", Receiver: "T", IsExportedAPI: true,
		}, {
			ID: "github.com/foo/bar_test.TestFn", Module: "github.com/foo/bar",
			Package: "github.com/foo/bar_test", Symbol: "TestFn", IsExportedAPI: true, IsTest: true,
		}},
		Edges: []callgraphdomain.CallEdge{{FromID: "github.com/foo/bar.Fn", ToID: "net/http.Get"}},
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
	// IsTest must survive the projection too: the root selection reads it here,
	// and a dropped axis would reach the selector as "not a test" rather than as
	// the fact the graph recorded.
	want := []ports.CallGraphNode{{
		ID: "github.com/foo/bar.Fn", Module: "github.com/foo/bar",
		Package: "github.com/foo/bar", Symbol: "Fn", Receiver: "T", IsExportedAPI: true,
	}, {
		ID: "github.com/foo/bar_test.TestFn", Module: "github.com/foo/bar",
		Package: "github.com/foo/bar_test", Symbol: "TestFn", IsExportedAPI: true, IsTest: true,
	}}
	if !slices.Equal(proj.Nodes, want) {
		t.Errorf("Nodes = %+v, want %+v", proj.Nodes, want)
	}
	if len(proj.Edges) != 1 || proj.Edges[0].FromID != "github.com/foo/bar.Fn" || proj.Edges[0].ToID != "net/http.Get" {
		t.Errorf("Edges = %+v", proj.Edges)
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
// decided, so it is where the mistake that got it wrong is pinned.
//
// The analyser records one attribute, reflect_dispatch, and it means "the callee
// is in package reflect". Nearly everything it marks bounds perfectly: an edge
// to reflect.TypeOf has exactly one callee. Only the five reflect.Value methods
// that pick their target at run time hide anything, and reading the attribute as
// though it named them overstates the population by about two orders of
// magnitude.
//
// Both conditions are required and neither is sufficient. The attribute is what
// the analyser measured; the callee list is what makes it a dispatch.
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
			// Flagged, and bounds perfectly. This is the one a count of the
			// attribute alone gets wrong.
			edge("reflect.TypeOf", true, "bind.go", 12),
			edge("reflect.DeepEqual", true, "bind.go", 14),
			// A dispatching callee the analyser did NOT flag. The stored attribute
			// stays the authority on what was measured; a name match is not a
			// measurement.
			edge("reflect.(Value).Call", false, "bind.go", 16),
			// A plain call between the module's own functions.
			edge("github.com/foo/bar.helper", false, "bind.go", 18),
		},
	}

	l := reachability.NewCallGraphStoreLoader(&fakeStore{record: rec, found: true}, "p1")
	proj, err := l.Load(context.Background(), loaderCoord)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if len(proj.Edges) != 5 {
		t.Fatalf("the projection carries %d edges, want all 5 — nothing is dropped here", len(proj.Edges))
	}
	want := []ports.CallGraphReflectSite{{
		CallerID: "github.com/foo/bar.bind",
		CalleeID: "reflect.(Value).MethodByName",
		File:     "bind.go",
		Line:     10,
	}}
	if !slices.Equal(proj.ReflectiveDispatch, want) {
		t.Errorf("the projection names %+v as reflective dispatch, want %+v", proj.ReflectiveDispatch, want)
	}
}
