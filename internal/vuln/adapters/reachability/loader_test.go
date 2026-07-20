package reachability_test

import (
	"context"
	"errors"
	"testing"

	callgraphdomain "github.com/eitanity/kanonarion/internal/callgraph/domain"
	cgports "github.com/eitanity/kanonarion/internal/callgraph/ports"
	fetchdomain "github.com/eitanity/kanonarion/internal/fetch/domain"
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

func (s *fakeStore) GetCallGraphRecord(_ context.Context, _ fetchdomain.ModuleCoordinate, _ string) (callgraphdomain.CallGraphRecord, bool, error) {
	return s.record, s.found, s.err
}

func (s *fakeStore) PutCallGraphRecord(context.Context, callgraphdomain.CallGraphRecord) error {
	return nil
}

func (s *fakeStore) ListCallGraphRecords(context.Context, cgports.CallGraphFilter) ([]cgports.CallGraphSummary, error) {
	return nil, nil
}

func (s *fakeStore) FindCallers(context.Context, string, string) ([]cgports.CallEdgeRef, error) {
	return nil, nil
}

func (s *fakeStore) FindCallees(context.Context, string, string) ([]cgports.CallEdgeRef, error) {
	return nil, nil
}

var loaderCoord = fetchdomain.ModuleCoordinate{Path: "github.com/foo/bar", Version: "v1.0.0"}

func TestLoad_ProjectsRecord(t *testing.T) {
	rec := callgraphdomain.CallGraphRecord{
		Algorithm:    callgraphdomain.AlgorithmCHA,
		Completeness: callgraphdomain.CompletenessBuiltWithBodies,
		ArtifactKind: callgraphdomain.ArtifactApplication,
		Nodes: []callgraphdomain.CallNode{{
			ID: "github.com/foo/bar.Fn", Module: "github.com/foo/bar",
			Package: "github.com/foo/bar", Symbol: "Fn", Receiver: "T", IsExportedAPI: true,
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
	want := ports.CallGraphNode{
		ID: "github.com/foo/bar.Fn", Module: "github.com/foo/bar",
		Package: "github.com/foo/bar", Symbol: "Fn", Receiver: "T", IsExportedAPI: true,
	}
	if len(proj.Nodes) != 1 || proj.Nodes[0] != want {
		t.Errorf("Nodes = %+v, want [%+v]", proj.Nodes, want)
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
