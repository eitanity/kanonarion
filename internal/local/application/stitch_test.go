package application_test

import (
	"context"
	"errors"
	"testing"

	"github.com/eitanity/kanonarion/internal/coordinate"

	callgraphdomain "github.com/eitanity/kanonarion/internal/callgraph/domain"

	"github.com/eitanity/kanonarion/internal/local/application"
	"github.com/eitanity/kanonarion/internal/local/ports"
)

// fakeDependencyLoader is an in-memory implementation of ports.DependencyLoader.
type fakeDependencyLoader struct {
	records map[string]callgraphdomain.CallGraphRecord // keyed by module path
	err     error
}

func (f *fakeDependencyLoader) LoadCallGraphRecords(_ context.Context, coords []coordinate.ModuleCoordinate, _ string) ([]callgraphdomain.CallGraphRecord, error) {
	if f.err != nil {
		return nil, f.err
	}
	out := make([]callgraphdomain.CallGraphRecord, 0, len(coords))
	for _, c := range coords {
		if r, ok := f.records[c.Path]; ok {
			out = append(out, r)
		}
	}
	return out, nil
}

// Compile-time interface check.
var _ ports.DependencyLoader = (*fakeDependencyLoader)(nil)

func coord(t *testing.T, path, ver string) coordinate.ModuleCoordinate {
	t.Helper()
	c, err := coordinate.NewModuleCoordinate(path, ver)
	if err != nil {
		t.Fatalf("NewModuleCoordinate: %v", err)
	}
	return c
}

func TestLoadDependenciesUseCase_Execute_LoadsSession(t *testing.T) {
	c := coord(t, "example.com/dep", "v1.0.0")
	loader := &fakeDependencyLoader{
		records: map[string]callgraphdomain.CallGraphRecord{
			"example.com/dep": {
				Coordinate:    c,
				OverallStatus: callgraphdomain.CallGraphStatusExtracted,
				Nodes: []callgraphdomain.CallNode{
					{ID: "example.com/dep.Func", Module: "example.com/dep", Package: "example.com/dep", Symbol: "Func"},
				},
			},
		},
	}
	uc := application.NewLoadDependenciesUseCase(loader, "0.1.0")
	session, err := uc.Execute(context.Background(), []coordinate.ModuleCoordinate{c})
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if session.ModuleCount() != 1 {
		t.Errorf("ModuleCount = %d, want 1", session.ModuleCount())
	}
	if _, ok := session.FindNode("example.com/dep.Func"); !ok {
		t.Error("FindNode: example.com/dep.Func not found in session")
	}
}

func TestLoadDependenciesUseCase_Execute_SilentlySkipsMissingCoords(t *testing.T) {
	loader := &fakeDependencyLoader{records: map[string]callgraphdomain.CallGraphRecord{}}
	uc := application.NewLoadDependenciesUseCase(loader, "0.1.0")

	coords := []coordinate.ModuleCoordinate{
		coord(t, "example.com/missing", "v1.0.0"),
	}
	session, err := uc.Execute(context.Background(), coords)
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if session.ModuleCount() != 0 {
		t.Errorf("ModuleCount = %d, want 0 (missing coords should be silently omitted)", session.ModuleCount())
	}
}

func TestLoadDependenciesUseCase_Execute_EmptyCoords(t *testing.T) {
	loader := &fakeDependencyLoader{}
	uc := application.NewLoadDependenciesUseCase(loader, "0.1.0")
	session, err := uc.Execute(context.Background(), nil)
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if session.ModuleCount() != 0 {
		t.Errorf("ModuleCount = %d, want 0", session.ModuleCount())
	}
}

func TestLoadDependenciesUseCase_Execute_LoaderError(t *testing.T) {
	loaderErr := errors.New("store unavailable")
	loader := &fakeDependencyLoader{err: loaderErr}
	uc := application.NewLoadDependenciesUseCase(loader, "0.1.0")

	_, err := uc.Execute(context.Background(), []coordinate.ModuleCoordinate{
		coord(t, "example.com/dep", "v1.0.0"),
	})
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !errors.Is(err, loaderErr) {
		t.Errorf("error = %v, want wrapping %v", err, loaderErr)
	}
}

func TestLoadDependenciesUseCase_Execute_MultipleModules(t *testing.T) {
	cA := coord(t, "example.com/a", "v1.0.0")
	cB := coord(t, "example.com/b", "v2.0.0")
	loader := &fakeDependencyLoader{
		records: map[string]callgraphdomain.CallGraphRecord{
			"example.com/a": {Coordinate: cA, OverallStatus: callgraphdomain.CallGraphStatusExtracted},
			"example.com/b": {Coordinate: cB, OverallStatus: callgraphdomain.CallGraphStatusExtracted},
		},
	}
	uc := application.NewLoadDependenciesUseCase(loader, "0.1.0")
	session, err := uc.Execute(context.Background(), []coordinate.ModuleCoordinate{cA, cB})
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if session.ModuleCount() != 2 {
		t.Errorf("ModuleCount = %d, want 2", session.ModuleCount())
	}
	if _, ok := session.ModuleRecord("example.com/a"); !ok {
		t.Error("ModuleRecord: example.com/a not found")
	}
	if _, ok := session.ModuleRecord("example.com/b"); !ok {
		t.Error("ModuleRecord: example.com/b not found")
	}
}
