package application_test

import (
	"context"
	"errors"
	"reflect"
	"testing"

	"code.eitanity.com/kanonarion/internal/callgraph/application"
	cgports "code.eitanity.com/kanonarion/internal/callgraph/ports"
	"code.eitanity.com/kanonarion/internal/coordinate"
)

// unservedFake is frontierBatchFake that also names superseded holders: holds
// maps a symbol to the coordinate holding a superseded edge touching it, and
// served lists the coordinates that also hold a served generation.
type unservedFake struct {
	frontierBatchFake
	holds         map[string]coordinate.ModuleCoordinate
	served        map[coordinate.ModuleCoordinate]bool
	holderCalls   [][]string
	holderErr     error
	unservedErr   error
	unservedCalls int
}

func (s *unservedFake) holders(syms []string) ([]coordinate.ModuleCoordinate, error) {
	s.holderCalls = append(s.holderCalls, append([]string(nil), syms...))
	if s.holderErr != nil {
		return nil, s.holderErr
	}
	var out []coordinate.ModuleCoordinate
	for _, sym := range syms {
		if c, ok := s.holds[sym]; ok {
			out = append(out, c)
		}
	}
	return out, nil
}

func (s *unservedFake) SupersededCallerHolders(_ context.Context, syms []string, _ string, _ coordinate.ModuleSet, _ cgports.EdgeQueryOptions) ([]coordinate.ModuleCoordinate, error) {
	return s.holders(syms)
}

func (s *unservedFake) SupersededCalleeHolders(_ context.Context, syms []string, _ string, _ coordinate.ModuleSet, _ cgports.EdgeQueryOptions) ([]coordinate.ModuleCoordinate, error) {
	return s.holders(syms)
}

func (s *unservedFake) UnservedCoordinates(_ context.Context, coords []coordinate.ModuleCoordinate, _ string) ([]cgports.UnservedCoordinate, error) {
	s.unservedCalls++
	if s.unservedErr != nil {
		return nil, s.unservedErr
	}
	seen := map[coordinate.ModuleCoordinate]bool{}
	var out []cgports.UnservedCoordinate
	for _, c := range coords {
		if s.served[c] || seen[c] {
			continue
		}
		seen[c] = true
		out = append(out, cgports.UnservedCoordinate{Coordinate: c, Pipelines: []string{"0.0.1"}})
	}
	return out, nil
}

var _ cgports.CallGraphUnservedReader = (*unservedFake)(nil)

func mustCoordinate(t *testing.T, path string) coordinate.ModuleCoordinate {
	t.Helper()
	c, err := coordinate.NewModuleCoordinate(path, "v1.0.0")
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func newUnservedFake(t *testing.T) (*unservedFake, coordinate.ModuleCoordinate, coordinate.ModuleCoordinate) {
	t.Helper()
	old := mustCoordinate(t, "example.com/old")
	mixed := mustCoordinate(t, "example.com/mixed")
	s := &unservedFake{
		holds:  map[string]coordinate.ModuleCoordinate{"root": old, "a2": mixed, "b4": old, "c1": mustCoordinate(t, "example.com/beyond")},
		served: map[coordinate.ModuleCoordinate]bool{mixed: true},
	}
	s.callers, s.callees = layeredCallers(), layeredCallers()
	return s, old, mixed
}

// TestTraverse_AsksHoldersOncePerLevelOfTheSameFrontier: one holder statement
// per expanded level, over exactly the frontier the edge query was given; a
// coordinate holding a served generation is not named, and the unexpanded
// frontier of a bounded walk is not asked about.
func TestTraverse_AsksHoldersOncePerLevelOfTheSameFrontier(t *testing.T) {
	for name, traverse := range map[string]func(*application.QueryCallGraphUseCase, context.Context, application.TraversalRequest) (application.TraversalResult, error){
		"callers": (*application.QueryCallGraphUseCase).TraverseCallers,
		"callees": (*application.QueryCallGraphUseCase).TraverseCallees,
	} {
		t.Run(name, func(t *testing.T) {
			s, old, _ := newUnservedFake(t)
			res, err := traverse(application.NewQueryCallGraphUseCase(s), context.Background(), traversal(2))
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(s.holderCalls, s.frontiers) {
				t.Errorf("holders were asked %v, the edge query %v", s.holderCalls, s.frontiers)
			}
			want := []cgports.UnservedCoordinate{{Coordinate: old, Pipelines: []string{"0.0.1"}}}
			if !reflect.DeepEqual(res.NotSearched, want) || s.unservedCalls != 1 {
				t.Errorf("NotSearched = %+v after %d resolution(s), want %+v once", res.NotSearched, s.unservedCalls, want)
			}
		})
	}
}

// TestTraverse_AStoreThatCannotSayNamesNothing: the capability is optional.
func TestTraverse_AStoreThatCannotSayNamesNothing(t *testing.T) {
	s := &frontierBatchFake{frontierFake{callers: layeredCallers()}}
	uc := application.NewQueryCallGraphUseCase(s)
	res, err := uc.TraverseCallers(context.Background(), traversal(0))
	if err != nil || res.NotSearched != nil {
		t.Errorf("NotSearched = %v, %v; want nothing", res.NotSearched, err)
	}
	got, err := uc.NotSearchedByCallers(context.Background(), []string{"root"}, "0.1.0", coordinate.ModuleSet{}, cgports.EdgeQueryOptions{})
	if err != nil || got != nil {
		t.Errorf("NotSearchedByCallers = %v, %v; want nothing", got, err)
	}
}

// TestNotSearched_OneHopNamesTheUnservedHolders covers both directions.
func TestNotSearched_OneHopNamesTheUnservedHolders(t *testing.T) {
	s, old, _ := newUnservedFake(t)
	uc := application.NewQueryCallGraphUseCase(s)
	ctx := context.Background()
	for _, find := range []func(context.Context, []string, string, coordinate.ModuleSet, cgports.EdgeQueryOptions) ([]cgports.UnservedCoordinate, error){
		uc.NotSearchedByCallers, uc.NotSearchedByCallees,
	} {
		got, err := find(ctx, []string{"root", "a2"}, "0.1.0", coordinate.ModuleSet{}, cgports.EdgeQueryOptions{})
		if err != nil || len(got) != 1 || got[0].Coordinate != old {
			t.Errorf("= %+v, %v; want old alone", got, err)
		}
	}
	if got, err := uc.UnservedCoordinates(ctx, nil, "0.1.0"); err != nil || got != nil {
		t.Errorf("no coordinates = %v, %v; want nothing asked", got, err)
	}
}

// TestNotSearched_StoreErrorsAreReturned: a failed read fails the answer
// rather than shrinking what it names.
func TestNotSearched_StoreErrorsAreReturned(t *testing.T) {
	boom := errors.New("boom")
	ctx := context.Background()

	s, _, _ := newUnservedFake(t)
	s.holderErr = boom
	uc := application.NewQueryCallGraphUseCase(s)
	if _, err := uc.TraverseCallers(ctx, traversal(0)); !errors.Is(err, boom) {
		t.Errorf("traversal holder error = %v", err)
	}
	if _, err := uc.NotSearchedByCallees(ctx, []string{"root"}, "0.1.0", coordinate.ModuleSet{}, cgports.EdgeQueryOptions{}); !errors.Is(err, boom) {
		t.Errorf("one-hop holder error = %v", err)
	}

	s, _, _ = newUnservedFake(t)
	s.unservedErr = boom
	uc = application.NewQueryCallGraphUseCase(s)
	if _, err := uc.TraverseCallees(ctx, traversal(0)); !errors.Is(err, boom) {
		t.Errorf("traversal resolution error = %v", err)
	}
}
