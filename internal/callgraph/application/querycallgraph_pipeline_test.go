package application_test

import (
	"context"
	"sync"
	"testing"

	"code.eitanity.com/kanonarion/internal/callgraph/application"
	"code.eitanity.com/kanonarion/internal/callgraph/domain"
	cgports "code.eitanity.com/kanonarion/internal/callgraph/ports"
	"code.eitanity.com/kanonarion/internal/coordinate"
	"code.eitanity.com/kanonarion/internal/gotoolchain"
)

// pipelineSpy records the pipeline version every read reaches the store with,
// and answers only at the current one, as a store holding only current
// generations does.
type pipelineSpy struct {
	mu   sync.Mutex
	seen map[string][]string
	held coordinate.ModuleCoordinate
}

func (s *pipelineSpy) saw(method, pv string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.seen[method] = append(s.seen[method], pv)
	return pv == application.PipelineVersion
}

func (s *pipelineSpy) PutCallGraphRecord(context.Context, domain.CallGraphRecord) error { return nil }

func (s *pipelineSpy) GetCallGraphRecord(_ context.Context, _ coordinate.ModuleCoordinate, pv string) (domain.CallGraphRecord, bool, error) {
	return domain.CallGraphRecord{}, s.saw("GetCallGraphRecord", pv), nil
}

func (s *pipelineSpy) ListCallGraphRecords(context.Context, cgports.CallGraphFilter) ([]cgports.CallGraphSummary, error) {
	return nil, nil
}

func (s *pipelineSpy) edges(method, pv string) []cgports.CallEdgeRef {
	if !s.saw(method, pv) {
		return nil
	}
	return []cgports.CallEdgeRef{{FromID: "example.com/m.A", ToID: "example.com/m.B", PipelineVersion: pv}}
}

func (s *pipelineSpy) FindCallers(_ context.Context, _, pv string, _ coordinate.ModuleSet, _ cgports.EdgeQueryOptions) ([]cgports.CallEdgeRef, error) {
	return s.edges("FindCallers", pv), nil
}

func (s *pipelineSpy) FindCallees(_ context.Context, _, pv string, _ coordinate.ModuleSet, _ cgports.EdgeQueryOptions) ([]cgports.CallEdgeRef, error) {
	return s.edges("FindCallees", pv), nil
}

func (s *pipelineSpy) ListCallGraphRecordsFor(_ context.Context, _ coordinate.ModuleCoordinate, pv string) ([]domain.CallGraphRecord, error) {
	if !s.saw("CallGraphHistory", pv) {
		return nil, nil
	}
	return []domain.CallGraphRecord{{}}, nil
}

func (s *pipelineSpy) GetCallGraphRecordFrom(_ context.Context, _ coordinate.ModuleCoordinate, pv string, _ domain.ComposeRequest) (domain.CallGraphRecord, bool, error) {
	return domain.CallGraphRecord{}, s.saw("GetCallGraphRecordFrom", pv), nil
}

func (s *pipelineSpy) WithReadFrame(domain.BuildFrame) {}

func (s *pipelineSpy) WorktreeRouting(_ context.Context, _ coordinate.ModuleCoordinate, pv string) (cgports.WorktreeRouting, bool, error) {
	return cgports.WorktreeRouting{}, s.saw("WorktreeRouting", pv), nil
}

func (s *pipelineSpy) ForeignModulesBuilt(_ context.Context, _ coordinate.ModuleCoordinate, pv string, _ gotoolchain.Version) ([]domain.ForeignModule, bool, error) {
	return nil, s.saw("ForeignModulesBuilt", pv), nil
}

func (s *pipelineSpy) holders(method, pv string) []coordinate.ModuleCoordinate {
	if !s.saw(method, pv) {
		return nil
	}
	return []coordinate.ModuleCoordinate{s.held}
}

func (s *pipelineSpy) SupersededCallerHolders(_ context.Context, _ []string, pv string, _ coordinate.ModuleSet, _ cgports.EdgeQueryOptions) ([]coordinate.ModuleCoordinate, error) {
	return s.holders("SupersededCallerHolders", pv), nil
}

func (s *pipelineSpy) SupersededCalleeHolders(_ context.Context, _ []string, pv string, _ coordinate.ModuleSet, _ cgports.EdgeQueryOptions) ([]coordinate.ModuleCoordinate, error) {
	return s.holders("SupersededCalleeHolders", pv), nil
}

func (s *pipelineSpy) UnservedCoordinates(_ context.Context, coords []coordinate.ModuleCoordinate, pv string) ([]cgports.UnservedCoordinate, error) {
	if !s.saw("UnservedCoordinates", pv) {
		return nil, nil
	}
	out := make([]cgports.UnservedCoordinate, 0, len(coords))
	for _, c := range coords {
		out = append(out, cgports.UnservedCoordinate{Coordinate: c})
	}
	return out, nil
}

// An empty pipeline version reads the current pipeline on every query that
// takes one. Passed through, it named no generation, and the read answered
// as if the store held nothing.
func TestQueryCallGraph_AnEmptyPipelineVersionReadsTheCurrentOne(t *testing.T) {
	ctx := context.Background()
	coord := mustCoordinate(t, "example.com/m")
	spy := &pipelineSpy{seen: map[string][]string{}, held: coord}
	uc := application.NewQueryCallGraphUseCase(spy)
	none := coordinate.ModuleSet{}
	opts := cgports.EdgeQueryOptions{}

	answered := map[string]func() (bool, error){
		"GetCallGraphRecord": func() (bool, error) {
			_, ok, err := uc.GetCallGraphRecord(ctx, coord, "")
			return ok, err
		},
		"CallGraphHistory": func() (bool, error) {
			recs, err := uc.CallGraphHistory(ctx, coord, "")
			return len(recs) > 0, err
		},
		"GetCallGraphRecordFrom": func() (bool, error) {
			_, ok, err := uc.GetCallGraphRecordFrom(ctx, coord, "", domain.ComposeRequest{})
			return ok, err
		},
		"WorktreeRouting": func() (bool, error) {
			_, ok, err := uc.WorktreeRouting(ctx, coord, "")
			return ok, err
		},
		"ForeignModulesBuilt": func() (bool, error) {
			_, ok, err := uc.ForeignModulesBuilt(ctx, coord, "", gotoolchain.Unrecorded)
			return ok, err
		},
		"FindCallers": func() (bool, error) {
			refs, err := uc.FindCallers(ctx, "example.com/m.B", "", none, opts)
			return len(refs) > 0, err
		},
		"FindCallees": func() (bool, error) {
			refs, err := uc.FindCallees(ctx, "example.com/m.A", "", none, opts)
			return len(refs) > 0, err
		},
		"NotSearchedByCallers": func() (bool, error) {
			un, err := uc.NotSearchedByCallers(ctx, []string{"example.com/m.B"}, "", none, opts)
			return len(un) > 0, err
		},
		"NotSearchedByCallees": func() (bool, error) {
			un, err := uc.NotSearchedByCallees(ctx, []string{"example.com/m.A"}, "", none, opts)
			return len(un) > 0, err
		},
		"UnservedCoordinates": func() (bool, error) {
			un, err := uc.UnservedCoordinates(ctx, []coordinate.ModuleCoordinate{coord}, "")
			return len(un) > 0, err
		},
		"TraverseCallers": func() (bool, error) {
			res, err := uc.TraverseCallers(ctx, application.TraversalRequest{SymbolID: "example.com/m.B"})
			return len(res.Edges) > 0, err
		},
		"TraverseCallees": func() (bool, error) {
			res, err := uc.TraverseCallees(ctx, application.TraversalRequest{SymbolID: "example.com/m.A"})
			return len(res.Edges) > 0, err
		},
	}
	for name, call := range answered {
		ok, err := call()
		if err != nil || !ok {
			t.Errorf("%s with an empty pipeline version = answered %v, %v; want the current pipeline's answer", name, ok, err)
		}
	}
	for method, pvs := range spy.seen {
		for _, pv := range pvs {
			if pv != application.PipelineVersion {
				t.Errorf("the store's %s was asked at pipeline %q, want %q", method, pv, application.PipelineVersion)
			}
		}
	}
}
