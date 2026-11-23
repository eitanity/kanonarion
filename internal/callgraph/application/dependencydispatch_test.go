package application_test

import (
	"context"
	"errors"
	"testing"

	"code.eitanity.com/kanonarion/internal/callgraph/application"
	cgports "code.eitanity.com/kanonarion/internal/callgraph/ports"
	"code.eitanity.com/kanonarion/internal/coordinate"
	"code.eitanity.com/kanonarion/internal/gotoolchain"
)

// dispatchSpy is pipelineSpy that also reads the dispatch rows.
type dispatchSpy struct {
	pipelineSpy
	err error
}

func (s *dispatchSpy) DependencyDispatchOf(_ context.Context, ids []string, pv string, _ coordinate.ModuleSet, _ gotoolchain.Version) (map[string]string, error) {
	if s.err != nil {
		return nil, s.err
	}
	return map[string]string{ids[0]: pv}, nil
}

var _ cgports.CallGraphDispatchReader = (*dispatchSpy)(nil)

// A store that cannot read the rows says so, rather than answering "no facts";
// one that can is read at the served pipeline when none is named.
func TestDependencyDispatchOf_SaysWhetherTheStoreCouldAnswer(t *testing.T) {
	ctx := context.Background()
	if _, found, err := application.NewQueryCallGraphUseCase(&pipelineSpy{seen: map[string][]string{}}).
		DependencyDispatchOf(ctx, []string{"m.(*T).Read"}, "", coordinate.ModuleSet{}, ""); found || err != nil {
		t.Errorf("a store without the read: found=%v err=%v, want not found", found, err)
	}
	uc := application.NewQueryCallGraphUseCase(&dispatchSpy{pipelineSpy: pipelineSpy{seen: map[string][]string{}}})
	got, found, err := uc.DependencyDispatchOf(ctx, []string{"m.(*T).Read"}, "", coordinate.ModuleSet{}, "")
	if err != nil || !found || got["m.(*T).Read"] != application.PipelineVersion {
		t.Errorf("DependencyDispatchOf = %v, %v, %v; want the row at the served pipeline", got, found, err)
	}
	failing := application.NewQueryCallGraphUseCase(&dispatchSpy{pipelineSpy: pipelineSpy{seen: map[string][]string{}}, err: errors.New("disk")})
	if _, _, err := failing.DependencyDispatchOf(ctx, []string{"x"}, "", coordinate.ModuleSet{}, ""); err == nil {
		t.Error("a failing read returned no error")
	}
}
