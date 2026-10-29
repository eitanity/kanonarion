package application_test

import (
	"context"
	"errors"
	"strings"
	"testing"

	"code.eitanity.com/kanonarion/internal/callgraph/application"
	"code.eitanity.com/kanonarion/internal/callgraph/domain"
	cgports "code.eitanity.com/kanonarion/internal/callgraph/ports"
	"code.eitanity.com/kanonarion/internal/coordinate"
)

const (
	implIface = "example.com/m/ports.Store"
	implType  = "example.com/m/adapter.(*S)"
)

// implementersStore serves one record of example.com/m at the current
// pipeline, declaring implIface and its one production implementer, and a
// second version held only at an older pipeline.
type implementersStore struct {
	queryCGFakeStore
	partial bool
}

func newImplementersStore(t *testing.T) *implementersStore {
	t.Helper()
	rec := domain.CallGraphRecord{
		Coordinate: mustCoordinate(t, "example.com/m"), PipelineVersion: application.PipelineVersion,
		OverallStatus: domain.CallGraphStatusExtracted, Completeness: domain.CompletenessBuiltWithBodies,
		TestScope:  domain.TestScopeAnalysed,
		Interfaces: []domain.InterfaceType{{ID: implIface, Methods: []string{"Put"}}},
		Implementations: []domain.InterfaceImplementation{{
			InterfaceID: implIface, TypeID: implType,
			Methods: []domain.ImplementedMethod{{Method: "Put", NodeID: implType + ".Put"}},
		}},
	}
	s := &implementersStore{}
	if err := s.PutCallGraphRecord(context.Background(), rec); err != nil {
		t.Fatal(err)
	}
	return s
}

func (s *implementersStore) ListCallGraphCoordinates(_ context.Context, f cgports.CallGraphFilter) ([]cgports.CallGraphCoordinate, error) {
	all := []cgports.CallGraphCoordinate{
		{ModulePath: "example.com/m", ModuleVersion: "v1.0.0", PipelineVersion: application.PipelineVersion},
		{ModulePath: "example.com/m", ModuleVersion: "v0.9.0", PipelineVersion: "0.0.1"},
	}
	var out []cgports.CallGraphCoordinate
	for _, c := range all {
		if f.PipelineVersion == "" || f.PipelineVersion == c.PipelineVersion {
			out = append(out, c)
		}
	}
	return out, nil
}

func (s *implementersStore) GetCallGraphRecordFrom(ctx context.Context, c coordinate.ModuleCoordinate, pv string, _ domain.ComposeRequest) (domain.CallGraphRecord, bool, error) {
	rec, ok, err := s.GetCallGraphRecord(ctx, c, pv)
	if s.partial {
		rec.OverallStatus, rec.FailedPackages, rec.Implementations = domain.CallGraphStatusPartial, []string{"example.com/m/ports"}, nil
	}
	return rec, ok, err
}

func (s *implementersStore) UnservedCoordinates(_ context.Context, coords []coordinate.ModuleCoordinate, _ string) ([]cgports.UnservedCoordinate, error) {
	out := make([]cgports.UnservedCoordinate, 0, len(coords))
	for _, c := range coords {
		out = append(out, cgports.UnservedCoordinate{Coordinate: c, Pipelines: []string{"0.0.1"}})
	}
	return out, nil
}

func TestImplementers_NamesTheTypeAndItsMethod(t *testing.T) {
	s := newImplementersStore(t)
	uc := application.NewQueryCallGraphUseCase(s)
	res, err := application.FindImplementers(context.Background(), s, application.ImplementersRequest{InterfaceID: "example.com/m/ports.(Store).Put"})
	if err != nil || len(res.Implementers) != 1 || res.Implementers[0].NodeID != implType+".Put" || res.Method != "Put" ||
		res.Answer.Outcome != domain.AnswerResolvedPresent || res.ModulePath != "example.com/m" || len(res.NotSearched) != 1 {
		t.Fatalf("FindImplementers = %+v, %v", res, err)
	}
	// The use case's own method reads through the same function.
	if again, err := uc.Implementers(context.Background(), application.ImplementersRequest{InterfaceID: implIface}); err != nil ||
		len(again.Implementers) != 1 || again.Implementers[0].NodeID != "" {
		t.Errorf("Implementers through the use case = %+v, %v", again, err)
	}
}

func TestImplementers_TestsExcludedAndAnUnresolvedAbsence(t *testing.T) {
	s := newImplementersStore(t)
	s.partial = true
	res, err := application.FindImplementers(context.Background(), s, application.ImplementersRequest{InterfaceID: implIface, Opts: cgports.EdgeQueryOptions{ExcludeTests: true}})
	if err != nil || len(res.Implementers) != 0 || res.Answer.Outcome != domain.AnswerUnresolved || res.Method != "" {
		t.Fatalf("FindImplementers on a partial record = %+v, %v; want UNRESOLVED", res, err)
	}
}

func TestImplementers_Refusals(t *testing.T) {
	s := newImplementersStore(t)
	ctx := context.Background()
	if _, err := application.FindImplementers(ctx, s, application.ImplementersRequest{InterfaceID: "example.com/m/ports.(Store).Get"}); err == nil ||
		!strings.Contains(err.Error(), `declares no method "Get"`) {
		t.Errorf("unknown method = %v", err)
	}
	var miss *application.InterfaceNotDeclaredError
	_, err := application.FindImplementers(ctx, s, application.ImplementersRequest{InterfaceID: "example.com/m/ports.Other"})
	if !errors.As(err, &miss) || !miss.ModuleAnalysed || !miss.ServedAny || miss.Error() == "" {
		t.Errorf("undeclared interface = %v", err)
	}
	_, err = application.FindImplementers(ctx, s, application.ImplementersRequest{InterfaceID: "example.org/x.Store"})
	if !errors.As(err, &miss) || miss.ModuleAnalysed || !strings.Contains(miss.Error(), "no module") {
		t.Errorf("interface of an unanalysed module = %v", err)
	}
	var sup *application.SupersededModuleError
	_, err = application.FindImplementers(ctx, s, application.ImplementersRequest{InterfaceID: implIface, PipelineVersion: "9.9.9"})
	if !errors.As(err, &sup) || sup.ModulePath != "example.com/m" || !strings.Contains(sup.Error(), "superseded") {
		t.Errorf("module held only at other pipelines = %v", err)
	}
	scope := coordinate.NewModuleSet([]coordinate.ModuleCoordinate{mustCoordinate(t, "example.com/other")})
	if _, err = application.FindImplementers(ctx, s, application.ImplementersRequest{InterfaceID: implIface, Scope: scope}); !errors.As(err, &miss) {
		t.Errorf("out-of-scope module = %v", err)
	}
}
