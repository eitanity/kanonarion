package application_test

import (
	"context"
	"testing"

	"github.com/eitanity/kanonarion/internal/adapters/clock"
	"github.com/eitanity/kanonarion/internal/audit"
	configdomain "github.com/eitanity/kanonarion/internal/config/domain"
	"github.com/eitanity/kanonarion/internal/directive/application"
	"github.com/eitanity/kanonarion/internal/directive/domain"
)

type fakeParser struct{ res domain.ParseResult }

func (f fakeParser) ParseProject(string) (domain.ParseResult, error) { return f.res, nil }

type fakeStore struct{ put *domain.Record }

func (s *fakeStore) PutDirectiveRecord(_ context.Context, r domain.Record) error {
	s.put = &r
	return nil
}
func (s *fakeStore) GetDirectiveRecord(context.Context, string) (domain.Record, bool, error) {
	if s.put == nil {
		return domain.Record{}, false, nil
	}
	return *s.put, true, nil
}
func (s *fakeStore) GetScanByID(_ context.Context, scanID string) (domain.Record, bool, error) {
	if s.put == nil || s.put.ID != scanID {
		return domain.Record{}, false, nil
	}
	return *s.put, true, nil
}
func (s *fakeStore) ListScans(context.Context, string, int) ([]domain.Record, error) {
	if s.put == nil {
		return nil, nil
	}
	return []domain.Record{*s.put}, nil
}

type fakeSink struct{ events []audit.Event }

func (s *fakeSink) RecordEvent(e audit.Event) error {
	s.events = append(s.events, e)
	return nil
}

// TestExtract_ClassifiesPolicyAndAudits is the regression: the use
// case must classify each directive, evaluate the governance policy (default
// posture flags a local-path replace), persist a deterministic record, and
// emit one audit event per directive with the event type.
func TestExtract_ClassifiesPolicyAndAudits(t *testing.T) {
	parser := fakeParser{res: domain.ParseResult{
		ProjectModulePath: "example.com/proj",
		ResolvedVersions:  map[string]string{"example.com/dep": "v1.2.0"},
		Directives: []domain.Directive{
			{Kind: domain.KindReplace, Source: "go.mod", Line: 7,
				OldPath: "example.com/dep", IsLocal: true, LocalPath: "../dep", Applied: true},
			{Kind: domain.KindExclude, Source: "go.mod", Line: 9,
				OldPath: "example.com/dep", OldVersion: "v1.3.0", Applied: true},
		},
	}}
	store := &fakeStore{}
	sink := &fakeSink{}

	uc := application.NewExtractDirectivesUseCase(application.Config{
		Parser: parser, Store: store, Audit: sink,
		Clock: clock.Fixed{}, Stopwatch: clock.Monotonic{},
	})

	rec, err := uc.Extract(context.Background(), "go.mod", configdomain.DefaultConfig().DirectivePolicy)
	if err != nil {
		t.Fatalf("Extract: %v", err)
	}

	if rec.ContentHash == "" || rec.SchemaVersion != domain.DirectiveSchemaVersion {
		t.Errorf("record metadata not set: %+v", rec)
	}
	if store.put == nil {
		t.Fatal("record was not persisted")
	}

	var localRepl, exc *domain.Directive
	for i := range rec.Directives {
		switch rec.Directives[i].Kind {
		case domain.KindReplace:
			localRepl = &rec.Directives[i]
		case domain.KindExclude:
			exc = &rec.Directives[i]
		}
	}
	if localRepl.Class != domain.RiskHighest {
		t.Errorf("local replace class = %v, want highest", localRepl.Class)
	}
	if localRepl.PolicyOutcome != string(configdomain.PolicyOutcomeWarn) || !localRepl.PolicyBlocking {
		t.Errorf("default policy must flag local-path replace: %+v", localRepl)
	}
	if localRepl.ReachabilityTarget != "../dep" {
		t.Errorf("reachability target = %q, want ../dep", localRepl.ReachabilityTarget)
	}
	if exc.Class != domain.RiskHigh {
		t.Errorf("exclude-newer class = %v, want high", exc.Class)
	}

	if len(sink.events) != 2 {
		t.Fatalf("want 2 audit events, got %d", len(sink.events))
	}
	seen := map[audit.EventType]bool{}
	for _, e := range sink.events {
		if err := e.Validate(); err != nil {
			t.Errorf("emitted invalid audit event: %v", err)
		}
		seen[e.Type] = true
	}
	if !seen[audit.EventReplaceDirectiveObserved] || !seen[audit.EventExcludeDirectiveObserved] {
		t.Errorf("missing expected audit event types: %v", seen)
	}
}
