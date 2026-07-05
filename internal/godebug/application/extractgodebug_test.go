package application_test

import (
	"context"
	"testing"

	"github.com/eitanity/kanonarion/internal/adapters/clock"
	"github.com/eitanity/kanonarion/internal/audit"
	configdomain "github.com/eitanity/kanonarion/internal/config/domain"
	"github.com/eitanity/kanonarion/internal/godebug/application"
	"github.com/eitanity/kanonarion/internal/godebug/domain"
)

type fakeScanner struct{ res domain.ParseResult }

func (f fakeScanner) ScanProject(string) (domain.ParseResult, error) { return f.res, nil }

type fakeStore struct{ put *domain.Record }

func (s *fakeStore) PutGoDebugRecord(_ context.Context, r domain.Record) error {
	s.put = &r
	return nil
}
func (s *fakeStore) GetGoDebugRecord(context.Context, string) (domain.Record, bool, error) {
	if s.put == nil {
		return domain.Record{}, false, nil
	}
	return *s.put, true, nil
}

type fakeSink struct{ events []audit.Event }

func (s *fakeSink) RecordEvent(e audit.Event) error {
	s.events = append(s.events, e)
	return nil
}

func newUC(res domain.ParseResult) (*application.ExtractGoDebugUseCase, *fakeStore, *fakeSink) {
	store := &fakeStore{}
	sink := &fakeSink{}
	uc := application.NewExtractGoDebugUseCase(application.Config{
		Scanner: fakeScanner{res: res}, Store: store, Audit: sink,
		Clock: clock.Fixed{}, Stopwatch: clock.Monotonic{},
	})
	return uc, store, sink
}

// TestExtract_ClassifiesPolicyAndAudits is the regression: a red
// setting applied in the main module's main package classifies red, is
// blocked by the default policy, persists a deterministic record carrying the
// taxonomy version, and emits one godebug audit event per setting.
func TestExtract_ClassifiesPolicyAndAudits(t *testing.T) {
	uc, store, sink := newUC(domain.ParseResult{
		ProjectModulePath: "example.com/proj",
		Settings: []domain.Setting{
			{Name: "tlsrsakex", Value: "1", Source: "main.go", Line: 4,
				Module: "example.com/proj", Applied: true},
		},
	})

	rec, err := uc.Extract(context.Background(), "go.mod", configdomain.DefaultConfig().GoDebugPolicy)
	if err != nil {
		t.Fatalf("Extract: %v", err)
	}
	if rec.ContentHash == "" || rec.SchemaVersion != domain.GoDebugSchemaVersion {
		t.Errorf("record metadata not set: %+v", rec)
	}
	if rec.TaxonomyVersion != domain.TaxonomyVersion() || rec.TaxonomyVersion == "" {
		t.Errorf("taxonomy version not recorded: %q", rec.TaxonomyVersion)
	}
	if store.put == nil {
		t.Fatal("record was not persisted")
	}
	got := rec.Settings[0]
	if got.Tier != domain.TierRed {
		t.Errorf("tier = %v, want red", got.Tier)
	}
	if got.PolicyOutcome != string(configdomain.PolicyOutcomeWarn) || !got.PolicyBlocking {
		t.Errorf("default policy must block applied red setting: %+v", got)
	}
	if len(sink.events) != 1 || sink.events[0].Type != audit.EventGoDebugSettingObserved {
		t.Fatalf("want 1 godebug audit event, got %+v", sink.events)
	}
	if err := sink.events[0].Validate(); err != nil {
		t.Errorf("invalid audit event: %v", err)
	}
}

// TestExtract_DependencySettingRecordedNotApplied is the acceptance
// case: a //go:debug carried by a dependency main package is recorded and
// classified but, being not-applied, never gates the build (it has no effect
// on the current binary) — yet it is still surfaced, never silently dropped.
func TestExtract_DependencySettingRecordedNotApplied(t *testing.T) {
	uc, _, sink := newUC(domain.ParseResult{
		ProjectModulePath: "example.com/proj",
		Settings: []domain.Setting{
			{Name: "tlsrsakex", Value: "1", Source: "vendor/example.com/dep/main.go",
				Line: 3, Module: "example.com/dep", Applied: false},
		},
	})

	rec, err := uc.Extract(context.Background(), "go.mod", configdomain.DefaultConfig().GoDebugPolicy)
	if err != nil {
		t.Fatalf("Extract: %v", err)
	}
	s := rec.Settings[0]
	if s.Tier != domain.TierRed {
		t.Errorf("dependency setting still classified: tier = %v, want red", s.Tier)
	}
	if s.Applied {
		t.Error("dependency setting must be recorded not-applied")
	}
	if s.PolicyBlocking {
		t.Error("not-applied setting must not gate the build")
	}
	if len(sink.events) != 1 {
		t.Fatalf("not-applied setting must still be audited, got %d events", len(sink.events))
	}
}

// TestExtract_CleanProject: no //go:debug anywhere yields an empty,
// deterministic record and no audit events (clean case).
func TestExtract_CleanProject(t *testing.T) {
	uc, store, sink := newUC(domain.ParseResult{ProjectModulePath: "example.com/proj"})
	rec, err := uc.Extract(context.Background(), "go.mod", configdomain.DefaultConfig().GoDebugPolicy)
	if err != nil {
		t.Fatalf("Extract: %v", err)
	}
	if len(rec.Settings) != 0 || rec.ContentHash == "" {
		t.Errorf("clean scan should be empty but hashed: %+v", rec)
	}
	if store.put == nil {
		t.Fatal("clean record must still be persisted")
	}
	if len(sink.events) != 0 {
		t.Errorf("clean scan must emit no audit events, got %d", len(sink.events))
	}
}
