package application_test

import (
	"context"
	"testing"

	"github.com/eitanity/kanonarion/internal/adapters/clock"
	"github.com/eitanity/kanonarion/internal/audit"
	configdomain "github.com/eitanity/kanonarion/internal/config/domain"
	"github.com/eitanity/kanonarion/internal/vendortree/application"
	"github.com/eitanity/kanonarion/internal/vendortree/domain"
)

type fakeScanner struct{ res domain.ParseResult }

func (f fakeScanner) ScanProject(string, bool) (domain.ParseResult, error) { return f.res, nil }

type fakeStore struct{ put *domain.Record }

func (s *fakeStore) PutVendorRecord(_ context.Context, r domain.Record) error {
	s.put = &r
	return nil
}
func (s *fakeStore) GetVendorRecord(context.Context, string) (domain.Record, bool, error) {
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

// TestExtract_DriftBlockedAndAudited is the regression: a drifted
// vendored module is classified, blocked by the default policy (on_drift =
// warn), persisted deterministically, and the scan emits a vendor audit
// event with the event type.
func TestExtract_DriftBlockedAndAudited(t *testing.T) {
	store := &fakeStore{}
	sink := &fakeSink{}
	uc := application.NewExtractVendorUseCase(application.Config{
		Scanner: fakeScanner{res: domain.ParseResult{
			ProjectModulePath: "example.com/proj",
			VendorDir:         "vendor",
			VendorOnly:        true,
			ModulesTxt:        []domain.VendoredModule{{Path: "example.com/dep", Version: "v1.2.0", Explicit: true}},
			GoModRequires:     map[string]string{"example.com/dep": "v1.2.0"},
			GoSum:             map[string]string{"example.com/dep@v1.2.0": "h1:EXPECTED"},
			PresentDirs:       map[string]bool{"example.com/dep": true},
			ComputedHashes:    map[string]string{"example.com/dep": "h1:TAMPERED"},
		}},
		Store: store, Audit: sink,
		Clock: clock.Fixed{}, Stopwatch: clock.Monotonic{},
	})

	rec, err := uc.Extract(context.Background(), "go.mod", true, configdomain.DefaultConfig().VendorPolicy)
	if err != nil {
		t.Fatalf("Extract: %v", err)
	}
	if rec.ContentHash == "" || rec.SchemaVersion != domain.VendorSchemaVersion {
		t.Errorf("record metadata not set: %+v", rec)
	}
	if rec.OverallStatus != "findings" || !rec.VendorOnly {
		t.Errorf("unexpected record posture: %+v", rec)
	}
	if store.put == nil {
		t.Fatal("record not persisted")
	}
	var drift *domain.Finding
	for i := range rec.Findings {
		if rec.Findings[i].Kind == domain.FindingDrift {
			drift = &rec.Findings[i]
		}
	}
	if drift == nil || drift.PolicyOutcome != string(configdomain.PolicyOutcomeWarn) || !drift.PolicyBlocking {
		t.Errorf("default policy must block drift: %+v", rec.Findings)
	}
	if len(sink.events) != 1 || sink.events[0].Type != audit.EventVendorTreeGenerated {
		t.Fatalf("want 1 vendor_tree_generated event, got %+v", sink.events)
	}
	if err := sink.events[0].Validate(); err != nil {
		t.Errorf("invalid audit event: %v", err)
	}
}

// TestExtract_CleanNoFindings: a reconciled tree with no discrepancies is a
// confident clean, still persisted and audited.
func TestExtract_CleanNoFindings(t *testing.T) {
	store := &fakeStore{}
	sink := &fakeSink{}
	uc := application.NewExtractVendorUseCase(application.Config{
		Scanner: fakeScanner{res: domain.ParseResult{
			ProjectModulePath: "example.com/proj",
			VendorDir:         "vendor",
			ModulesTxt:        []domain.VendoredModule{{Path: "example.com/dep", Version: "v1.2.0"}},
			GoModRequires:     map[string]string{"example.com/dep": "v1.2.0"},
			GoSum:             map[string]string{"example.com/dep@v1.2.0": "h1:OK"},
			PresentDirs:       map[string]bool{"example.com/dep": true},
			ComputedHashes:    map[string]string{"example.com/dep": "h1:OK"},
		}},
		Store: store, Audit: sink,
		Clock: clock.Fixed{}, Stopwatch: clock.Monotonic{},
	})
	rec, err := uc.Extract(context.Background(), "go.mod", false, configdomain.DefaultConfig().VendorPolicy)
	if err != nil {
		t.Fatalf("Extract: %v", err)
	}
	if rec.OverallStatus != "clean" || len(rec.Findings) != 0 {
		t.Errorf("want clean, got %+v", rec)
	}
	if len(sink.events) != 1 {
		t.Errorf("clean scan must still be audited, got %d events", len(sink.events))
	}
}
