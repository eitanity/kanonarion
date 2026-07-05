package application_test

import (
	"context"
	"testing"

	"github.com/eitanity/kanonarion/internal/adapters/clock"
	"github.com/eitanity/kanonarion/internal/audit"
	configdomain "github.com/eitanity/kanonarion/internal/config/domain"
	"github.com/eitanity/kanonarion/internal/fips/application"
	"github.com/eitanity/kanonarion/internal/fips/domain"
)

type fakeScanner struct{ res domain.ParseResult }

func (f fakeScanner) ScanProject(string) (domain.ParseResult, error) { return f.res, nil }

type fakeStore struct{ put *domain.Record }

func (s *fakeStore) PutFIPSRecord(_ context.Context, r domain.Record) error {
	s.put = &r
	return nil
}
func (s *fakeStore) GetFIPSRecord(context.Context, string) (domain.Record, bool, error) {
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

func newUC(res domain.ParseResult) (*application.ExtractFIPSUseCase, *fakeStore, *fakeSink) {
	store := &fakeStore{}
	sink := &fakeSink{}
	uc := application.NewExtractFIPSUseCase(application.Config{
		Scanner: fakeScanner{res: res}, Store: store, Audit: sink,
		Clock: clock.Fixed{}, Stopwatch: clock.Monotonic{},
	})
	return uc, store, sink
}

// fipsRequired returns a policy with FIPS required and OnDeviation=warn so
// algorithm findings block under the default policy (acceptance:
// "BoringCrypto + dep using MD5 -> algorithm flagged with module+location").
func fipsRequired() configdomain.FIPSPolicy {
	return configdomain.FIPSPolicy{Required: true, OnDeviation: configdomain.PolicyOutcomeWarn}
}

// TestExtract_StockGoNoCryptoNotCapable: stock Go, no algorithm imports —
// the toolchain finding marks the project not-eligible; under Required the
// toolchain deviation is the blocking fact (test case).
func TestExtract_StockGoNoCryptoNotCapable(t *testing.T) {
	uc, store, sink := newUC(domain.ParseResult{
		ProjectModulePath: "example.com/proj",
		ToolchainRaw:      "go1.22.0",
	})
	rec, err := uc.Extract(context.Background(), "go.mod", fipsRequired())
	if err != nil {
		t.Fatalf("Extract: %v", err)
	}
	if rec.ToolchainCapable {
		t.Error("stock Go must not be FIPS-capable")
	}
	if rec.Caveat != domain.EligibilityCaveat {
		t.Error("record must carry the eligibility-vs-validation caveat")
	}
	if store.put == nil {
		t.Fatal("record was not persisted")
	}
	if len(sink.events) != 1 || sink.events[0].Type != audit.EventFIPSAssessment {
		t.Fatalf("want 1 fips audit event, got %+v", sink.events)
	}
	if err := sink.events[0].Validate(); err != nil {
		t.Errorf("invalid audit event: %v", err)
	}
	// Toolchain finding is the deviation and blocking under Required.
	if rec.Findings[0].Kind != domain.FindingToolchain ||
		rec.Findings[0].Category != domain.CategoryDeviation ||
		!rec.Findings[0].PolicyBlocking {
		t.Errorf("toolchain finding = %+v, want deviation+blocking", rec.Findings[0])
	}
}

// TestExtract_BoringCryptoCleanEligible: recognised toolchain, no algorithm
// imports → eligible, no blocking findings (test case).
func TestExtract_BoringCryptoCleanEligible(t *testing.T) {
	uc, _, sink := newUC(domain.ParseResult{
		ProjectModulePath: "example.com/proj",
		ToolchainRaw:      "go1.22.0 X:boringcrypto",
	})
	rec, err := uc.Extract(context.Background(), "go.mod", fipsRequired())
	if err != nil {
		t.Fatalf("Extract: %v", err)
	}
	if !rec.ToolchainCapable || rec.ToolchainVariant != "boringcrypto" {
		t.Errorf("variant = %q capable=%t, want boringcrypto/true", rec.ToolchainVariant, rec.ToolchainCapable)
	}
	for _, f := range rec.Findings {
		if f.PolicyBlocking {
			t.Errorf("clean BoringCrypto must not block, but %+v blocks", f)
		}
	}
	if len(sink.events) != 1 {
		t.Errorf("want 1 audit event (toolchain only), got %d", len(sink.events))
	}
}

// TestExtract_BoringCryptoWithMD5DepFlagged: recognised toolchain but a
// dependency uses MD5 — the algorithm finding is recorded with its module +
// source location and blocks under Required (test case).
func TestExtract_BoringCryptoWithMD5DepFlagged(t *testing.T) {
	uc, _, sink := newUC(domain.ParseResult{
		ProjectModulePath: "example.com/proj",
		ToolchainRaw:      "go1.22.0 X:boringcrypto",
		Findings: []domain.Finding{
			{Kind: domain.FindingAlgorithm, Package: "crypto/md5",
				Module: "example.com/dep", Source: "vendor/example.com/dep/hash.go", Line: 7},
		},
	})
	rec, err := uc.Extract(context.Background(), "go.mod", fipsRequired())
	if err != nil {
		t.Fatalf("Extract: %v", err)
	}
	if !rec.ToolchainCapable {
		t.Fatal("toolchain must still be capable")
	}
	var algo *domain.Finding
	for i := range rec.Findings {
		if rec.Findings[i].Kind == domain.FindingAlgorithm {
			algo = &rec.Findings[i]
			break
		}
	}
	if algo == nil {
		t.Fatal("expected an algorithm finding")
	}
	if algo.Module != "example.com/dep" || algo.Source == "" || algo.Line == 0 {
		t.Errorf("algorithm finding lost provenance: %+v", *algo)
	}
	if !algo.PolicyBlocking {
		t.Error("MD5 in dep under FIPS-required policy must block")
	}
	// One event per finding (toolchain + algorithm).
	if len(sink.events) != 2 {
		t.Errorf("want 2 audit events, got %d", len(sink.events))
	}
}

// TestExtract_CgoCryptoLimitsAssessment: a cgo-crypto dependency forces the
// assessment into the "limited" bucket (the known cgo gap) and the cgo
// finding is classified unknown — never silently compliant.
func TestExtract_CgoCryptoLimitsAssessment(t *testing.T) {
	uc, _, _ := newUC(domain.ParseResult{
		ProjectModulePath: "example.com/proj",
		ToolchainRaw:      "go1.22.0 X:boringcrypto",
		Findings: []domain.Finding{
			{Kind: domain.FindingCgoCrypto, Module: "github.com/openssl/openssl-go",
				Source: "vendor/github.com/openssl/openssl-go/lib.go", Line: 1},
		},
	})
	rec, err := uc.Extract(context.Background(), "go.mod", fipsRequired())
	if err != nil {
		t.Fatalf("Extract: %v", err)
	}
	var cgo *domain.Finding
	for i := range rec.Findings {
		if rec.Findings[i].Kind == domain.FindingCgoCrypto {
			cgo = &rec.Findings[i]
		}
	}
	if cgo == nil || cgo.Category != domain.CategoryUnknown {
		t.Errorf("cgo finding must be unknown, got %+v", cgo)
	}
	if !cgo.PolicyBlocking {
		t.Error("cgo unknown finding must block under Required (fail safe)")
	}
}

// TestExtract_OptInOptional: with Required=false the assessor still records
// every finding but no policy outcome blocks — FIPS is opt-in.
func TestExtract_OptInOptional(t *testing.T) {
	uc, _, _ := newUC(domain.ParseResult{
		ProjectModulePath: "example.com/proj",
		ToolchainRaw:      "go1.22.0",
		Findings: []domain.Finding{
			{Kind: domain.FindingAlgorithm, Package: "crypto/md5", Module: "example.com/proj", Source: "a.go", Line: 1},
		},
	})
	rec, err := uc.Extract(context.Background(), "go.mod", configdomain.DefaultConfig().FIPSPolicy)
	if err != nil {
		t.Fatalf("Extract: %v", err)
	}
	for _, f := range rec.Findings {
		if f.PolicyBlocking {
			t.Errorf("Required=false: %+v must not block", f)
		}
	}
}
