package sqlite_test

import (
	"context"
	"errors"
	"testing"
	"time"

	fipssqlite "github.com/eitanity/kanonarion/internal/fips/adapters/store/sqlite"
	"github.com/eitanity/kanonarion/internal/fips/domain"
	"github.com/eitanity/kanonarion/internal/sqlitestore"
)

func openTestStore(t *testing.T) *fipssqlite.Store {
	t.Helper()
	db, err := sqlitestore.Open(":memory:", fipssqlite.Migrations())
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() {
		if err := db.Close(); err != nil {
			t.Errorf("Close: %v", err)
		}
	})
	return fipssqlite.New(db)
}

func mkRecord(project string, capable bool, variant, raw string) domain.Record {
	fs := []domain.Finding{
		{Kind: domain.FindingToolchain, Module: project, Toolchain: variant, ToolchainRaw: raw,
			Category: domain.CategoryCompliant, PolicyOutcome: "allow"},
		{Kind: domain.FindingAlgorithm, Package: "crypto/md5", Module: "example.com/dep",
			Source: "vendor/example.com/dep/hash.go", Line: 7,
			Category: domain.CategoryDeviation, PolicyOutcome: "warn", PolicyBlocking: true},
	}
	domain.Sort(fs)
	return domain.Record{
		Ecosystem:            domain.EcosystemGo,
		ProjectModulePath:    project,
		ToolchainCapable:     capable,
		ToolchainVariant:     variant,
		ToolchainRaw:         raw,
		Findings:             fs,
		ComplianceAssessment: "not eligible: toolchain boringcrypto recognised but non-FIPS algorithm in use: crypto/md5",
		Caveat:               domain.EligibilityCaveat,
		CatalogueVersion:     domain.CatalogueVersion(),
		ExtractedAt:          time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
		SchemaVersion:        domain.FIPSSchemaVersion,
		PipelineVersion:      domain.PipelineVersion,
		ContentHash:          domain.Hash(capable, variant, raw, fs),
	}
}

func TestFIPSRecord_EcosystemPresentAfterRoundTrip(t *testing.T) {
	store := openTestStore(t)
	ctx := context.Background()
	if err := store.PutFIPSRecord(ctx, mkRecord("example.com/eco", true, "boringcrypto", "go1.22")); err != nil {
		t.Fatalf("PutFIPSRecord: %v", err)
	}
	got, found, err := store.GetFIPSRecord(ctx, "example.com/eco")
	if err != nil || !found {
		t.Fatalf("GetFIPSRecord: err=%v found=%t", err, found)
	}
	if got.Ecosystem != domain.EcosystemGo {
		t.Errorf("Ecosystem after round-trip = %q, want %q", got.Ecosystem, domain.EcosystemGo)
	}
}

func TestFIPSRecord_RejectsForeignEcosystem(t *testing.T) {
	store := openTestStore(t)
	ctx := context.Background()
	rec := mkRecord("example.com/npm", true, "boringcrypto", "go1.22")
	rec.Ecosystem = "npm"
	if err := store.PutFIPSRecord(ctx, rec); err != nil {
		t.Fatalf("PutFIPSRecord: %v", err)
	}
	if _, _, err := store.GetFIPSRecord(ctx, "example.com/npm"); !errors.Is(err, domain.ErrUnsupportedEcosystem) {
		t.Errorf("expected ErrUnsupportedEcosystem, got %v", err)
	}
}

// TestStore_PutAndGetRoundTrip persists a record then reads it back; every
// field must round-trip. stores the assessment as a serialised blob,
// so this is the regression that catches a JSON/marshal mistake silently
// dropping data.
func TestStore_PutAndGetRoundTrip(t *testing.T) {
	store := openTestStore(t)
	ctx := context.Background()

	rec := mkRecord("example.com/proj", true, "boringcrypto", "go1.22.0 X:boringcrypto")
	if err := store.PutFIPSRecord(ctx, rec); err != nil {
		t.Fatalf("PutFIPSRecord: %v", err)
	}
	got, found, err := store.GetFIPSRecord(ctx, "example.com/proj")
	if err != nil || !found {
		t.Fatalf("GetFIPSRecord: err=%v found=%t", err, found)
	}
	if got.ContentHash != rec.ContentHash {
		t.Errorf("content hash differs: %q vs %q", got.ContentHash, rec.ContentHash)
	}
	if got.ToolchainCapable != rec.ToolchainCapable || got.ToolchainVariant != rec.ToolchainVariant {
		t.Errorf("toolchain differs: %+v vs %+v", got, rec)
	}
	if len(got.Findings) != len(rec.Findings) {
		t.Fatalf("findings differ: %d vs %d", len(got.Findings), len(rec.Findings))
	}
	if got.Caveat != domain.EligibilityCaveat {
		t.Errorf("caveat lost in round-trip: %q", got.Caveat)
	}
	if got.ComplianceAssessment != rec.ComplianceAssessment {
		t.Errorf("assessment lost: %q vs %q", got.ComplianceAssessment, rec.ComplianceAssessment)
	}
}

// TestStore_PutIdempotent: re-putting under the same (project, fingerprint)
// replaces rather than duplicates. Mirrors 's idempotency guarantee.
func TestStore_PutIdempotent(t *testing.T) {
	store := openTestStore(t)
	ctx := context.Background()
	rec := mkRecord("example.com/proj", true, "boringcrypto", "go1.22.0 X:boringcrypto")
	if err := store.PutFIPSRecord(ctx, rec); err != nil {
		t.Fatal(err)
	}
	rec.ComplianceAssessment = "rewritten"
	if err := store.PutFIPSRecord(ctx, rec); err != nil {
		t.Fatal(err)
	}
	got, found, err := store.GetFIPSRecord(ctx, "example.com/proj")
	if err != nil || !found {
		t.Fatalf("GetFIPSRecord: %v %t", err, found)
	}
	if got.ComplianceAssessment != "rewritten" {
		t.Errorf("idempotent put did not overwrite: %q", got.ComplianceAssessment)
	}
}

// TestStore_GetMissingIsNotError: a project never scanned reads found=false
// with nil error — the "not analysed" state, never confused with "no
// issues".
func TestStore_GetMissingIsNotError(t *testing.T) {
	store := openTestStore(t)
	_, found, err := store.GetFIPSRecord(context.Background(), "example.com/never-scanned")
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if found {
		t.Error("missing record must read found=false")
	}
}
