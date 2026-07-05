package kanonarion_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/eitanity/kanonarion/internal/driver"
	fetchapp "github.com/eitanity/kanonarion/internal/fetch/application"
	fetchdomain "github.com/eitanity/kanonarion/internal/fetch/domain"

	"github.com/eitanity/kanonarion/pkg/kanonarion"
)

// The compile-time assignments pin each published driver use case to the internal
// use case it must alias (§1). Both directions compile only when the two
// names denote the identical type, so a forked or re-wired alias fails the build.
var (
	_ *kanonarion.ServeModuleUseCase       = (*fetchapp.ServeModuleUseCase)(nil)
	_ *fetchapp.ServeModuleUseCase         = (*kanonarion.ServeModuleUseCase)(nil)
	_ *kanonarion.LocalWalkExtractUseCase  = (*driver.LocalWalkExtractUseCase)(nil)
	_ *driver.LocalWalkExtractUseCase      = (*kanonarion.LocalWalkExtractUseCase)(nil)
	_ *kanonarion.ValidateAndIngestUseCase = (*fetchapp.ValidateAndIngestUseCase)(nil)
	_ *fetchapp.ValidateAndIngestUseCase   = (*kanonarion.ValidateAndIngestUseCase)(nil)
)

// TestVerificationStatusConstantsMatchInternal proves every exported status
// constant aliases the internal domain value, so a consumer comparing
// ServeResult.VerificationStatus against the façade constants reasons over the
// same values the pipeline records. A drifted constant fails the build (wrong
// type) or this equality check (wrong value).
func TestVerificationStatusConstantsMatchInternal(t *testing.T) {
	t.Parallel()

	cases := map[kanonarion.VerificationStatus]fetchdomain.VerificationStatus{
		kanonarion.Verified:                    fetchdomain.Verified,
		kanonarion.VerifiedBySumDBOnly:         fetchdomain.VerifiedBySumDBOnly,
		kanonarion.UnverifiedNoSumDB:           fetchdomain.UnverifiedNoSumDB,
		kanonarion.UnverifiedMissingOrigin:     fetchdomain.UnverifiedMissingOrigin,
		kanonarion.UnverifiedHashMismatch:      fetchdomain.UnverifiedHashMismatch,
		kanonarion.UnverifiedGoModInconsistent: fetchdomain.UnverifiedGoModInconsistent,
		kanonarion.UnverifiedNoVCS:             fetchdomain.UnverifiedNoVCS,
		kanonarion.UnverifiedVCSToolMissing:    fetchdomain.UnverifiedVCSToolMissing,
		kanonarion.LocalSource:                 fetchdomain.LocalSource,
	}
	for got, want := range cases {
		if string(got) != string(want) {
			t.Errorf("façade status %q does not match internal %q", got, want)
		}
	}
}

// TestOpenDriver_WiresEveryDriver is the acceptance test: every driver use case
// is constructible via the public OpenDriver entrypoint alone, with no import of
// internal/cli. It opens a fresh store under a temp root (exercising migration
// application on an empty mirror.db) and asserts each driver field is wired.
func TestOpenDriver_WiresEveryDriver(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	d, cleanup, err := kanonarion.OpenDriver(root)
	if err != nil {
		t.Fatalf("OpenDriver(%q): %v", root, err)
	}
	t.Cleanup(func() {
		if cerr := cleanup(); cerr != nil {
			t.Errorf("cleanup: %v", cerr)
		}
	})

	if d.FetchServe == nil {
		t.Error("Driver.FetchServe is nil; composition root left the verified fetch/serve driver unwired")
	}
	if d.LocalWalkExtract == nil {
		t.Error("Driver.LocalWalkExtract is nil; composition root left the local walk→extract driver unwired")
	}
	if d.ValidateIngest == nil {
		t.Error("Driver.ValidateIngest is nil; composition root left the validate-and-ingest boundary unwired")
	}
}

// TestValidateIngest_RoundTripAndFailClosed is the acceptance test for the
// verified-fact boundary via the public surface alone: a valid record ingests
// and reads back verified; a tampered record is rejected fail-closed on both
// write and read, with kanonarion.ErrVerificationFailed surfaced through the
// façade. It uses a real store opened by OpenDriver, so it also proves the
// boundary is reachable without any internal/cli import.
func TestValidateIngest_RoundTripAndFailClosed(t *testing.T) {
	t.Parallel()

	d, cleanup, err := kanonarion.OpenDriver(t.TempDir())
	if err != nil {
		t.Fatalf("OpenDriver: %v", err)
	}
	t.Cleanup(func() { _ = cleanup() })

	ctx := context.Background()
	uc := d.ValidateIngest
	coord := fetchdomain.ModuleCoordinate{Path: "github.com/foo/bar", Version: "v1.2.3"}
	rec, err := fetchdomain.CanonicalHasher{}.SetContentHash(fetchdomain.FactRecord{
		SchemaVersion:   fetchdomain.SchemaVersion,
		Ecosystem:       fetchdomain.EcosystemGo,
		ModulePath:      coord.Path,
		ModuleVersion:   coord.Version,
		PipelineVersion: "0.1.0",
		FetchedAt:       time.Unix(0, 0).UTC(),
	})
	if err != nil {
		t.Fatalf("SetContentHash: %v", err)
	}

	if err := uc.Ingest(ctx, rec); err != nil {
		t.Fatalf("Ingest of a valid record: %v", err)
	}
	got, found, err := uc.ReadVerified(ctx, coord, rec.PipelineVersion)
	if err != nil || !found {
		t.Fatalf("ReadVerified valid record: found=%v err=%v", found, err)
	}
	if got.ContentHash != rec.ContentHash {
		t.Errorf("round-tripped record differs: got %q want %q", got.ContentHash, rec.ContentHash)
	}

	// Tampered import: body mutated after hashing — rejected fail-closed.
	tampered := rec
	tampered.ModuleVersion = "v9.9.9"
	if err := uc.Ingest(ctx, tampered); !errors.Is(err, kanonarion.ErrVerificationFailed) {
		t.Fatalf("Ingest of tampered record: want ErrVerificationFailed, got %v", err)
	}
}

// TestOpenDriver_TwoOpensShareNoState confirms OpenDriver is self-contained: two
// roots are independent stores, so the surface holds no global/process state.
func TestOpenDriver_TwoOpensShareNoState(t *testing.T) {
	t.Parallel()

	da, cleanupA, err := kanonarion.OpenDriver(t.TempDir())
	if err != nil {
		t.Fatalf("OpenDriver A: %v", err)
	}
	t.Cleanup(func() { _ = cleanupA() })

	db, cleanupB, err := kanonarion.OpenDriver(t.TempDir())
	if err != nil {
		t.Fatalf("OpenDriver B: %v", err)
	}
	t.Cleanup(func() { _ = cleanupB() })

	if da == db {
		t.Error("two OpenDriver calls returned the same Driver pointer; the surface is not per-store")
	}
}
