package application_test

import (
	"context"
	"testing"

	"github.com/eitanity/kanonarion/internal/fetch/application"
	domain2 "github.com/eitanity/kanonarion/internal/fetch/domain"
	"github.com/eitanity/kanonarion/internal/fetch/ports"
)

// availableGoModSumDB reports the given go.mod hash as verified, with no zip
// hash — the shape a go.mod-only verification consults.
func availableGoModSumDB(goModHash domain2.ModuleHash) *fakeSumDB {
	return &fakeSumDB{result: ports.SumDBResult{Available: true, GoModHash: goModHash}}
}

// TestExecuteGoModOnly_PersistsGoModOnlyRecord is the core regression for the
// go.mod-only fetch path: it stores and verifies the go.mod, records a
// distinguishable go.mod-only fact (GoModLocation set, ContentLocation empty),
// and never downloads the zip.
func TestExecuteGoModOnly_PersistsGoModOnlyRecord(t *testing.T) {
	proxy := &fakeProxy{}
	blobs := newFakeBlob()
	facts := newFakeFacts()

	uc := newUseCaseWithSumDB(proxy, &fakeVCS{}, blobs, facts, availableGoModSumDB(fakeGoModHash))
	result, err := uc.Execute(context.Background(), application.FetchRequest{Coordinate: testCoord, GoModOnly: true})
	if err != nil {
		t.Fatalf("Execute go.mod-only: %v", err)
	}

	rec := result.Record
	if !rec.IsGoModOnly() {
		t.Errorf("expected a go.mod-only record, got ContentLocation=%q GoModLocation=%q", rec.ContentLocation, rec.GoModLocation)
	}
	if rec.ContentLocation != "" {
		t.Errorf("go.mod-only record must have empty ContentLocation, got %q", rec.ContentLocation)
	}
	if rec.GoModLocation == "" {
		t.Error("go.mod-only record must have GoModLocation set")
	}
	if rec.VerificationStatus != string(domain2.VerifiedBySumDBOnly) {
		t.Errorf("expected VerifiedBySumDBOnly (go.mod anchored to checksum database), got %q", rec.VerificationStatus)
	}
	if proxy.zipDownloads != 0 {
		t.Errorf("go.mod-only path must not download the zip, got %d zip downloads", proxy.zipDownloads)
	}
}

// TestExecuteGoModOnly_HashMismatchRecorded verifies the go.mod hash is checked
// exactly as the zip hash is: a disagreement is recorded as UnverifiedHashMismatch
// rather than silently accepted. Verification failures do not fail Execute.
func TestExecuteGoModOnly_HashMismatchRecorded(t *testing.T) {
	proxy := &fakeProxy{}
	blobs := newFakeBlob()
	facts := newFakeFacts()

	wrong := domain2.ModuleHash{Algorithm: "h1", Value: "somethingelse=="}
	uc := newUseCaseWithSumDB(proxy, &fakeVCS{}, blobs, facts, availableGoModSumDB(wrong))
	result, err := uc.Execute(context.Background(), application.FetchRequest{Coordinate: testCoord, GoModOnly: true})
	if err != nil {
		t.Fatalf("Execute go.mod-only: %v", err)
	}
	if result.Record.VerificationStatus != string(domain2.UnverifiedHashMismatch) {
		t.Errorf("expected UnverifiedHashMismatch, got %q", result.Record.VerificationStatus)
	}
}

// TestExecuteGoModOnly_FullFetchUpgradesRecord verifies a full fetch does not
// treat an existing go.mod-only record as a cache hit: it re-fetches the zip and
// upgrades the record in place, so the source path is never starved.
func TestExecuteGoModOnly_FullFetchUpgradesRecord(t *testing.T) {
	proxy := &fakeProxy{}
	blobs := newFakeBlob()
	facts := newFakeFacts()

	uc := newUseCaseWithSumDB(proxy, &fakeVCS{}, blobs, facts, availableGoModSumDB(fakeGoModHash))
	ctx := context.Background()

	if _, err := uc.Execute(ctx, application.FetchRequest{Coordinate: testCoord, GoModOnly: true}); err != nil {
		t.Fatalf("go.mod-only Execute: %v", err)
	}

	full, err := uc.Execute(ctx, application.FetchRequest{Coordinate: testCoord})
	if err != nil {
		t.Fatalf("full Execute: %v", err)
	}
	if full.FromCache {
		t.Error("full fetch must not be satisfied by a go.mod-only record")
	}
	if full.Record.IsGoModOnly() {
		t.Error("full fetch must upgrade the record to carry a zip (ContentLocation set)")
	}
	if full.Record.ContentLocation == "" {
		t.Error("upgraded record must have ContentLocation set")
	}
	if proxy.zipDownloads != 1 {
		t.Errorf("expected exactly one zip download (the upgrade), got %d", proxy.zipDownloads)
	}
}

// TestExecuteGoModOnly_SatisfiedByFullRecord verifies the reverse: a go.mod-only
// request is a cache hit against an existing full record, which already carries a
// verified go.mod. No redundant fetch is issued.
func TestExecuteGoModOnly_SatisfiedByFullRecord(t *testing.T) {
	proxy := &fakeProxy{}
	blobs := newFakeBlob()
	facts := newFakeFacts()

	uc := newUseCaseWithSumDB(proxy, &fakeVCS{}, blobs, facts, availableGoModSumDB(fakeGoModHash))
	ctx := context.Background()

	if _, err := uc.Execute(ctx, application.FetchRequest{Coordinate: testCoord}); err != nil {
		t.Fatalf("full Execute: %v", err)
	}

	gomod, err := uc.Execute(ctx, application.FetchRequest{Coordinate: testCoord, GoModOnly: true})
	if err != nil {
		t.Fatalf("go.mod-only Execute: %v", err)
	}
	if !gomod.FromCache {
		t.Error("go.mod-only request should be satisfied by the existing full record")
	}
	if gomod.Record.IsGoModOnly() {
		t.Error("a full record served to a go.mod-only request must stay full")
	}
}
