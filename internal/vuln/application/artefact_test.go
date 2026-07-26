package application_test

import (
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/eitanity/kanonarion/internal/coordinate/coordinatetest"
	fetchdomain "github.com/eitanity/kanonarion/internal/fetch/domain"
	"github.com/eitanity/kanonarion/internal/fetch/fetchtest"

	"github.com/eitanity/kanonarion/internal/vuln/application"
	"github.com/eitanity/kanonarion/internal/vuln/domain"
)

// TestScanModule_RecordsTheArtefactItScanned is the ticket's observable for the
// vulnerability stage: a verdict reached by analysing bytes names which bytes,
// and the name matches the fetch record the scan actually read.
func TestScanModule_RecordsTheArtefactItScanned(t *testing.T) {
	ctx := t.Context()
	coord := coordinatetest.MustNew("example.com/scanned", "v1.0.0")
	now := time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)

	facts := newFakeFacts()
	blobs := newFakeBlob()
	vulnStore := newFakeVulnStore()
	scanner := &fakeScanner{}
	db := &fakeDatabase{
		snapshot: domain.DatabaseSnapshot{Source: "test", Version: "v1", RetrievedAt: now},
		content:  "vulndb content",
	}

	rec := fetchtest.Record(t,
		fetchtest.Coordinate(coord),
		fetchtest.PipelineVersion("v1"),
		fetchtest.Content("zip content"),
	)
	if err := blobs.Put(ctx, fetchtest.ZipIdentity(t, rec), strings.NewReader("zip content")); err != nil {
		t.Fatalf("blobs.Put: %v", err)
	}
	if err := facts.PutFetchRecord(ctx, fetchtest.Sealed(t,
		fetchtest.Coordinate(coord),
		fetchtest.PipelineVersion("v1"),
		fetchtest.Content("zip content"),
	)); err != nil {
		t.Fatalf("PutFetchRecord: %v", err)
	}

	uc := application.NewScanModuleUseCase(
		facts, blobs, vulnStore, nil, scanner, db, nil, fixedClock{t: now}, "v1", "v1", slog.Default(),
	)
	res, err := uc.Scan(ctx, application.ScanModuleParams{
		Coordinate: coord,
		WalkID:     "walk-1",
		Force:      true, // skip the metadata pre-filter so the source path runs
	})
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}

	want, err := fetchdomain.ArtefactIdentityOf(rec)
	if err != nil {
		t.Fatalf("ArtefactIdentityOf: %v", err)
	}
	if res.ArtefactIdentity != want.String() {
		t.Errorf("ArtefactIdentity = %q, want %q", res.ArtefactIdentity, want.String())
	}
	if res.SourceContentHash != rec.ContentHash {
		t.Errorf("SourceContentHash = %q, want the fetch record's own hash %q", res.SourceContentHash, rec.ContentHash)
	}
}

// TestScanModule_GoModOnlyStillNamesItsArtefact covers the case between the two
// obvious ones. A module held only as a go.mod is scanned metadata-only — no zip
// was read — but the measurement did see bytes, and the identity records them at
// go.mod depth. Recording nothing here would lose a real link; recording a zip
// identity would claim bytes nobody fetched.
func TestScanModule_GoModOnlyStillNamesItsArtefact(t *testing.T) {
	ctx := t.Context()
	coord := coordinatetest.MustNew("example.com/gomodonly", "v1.0.0")
	now := time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)

	facts := newFakeFacts()
	rec := fetchtest.Record(t,
		fetchtest.Coordinate(coord),
		fetchtest.PipelineVersion("v1"),
		fetchtest.GoModOnly("gomod content"),
	)
	if err := facts.PutFetchRecord(ctx, fetchtest.Sealed(t,
		fetchtest.Coordinate(coord),
		fetchtest.PipelineVersion("v1"),
		fetchtest.GoModOnly("gomod content"),
	)); err != nil {
		t.Fatalf("PutFetchRecord: %v", err)
	}

	uc := application.NewScanModuleUseCase(
		facts, newFakeBlob(), newFakeVulnStore(), nil, &fakeScanner{},
		&fakeDatabase{
			snapshot: domain.DatabaseSnapshot{Source: "test", Version: "v1", RetrievedAt: now},
			content:  "vulndb content",
		},
		nil, fixedClock{t: now}, "v1", "v1", slog.Default(),
	)
	res, err := uc.Scan(ctx, application.ScanModuleParams{Coordinate: coord, WalkID: "walk-1"})
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}

	want, err := fetchdomain.ArtefactIdentityOf(rec)
	if err != nil {
		t.Fatalf("ArtefactIdentityOf: %v", err)
	}
	if !want.GoModOnly() {
		t.Fatalf("fixture is not go.mod-only: %v", want)
	}
	if res.ArtefactIdentity != want.String() {
		t.Errorf("ArtefactIdentity = %q, want %q", res.ArtefactIdentity, want.String())
	}
	if res.SourceContentHash != rec.ContentHash {
		t.Errorf("SourceContentHash = %q, want %q", res.SourceContentHash, rec.ContentHash)
	}
}

// TestScanModule_MetadataOnlyRecordsNoArtefact pins the deliberate asymmetry
// with the extraction stages. A module that was never fetched is matched against
// the advisory database by coordinate alone: nothing read any bytes, so the
// record must not claim to have. Absence here is permanent and expected, not a
// legacy row waiting to be backfilled — which is why the vulnerability store
// cannot carry the extraction stores' write-leg refusal.
func TestScanModule_MetadataOnlyRecordsNoArtefact(t *testing.T) {
	ctx := t.Context()
	coord := coordinatetest.MustNew("example.com/neverfetched", "v1.0.0")
	now := time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)

	uc := application.NewScanModuleUseCase(
		newFakeFacts(), newFakeBlob(), newFakeVulnStore(), nil, &fakeScanner{},
		&fakeDatabase{
			snapshot: domain.DatabaseSnapshot{Source: "test", Version: "v1", RetrievedAt: now},
			content:  "vulndb content",
		},
		nil, fixedClock{t: now}, "v1", "v1", slog.Default(),
	)
	res, err := uc.Scan(ctx, application.ScanModuleParams{Coordinate: coord, WalkID: "walk-1"})
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if res.UnscannableReason == "" {
		t.Fatalf("expected the metadata-only fallback for a module with no fetch record")
	}
	if res.ArtefactIdentity != "" {
		t.Errorf("ArtefactIdentity = %q, want empty: nothing read any bytes", res.ArtefactIdentity)
	}
	if res.SourceContentHash != "" {
		t.Errorf("SourceContentHash = %q, want empty", res.SourceContentHash)
	}

	id, err := domain.RecordArtefactIdentity(res)
	if err != nil {
		t.Fatalf("RecordArtefactIdentity: %v", err)
	}
	if !id.IsZero() {
		t.Errorf("RecordArtefactIdentity = %v, want the zero identity", id)
	}
}
