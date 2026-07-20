package application_test

import (
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/eitanity/kanonarion/internal/coordinate"

	fetchdomain "github.com/eitanity/kanonarion/internal/fetch/domain"
	"github.com/eitanity/kanonarion/internal/vuln/application"
	"github.com/eitanity/kanonarion/internal/vuln/domain"
)

// A module ingested from a local working tree (a local-replace target or the
// project-walk root) persists its FactRecord under the local-ingest pipeline
// version, not the proxy fetch pipeline version. The scan must find that
// record and run a full source scan instead of degrading to metadata-only.
func TestScanModule_FindsFactRecordUnderLocalIngestPipelineVersion(t *testing.T) {
	ctx := t.Context()
	const localPipeline = "local-0.1.0"
	coord := coordinate.ModuleCoordinate{Path: "example.com/localmod", Version: "v0.0.0"}
	now := time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)

	facts := newFakeFacts()
	blobs := newFakeBlob()
	vulnStore := newFakeVulnStore()
	scanner := &fakeScanner{}
	db := &fakeDatabase{
		snapshot: domain.DatabaseSnapshot{Source: "test", Version: "v1", RetrievedAt: now},
		content:  "vulndb content",
	}

	handle, err := blobs.Put(ctx, strings.NewReader("zip content"))
	if err != nil {
		t.Fatalf("blobs.Put: %v", err)
	}
	// The record exists ONLY under the local-ingest pipeline version.
	if err := facts.PutFetchRecord(ctx, fetchdomain.FactRecord{
		ModulePath:      coord.Path,
		ModuleVersion:   coord.Version,
		PipelineVersion: localPipeline,
		ContentLocation: string(handle),
	}); err != nil {
		t.Fatalf("PutFetchRecord: %v", err)
	}

	uc := application.NewScanModuleUseCase(
		facts, blobs, vulnStore, nil, scanner, db, nil, fixedClock{t: now}, "v1", "v1", slog.Default(),
	).WithLocalFetchPipelineVersion(localPipeline)

	res, err := uc.Scan(ctx, application.ScanModuleParams{
		Coordinate: coord,
		WalkID:     "walk-1",
		Force:      true, // skip the metadata pre-filter so the full scan path runs
	})
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}

	if res.UnscannableReason != "" {
		t.Errorf("expected a full source scan, got metadata-only fallback: %q", res.UnscannableReason)
	}
}
