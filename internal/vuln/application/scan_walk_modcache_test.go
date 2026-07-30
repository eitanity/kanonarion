package application_test

import (
	"strings"
	"testing"
	"time"

	"github.com/eitanity/kanonarion/internal/coordinate/coordinatetest"
	"github.com/eitanity/kanonarion/internal/fetch/fetchtest"
	"github.com/eitanity/kanonarion/internal/vuln/application"
	"github.com/eitanity/kanonarion/internal/vuln/vulntest"

	"github.com/eitanity/kanonarion/internal/coordinate"

	walkdomain "github.com/eitanity/kanonarion/internal/walk/domain"

	"log/slog"
)

// TestScanWalk_WithRealModcache_UsesProvidedDir verifies that --from-modcache
// points govulncheck at the caller's existing module cache: the scanner is
// invoked with GOMODCACHE set to that directory, and no temporary cache is
// substituted.
func TestScanWalk_WithRealModcache_UsesProvidedDir(t *testing.T) {
	ctx := t.Context()
	now := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)
	clock := fixedClock{t: now}

	coord := coordinatetest.MustNew("github.com/example/mod", "v1.0.0")
	walkStore := newFakeWalkStore()
	if err := walkStore.PutWalk(ctx, walkdomain.WalkRecord{
		ID: "w1",
		Graph: walkdomain.Graph{
			Nodes: []walkdomain.GraphNode{{Coordinate: coord}},
		},
	}); err != nil {
		t.Fatalf("PutWalk: %v", err)
	}

	facts := newFakeFacts()
	blobs := newFakeBlob()
	rec := fetchtest.Record(t, fetchtest.Coordinate(coord), fetchtest.PipelineVersion("v1"), fetchtest.Content("zip"))
	if err := blobs.Put(ctx, fetchtest.ZipIdentity(t, rec), strings.NewReader("zip")); err != nil {
		t.Fatalf("Put blob: %v", err)
	}
	if err := facts.PutFetchRecord(ctx, fetchtest.Sealed(t, fetchtest.Coordinate(coord), fetchtest.PipelineVersion("v1"), fetchtest.Content("zip"))); err != nil {
		t.Fatalf("PutFetchRecord: %v", err)
	}

	// Force the heavy scan (past the metadata pre-filter) so the scanner — and
	// thus the GOMODCACHE argument — is actually exercised.
	db := &fakeDatabase{
		snapshot:    vulntest.MustNew("test", "v1"),
		vulnerables: map[coordinate.ModuleCoordinate][]string{coord: {"GO-VULN-ID"}},
	}
	vulnStore := newFakeVulnStore()
	scanner := &fakeScanner{}

	moduleUC := application.NewScanModuleUseCase(
		facts, blobs, vulnStore, walkStore, scanner, db, nil, clock, "v1", "v1", slog.Default(),
	)
	const realCache = "/tmp/existing-modcache-fixture"
	walkUC := application.NewScanWalkUseCase(
		walkStore, vulnStore, moduleUC, nil, clock, "v1", slog.Default(),
	).WithRealModcache(realCache)

	if _, err := walkUC.Scan(ctx, application.ScanWalkParams{WalkID: "w1"}); err != nil {
		t.Fatalf("Scan: %v", err)
	}

	if scanner.gotModCache != realCache {
		t.Errorf("scanner GOMODCACHE = %q, want %q (the provided cache dir)", scanner.gotModCache, realCache)
	}
}
