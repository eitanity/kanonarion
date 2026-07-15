package application_test

import (
	"strings"
	"testing"
	"time"

	"github.com/eitanity/kanonarion/internal/vuln/application"
	"github.com/eitanity/kanonarion/internal/vuln/domain"

	fetchdomain "github.com/eitanity/kanonarion/internal/fetch/domain"
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

	coord := fetchdomain.ModuleCoordinate{Path: "github.com/example/mod", Version: "v1.0.0"}
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
	h, _ := blobs.Put(ctx, strings.NewReader("zip"))
	if err := facts.PutFetchRecord(ctx, fetchdomain.FactRecord{
		ModulePath: coord.Path, ModuleVersion: coord.Version, PipelineVersion: "v1", ContentLocation: string(h),
	}); err != nil {
		t.Fatalf("PutFetchRecord: %v", err)
	}

	// Force the heavy scan (past the metadata pre-filter) so the scanner — and
	// thus the GOMODCACHE argument — is actually exercised.
	db := &fakeDatabase{
		snapshot:    domain.DatabaseSnapshot{Source: "test", Version: "v1"},
		vulnerables: map[fetchdomain.ModuleCoordinate][]string{coord: {"GO-VULN-ID"}},
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
