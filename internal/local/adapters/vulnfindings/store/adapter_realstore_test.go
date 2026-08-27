package store_test

import (
	"strings"
	"testing"
	"time"

	"github.com/eitanity/kanonarion/internal/coordinate"
	"github.com/eitanity/kanonarion/internal/coordinate/coordinatetest"
	fetchdomain "github.com/eitanity/kanonarion/internal/fetch/domain"
	"github.com/eitanity/kanonarion/internal/local/adapters/vulnfindings/store"
	"github.com/eitanity/kanonarion/internal/sqlitestore"
	vulnsqlite "github.com/eitanity/kanonarion/internal/vuln/adapters/store/sqlite"
	vulndomain "github.com/eitanity/kanonarion/internal/vuln/domain"
	"github.com/eitanity/kanonarion/internal/vuln/vulntest"
)

// The shared-store situation, end to end through the real ledger: two projects
// have scanned the same dependency and both records are in one store, sealed
// and read back through the store's own query — not a fake that could return
// whatever the test wanted.
//
// The unit tests above pin the selection; this pins that the store hands the
// selection every frame it holds. A per-module read that returned one composed
// row would leave the filter nothing to choose from and the defect intact.
func TestLoadFindings_TwoConsumersInOneLedger(t *testing.T) {
	ctx := t.Context()
	db, err := sqlitestore.Open(":memory:", vulnsqlite.Migrations(), sqlitestore.IntentCreate)
	if err != nil {
		t.Fatalf("opening in-memory db: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	ledger := vulnsqlite.New(db)

	dep := coordinatetest.MustNew("example.com/dep", "v1.0.0")
	ownFrame := vulndomain.TargetRootedAt(coordinatetest.MustNew(probedTree, "local"))
	otherFrame := vulndomain.TargetRootedAt(coordinatetest.MustNew(otherConsumer, "local"))

	// The other consumer's build reaches the vulnerable symbol; this tree's does
	// not. Written last, and newest, so recency alone would serve it.
	for _, rec := range []vulndomain.VulnerabilityRecord{
		ledgerRecord(t, dep, ownFrame, false, time.Date(2026, 7, 1, 12, 0, 0, 0, time.UTC)),
		ledgerRecord(t, dep, otherFrame, true, time.Date(2026, 8, 1, 12, 0, 0, 0, time.UTC)),
	} {
		if err := ledger.PutVulnerabilityRecord(ctx, rec); err != nil {
			t.Fatalf("PutVulnerabilityRecord: %v", err)
		}
	}

	adapter := store.New(ledger, "v16")
	set, err := adapter.LoadFindings(ctx, []coordinate.ModuleCoordinate{dep}, probedTree)
	if err != nil {
		t.Fatalf("LoadFindings: %v", err)
	}
	findings := set.Findings[dep]
	if len(findings) != 1 {
		t.Fatalf("findings = %d, want 1", len(findings))
	}
	if findings[0].Reachable == nil || *findings[0].Reachable {
		t.Errorf("seeded Reachable = %v — that is the other consumer's build's verdict", findings[0].Reachable)
	}
	if !strings.Contains(findings[0].ReachableBasis, string(ownFrame)) {
		t.Errorf("ReachableBasis = %q, want it to name this tree's own frame %s", findings[0].ReachableBasis, ownFrame)
	}
}

// ledgerRecord is one project's scan of dep, sealed exactly as the production
// write path seals it.
func ledgerRecord(
	t *testing.T,
	dep coordinate.ModuleCoordinate,
	rooting vulndomain.Rooting,
	reachable bool,
	scannedAt time.Time,
) vulndomain.VulnerabilityRecord {
	t.Helper()
	rec := vulndomain.VulnerabilityRecord{
		Ecosystem:  fetchdomain.EcosystemGo,
		Coordinate: dep,
		WalkID:     "walk-" + rooting.RootTarget(),
		Findings: []vulndomain.VulnerabilityFinding{{
			ID:            "GO-2026-0001",
			Summary:       "a vulnerability in the shared dependency",
			AffectedRange: "< v2",
			Reachable: &vulndomain.ReachabilityResult{
				IsReachable: reachable,
				Confidence:  vulndomain.ConfidenceHigh,
				DerivedBy: vulndomain.ReachabilityDerivation{
					Analyser: vulndomain.AnalyserGovulncheck,
					Rooting:  rooting,
				},
			},
		}},
		OverallStatus:    vulndomain.StatusAffected,
		DatabaseSnapshot: vulntest.MustNewAt("govulndb", "2026-07-17T19:42:05Z", time.Date(2026, 7, 17, 19, 42, 5, 0, time.UTC)),
		ScannedAt:        scannedAt,
		FirstScannedAt:   scannedAt,
		PipelineVersion:  "v16",
		Rooting:          rooting,
	}
	sealed, err := vulndomain.VulnerabilityRecordHasher{}.SetContentHash(rec)
	if err != nil {
		t.Fatalf("sealing record: %v", err)
	}
	return sealed
}
