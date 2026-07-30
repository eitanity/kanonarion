package application_test

import (
	"log/slog"
	"testing"
	"time"

	"github.com/eitanity/kanonarion/internal/coordinate"
	coordinatetest "github.com/eitanity/kanonarion/internal/coordinate/coordinatetest"
	"github.com/eitanity/kanonarion/internal/vuln/application"
	"github.com/eitanity/kanonarion/internal/vuln/domain"
	"github.com/eitanity/kanonarion/internal/vuln/vulntest"
)

// bboltWithdrawnAt is GO-2026-4923's retraction timestamp, two days after it was
// published.
var bboltWithdrawnAt = time.Date(2026, 4, 8, 13, 33, 56, 0, time.UTC)

// TestScanModule_WithdrawnAdvisoryIsNotAnAffectedVerdict is the ticket's
// acceptance criterion at the producer, on the exact coordinate the false finding
// was reported for.
//
// Both halves are asserted, because the criterion has two: the retraction must be
// named, and the coordinate must not be counted affected on the strength of it.
// Passing only the first would leave the live false positive in place; passing
// only the second would restore the silence — a retraction folded into Clean is
// indistinguishable from an advisory that never applied.
func TestScanModule_WithdrawnAdvisoryIsNotAnAffectedVerdict(t *testing.T) {
	vulnStore := newFakeVulnStore()
	snap := vulntest.MustNew("vuln.go.dev", "2026-07-08T17:05:00Z")
	bbolt := coordinatetest.MustNew("go.etcd.io/bbolt", "v1.4.3")
	db := &fakeDatabase{
		snapshot:    snap,
		vulnerables: map[coordinate.ModuleCoordinate][]string{bbolt: {"GO-2026-4923"}},
		findings: map[coordinate.ModuleCoordinate][]domain.VulnerabilityFinding{
			bbolt: {{
				ID:          "GO-2026-4923",
				Aliases:     []string{"CVE-2026-33817", "GHSA-6jwv-w5xf-7j27"},
				Summary:     "WITHDRAWN: out-of-range-index in go.etcd.io/bbolt",
				WithdrawnAt: bboltWithdrawnAt,
			}},
		},
	}

	uc := application.NewScanModuleUseCase(
		newFakeFacts(), newFakeBlob(), vulnStore, newFakeWalkStore(),
		&fakeScanner{results: map[string]domain.VulnerabilityRecord{}}, db, nil,
		fixedClock{t: time.Date(2026, 7, 28, 0, 0, 0, 0, time.UTC)}, "v16", slog.Default(),
	)
	if _, err := uc.Scan(t.Context(), application.ScanModuleParams{
		Coordinate: bbolt,
		WalkID:     "w1",
		Snapshot:   &snap,
	}); err != nil {
		t.Fatalf("Scan(): %v", err)
	}

	stored, ok := vulnStore.served(vulnStore.recordKey(bbolt, "v16", snap))
	if !ok {
		t.Fatal("no record was stored")
	}
	if stored.FindingsStatus != domain.FindingsRecordWithdrawn {
		t.Errorf("findings_status = %q, want %q — this is the false finding a security review acted on",
			stored.FindingsStatus, domain.FindingsRecordWithdrawn)
	}
	if stored.FindingsStatus == domain.FindingsRecordClean {
		t.Error("findings_status collapsed to Clean, which is the silent resolution the withdrawal must replace")
	}
	// The summary word carries the retraction rather than the coverage gap, on the
	// same terms an Affected match does on this path: the findings answer stays
	// visible to a consumer that reads only the word.
	if stored.OverallStatus != domain.StatusWithdrawn {
		t.Errorf("overall_status = %q, want %q", stored.OverallStatus, domain.StatusWithdrawn)
	}
	// The retracted advisory is retained with its date, so a reader can see what was
	// found and why it no longer stands.
	if len(stored.Findings) != 1 || !stored.Findings[0].WithdrawnAt.Equal(bboltWithdrawnAt) {
		t.Errorf("findings = %v, want the retracted advisory retained with its withdrawal date", stored.Findings)
	}
	if err := (domain.VulnerabilityRecordHasher{}).VerifyContentHash(stored); err != nil {
		t.Errorf("VerifyContentHash(stored) = %v, want nil", err)
	}
}

// TestScanModule_LiveAdvisoryBesideAWithdrawnOneStillAffects is the guard against
// over-applying the retraction. A module carrying one live advisory and one
// retracted one is affected, and the live advisory must not be masked by the
// retracted one sitting beside it.
func TestScanModule_LiveAdvisoryBesideAWithdrawnOneStillAffects(t *testing.T) {
	vulnStore := newFakeVulnStore()
	snap := vulntest.MustNew("vuln.go.dev", "2026-07-08T17:05:00Z")
	mod := coordinatetest.MustNew("github.com/mixed/mod", "v1.0.0")
	db := &fakeDatabase{
		snapshot:    snap,
		vulnerables: map[coordinate.ModuleCoordinate][]string{mod: {"GO-1", "GO-2"}},
		findings: map[coordinate.ModuleCoordinate][]domain.VulnerabilityFinding{
			mod: {
				{ID: "GO-1", Summary: "WITHDRAWN: retracted", WithdrawnAt: bboltWithdrawnAt},
				{ID: "GO-2", Summary: "live advisory"},
			},
		},
	}

	uc := application.NewScanModuleUseCase(
		newFakeFacts(), newFakeBlob(), vulnStore, newFakeWalkStore(),
		&fakeScanner{results: map[string]domain.VulnerabilityRecord{}}, db, nil,
		fixedClock{t: time.Date(2026, 7, 28, 0, 0, 0, 0, time.UTC)}, "v16", slog.Default(),
	)
	if _, err := uc.Scan(t.Context(), application.ScanModuleParams{
		Coordinate: mod,
		WalkID:     "w1",
		Snapshot:   &snap,
	}); err != nil {
		t.Fatalf("Scan(): %v", err)
	}

	stored, ok := vulnStore.served(vulnStore.recordKey(mod, "v16", snap))
	if !ok {
		t.Fatal("no record was stored")
	}
	if stored.FindingsStatus != domain.FindingsRecordAffected {
		t.Errorf("findings_status = %q, want %q: one live advisory decides the axis",
			stored.FindingsStatus, domain.FindingsRecordAffected)
	}
	if len(stored.Findings) != 2 {
		t.Errorf("findings = %v, want both advisories retained", stored.Findings)
	}
}
