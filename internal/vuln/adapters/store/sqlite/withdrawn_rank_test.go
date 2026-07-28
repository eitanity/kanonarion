package sqlite_test

import (
	"testing"
	"time"

	fetchdomain "github.com/eitanity/kanonarion/internal/fetch/domain"
	"github.com/eitanity/kanonarion/internal/vuln/domain"
)

// A later withdrawal must supersede an earlier Affected verdict, and a later bare
// all-clear still must not.
//
// The two cases share one ranking expression and pull in opposite directions,
// which is why they are asserted together. The interim guard ranked "reports a
// finding" above everything else, and a withdrawn record does report one — so if
// Withdrawn were ranked with Clean it would lose to the stale Affected row and
// vuln-by-id would keep answering with the false finding, the exact outcome the
// guard was put in to prevent for the opposite case.
func TestListVulnerabilityRecordsByFindingID_WithdrawalSupersedesAnAffectedVerdict(t *testing.T) {
	ctx := t.Context()
	store := newTestStore(t)

	affected := findingRecord(t, "go.etcd.io/bbolt", "v1.4.3", "walk-1", "GO-2026-4923", snap("vuln.go.dev", "2026-04-07"))
	affected.ScannedAt = time.Date(2026, 4, 7, 0, 0, 0, 0, time.UTC)
	affected = seal(t, affected)

	// The same coordinate re-scanned after the retraction was readable. It carries
	// the same finding — so it joins the findings index and enters the ranking — with
	// the retraction stated on the finding and on the axis.
	withdrawn := seal(t, domain.VulnerabilityRecord{
		Ecosystem:        fetchdomain.EcosystemGo,
		Coordinate:       coord("go.etcd.io/bbolt", "v1.4.3"),
		WalkID:           "walk-1",
		DatabaseSnapshot: snap("vuln.go.dev", "2026-07-08"),
		ScannedAt:        time.Date(2026, 7, 28, 0, 0, 0, 0, time.UTC),
		PipelineVersion:  "v16",
		CoverageStatus:   domain.CoverageAnalysed,
		Findings: []domain.VulnerabilityFinding{{
			ID:          "GO-2026-4923",
			Summary:     "WITHDRAWN: out-of-range-index in go.etcd.io/bbolt",
			WithdrawnAt: time.Date(2026, 4, 8, 13, 33, 56, 0, time.UTC),
		}},
	})
	if withdrawn.FindingsStatus != domain.FindingsRecordWithdrawn {
		t.Fatalf("fixture findings axis = %q, want %q", withdrawn.FindingsStatus, domain.FindingsRecordWithdrawn)
	}

	for _, rec := range []domain.VulnerabilityRecord{affected, withdrawn} {
		if err := store.PutVulnerabilityRecord(ctx, rec); err != nil {
			t.Fatalf("PutVulnerabilityRecord: %v", err)
		}
	}

	got, err := store.ListVulnerabilityRecordsByFindingID(ctx, "GO-2026-4923", "")
	if err != nil {
		t.Fatalf("ListVulnerabilityRecordsByFindingID: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("got %d records, want 1 per coordinate", len(got))
	}
	if got[0].OverallStatus != domain.StatusWithdrawn {
		t.Errorf("status = %s, want %s: the retraction is a stated reason and supersedes the earlier verdict",
			got[0].OverallStatus, domain.StatusWithdrawn)
	}
}

// The mirror case, on the same ranking expression: a record whose live advisory
// still stands must not lose to a withdrawal of a different advisory recorded
// later. Both are in the finding-bearing tier, so the newest wins — which here is
// the withdrawal for its own ID and the Affected record for its own, with neither
// answering for the other.
func TestListVulnerabilityRecordsByFindingID_AWithdrawalDoesNotAnswerForAnotherAdvisory(t *testing.T) {
	ctx := t.Context()
	store := newTestStore(t)

	live := findingRecord(t, "golang.org/x/text", "v0.37.0", "walk-1", "GO-2026-5970", snap("vuln.go.dev", "2026-07-08"))
	live.ScannedAt = time.Date(2026, 7, 1, 0, 0, 0, 0, time.UTC)
	live = seal(t, live)

	withdrawn := seal(t, domain.VulnerabilityRecord{
		Ecosystem:        fetchdomain.EcosystemGo,
		Coordinate:       coord("go.etcd.io/bbolt", "v1.4.3"),
		WalkID:           "walk-1",
		DatabaseSnapshot: snap("vuln.go.dev", "2026-07-08"),
		ScannedAt:        time.Date(2026, 7, 28, 0, 0, 0, 0, time.UTC),
		PipelineVersion:  "v16",
		CoverageStatus:   domain.CoverageAnalysed,
		Findings: []domain.VulnerabilityFinding{{
			ID:          "GO-2026-4923",
			WithdrawnAt: time.Date(2026, 4, 8, 13, 33, 56, 0, time.UTC),
		}},
	})

	for _, rec := range []domain.VulnerabilityRecord{live, withdrawn} {
		if err := store.PutVulnerabilityRecord(ctx, rec); err != nil {
			t.Fatalf("PutVulnerabilityRecord: %v", err)
		}
	}

	got, err := store.ListVulnerabilityRecordsByFindingID(ctx, "GO-2026-5970", "")
	if err != nil {
		t.Fatalf("ListVulnerabilityRecordsByFindingID: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("got %d records, want 1", len(got))
	}
	if got[0].OverallStatus != domain.StatusAffected {
		t.Errorf("status = %s, want %s: the live advisory still stands", got[0].OverallStatus, domain.StatusAffected)
	}
}
