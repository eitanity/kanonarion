package sqlite_test

import (
	"context"
	"strings"
	"testing"
	"time"

	fetchdomain "github.com/eitanity/kanonarion/internal/fetch/domain"
	"github.com/eitanity/kanonarion/internal/vuln/adapters/store/sqlite"
	"github.com/eitanity/kanonarion/internal/vuln/domain"
)

// indexTestSnapshot is the one snapshot every test here re-scans against, so
// the re-scan lands on the same (module, version, pipeline, snapshot) key the
// index is reconciled on.
func indexTestSnapshot() domain.DatabaseSnapshot {
	return domain.DatabaseSnapshot{
		Source:      "govulndb",
		Version:     "2026-07-17T19:42:05Z",
		RetrievedAt: time.Date(2026, 7, 17, 19, 42, 5, 0, time.UTC),
		ContentHash: "snapshot-hash",
	}
}

// indexTestRecord builds a sealed record for the shared key carrying findings.
func indexTestRecord(t *testing.T, status domain.VulnerabilityStatus, findings ...domain.VulnerabilityFinding) domain.VulnerabilityRecord {
	t.Helper()
	return seal(t, domain.VulnerabilityRecord{
		Ecosystem:        fetchdomain.EcosystemGo,
		Coordinate:       coord("golang.org/x/text", "v0.37.0"),
		WalkID:           "walk-1",
		Findings:         findings,
		OverallStatus:    status,
		DatabaseSnapshot: indexTestSnapshot(),
		ScannedAt:        time.Date(2026, 7, 17, 20, 0, 0, 0, time.UTC),
		FirstScannedAt:   time.Date(2026, 7, 17, 20, 0, 0, 0, time.UTC),
		PipelineVersion:  "v14",
	})
}

func finding(id string, aliases ...string) domain.VulnerabilityFinding {
	return domain.VulnerabilityFinding{
		ID:            id,
		Aliases:       aliases,
		Summary:       "summary of " + id,
		AffectedRange: "< v0.38.0",
	}
}

// TestPutVulnerabilityRecord_ReScanRetractsIndexRows reproduces the defect end
// to end: scan a coordinate that yields findings, re-scan the
// same key against a state that yields none, and the index must no longer claim
// the retired advisories. Before the reconciliation the old rows survived and
// put the module into vuln-by-id's answer on evidence its own record denies.
func TestPutVulnerabilityRecord_ReScanRetractsIndexRows(t *testing.T) {
	ctx := t.Context()
	store := newTestStore(t)

	affected := indexTestRecord(t, domain.StatusAffected,
		finding("GO-2026-5970", "CVE-2026-56852"))
	if err := store.PutVulnerabilityRecord(ctx, affected); err != nil {
		t.Fatalf("first scan: %v", err)
	}

	// The index answers for both the finding's own ID and its alias.
	for _, id := range []string{"GO-2026-5970", "CVE-2026-56852"} {
		recs, err := store.ListVulnerabilityRecordsByFindingID(ctx, id, "")
		if err != nil {
			t.Fatalf("ListVulnerabilityRecordsByFindingID(%s): %v", id, err)
		}
		if len(recs) != 1 {
			t.Fatalf("after the affected scan, %s matched %d records, want 1", id, len(recs))
		}
	}

	// The re-scan of the same key comes back clean.
	clean := indexTestRecord(t, domain.StatusClean)
	if err := store.PutVulnerabilityRecord(ctx, clean); err != nil {
		t.Fatalf("re-scan: %v", err)
	}

	for _, id := range []string{"GO-2026-5970", "CVE-2026-56852"} {
		recs, err := store.ListVulnerabilityRecordsByFindingID(ctx, id, "")
		if err != nil {
			t.Fatalf("ListVulnerabilityRecordsByFindingID(%s): %v", id, err)
		}
		if len(recs) != 0 {
			t.Fatalf("after an all-clear re-scan, %s still matched %d records; "+
				"the index kept rows the record does not support", id, len(recs))
		}
	}

	defects, err := store.CheckFindingsIndex(ctx)
	if err != nil {
		t.Fatalf("CheckFindingsIndex: %v", err)
	}
	if len(defects) != 0 {
		t.Fatalf("CheckFindingsIndex found %d defect(s) after a clean re-scan: %v",
			len(defects), sqlite.FindingsIndexDefectsError(defects))
	}
}

// TestPutVulnerabilityRecord_ReScanRetractsOnlyRetiredFindings proves the
// reconciliation is a rewrite, not a purge: a finding the re-scan still reports
// keeps its index row, and only the one that stopped applying is dropped.
func TestPutVulnerabilityRecord_ReScanRetractsOnlyRetiredFindings(t *testing.T) {
	ctx := t.Context()
	store := newTestStore(t)

	both := indexTestRecord(t, domain.StatusAffected,
		finding("GO-2026-0001"), finding("GO-2026-0002"))
	if err := store.PutVulnerabilityRecord(ctx, both); err != nil {
		t.Fatalf("first scan: %v", err)
	}

	one := indexTestRecord(t, domain.StatusAffected, finding("GO-2026-0001"))
	if err := store.PutVulnerabilityRecord(ctx, one); err != nil {
		t.Fatalf("re-scan: %v", err)
	}

	kept, err := store.ListVulnerabilityRecordsByFindingID(ctx, "GO-2026-0001", "")
	if err != nil {
		t.Fatalf("ListVulnerabilityRecordsByFindingID(kept): %v", err)
	}
	if len(kept) != 1 {
		t.Fatalf("a still-reported finding matched %d records, want 1 — the rewrite dropped a live row", len(kept))
	}

	retired, err := store.ListVulnerabilityRecordsByFindingID(ctx, "GO-2026-0002", "")
	if err != nil {
		t.Fatalf("ListVulnerabilityRecordsByFindingID(retired): %v", err)
	}
	if len(retired) != 0 {
		t.Fatalf("a retired finding still matched %d records, want 0", len(retired))
	}
}

// TestCheckFindingsIndex_DetectsUnsupportedRow pins the check itself against a
// row planted the way the old append-only write path produced them. Without
// this the class of defect returns silently: each record involved is
// internally valid and correctly sealed, so no content-hash check sees it.
func TestCheckFindingsIndex_DetectsUnsupportedRow(t *testing.T) {
	ctx := t.Context()
	store := newTestStore(t)

	clean := indexTestRecord(t, domain.StatusClean)
	if err := store.PutVulnerabilityRecord(ctx, clean); err != nil {
		t.Fatalf("writing the all-clear record: %v", err)
	}

	plantIndexRow(t, ctx, store, "CVE-2026-56852", clean)

	defects, err := store.CheckFindingsIndex(ctx)
	if err != nil {
		t.Fatalf("CheckFindingsIndex: %v", err)
	}
	if len(defects) != 1 {
		t.Fatalf("CheckFindingsIndex found %d defect(s), want 1: %v", len(defects), defects)
	}
	got := defects[0]
	if got.FindingID != "CVE-2026-56852" || got.ModulePath != "golang.org/x/text" {
		t.Fatalf("defect names the wrong row: %+v", got)
	}
	if !strings.Contains(got.String(), "does not carry this finding") {
		t.Fatalf("defect reason = %q, want it to name the record's disagreement", got.String())
	}

	err = sqlite.FindingsIndexDefectsError(defects)
	if err == nil {
		t.Fatal("FindingsIndexDefectsError(non-empty) = nil, want a failure")
	}
	if !strings.Contains(err.Error(), "CVE-2026-56852") {
		t.Fatalf("error text does not name the offending advisory: %v", err)
	}
}

// TestCheckFindingsIndex_DetectsRowWithNoRecord covers the weaker orphan: an
// index row whose record is absent entirely. It puts a module into an
// advisory's answer on the strength of no evidence at all, so it is a defect on
// the same terms as one whose record disagrees.
func TestCheckFindingsIndex_DetectsRowWithNoRecord(t *testing.T) {
	ctx := t.Context()
	store := newTestStore(t)

	orphan := indexTestRecord(t, domain.StatusClean)
	plantIndexRow(t, ctx, store, "GO-2026-9999", orphan)

	defects, err := store.CheckFindingsIndex(ctx)
	if err != nil {
		t.Fatalf("CheckFindingsIndex: %v", err)
	}
	if len(defects) != 1 {
		t.Fatalf("CheckFindingsIndex found %d defect(s), want 1: %v", len(defects), defects)
	}
	if !strings.Contains(defects[0].String(), "no vulnerability record exists") {
		t.Fatalf("defect reason = %q, want it to name the missing record", defects[0].String())
	}
}

// TestCheckFindingsIndex_CleanStoreIsSilent proves the check does not
// manufacture defects: a store written entirely through the reconciling path
// reports none, and FindingsIndexDefectsError renders that as nil.
func TestCheckFindingsIndex_CleanStoreIsSilent(t *testing.T) {
	ctx := t.Context()
	store := newTestStore(t)

	rec := indexTestRecord(t, domain.StatusAffected,
		finding("GO-2026-0001", "CVE-2026-1111", "GHSA-aaaa-bbbb-cccc"))
	if err := store.PutVulnerabilityRecord(ctx, rec); err != nil {
		t.Fatalf("writing record: %v", err)
	}

	defects, err := store.CheckFindingsIndex(ctx)
	if err != nil {
		t.Fatalf("CheckFindingsIndex: %v", err)
	}
	if len(defects) != 0 {
		t.Fatalf("CheckFindingsIndex found %d defect(s) on a store written only through Put: %v",
			len(defects), defects)
	}
	if err := sqlite.FindingsIndexDefectsError(defects); err != nil {
		t.Fatalf("FindingsIndexDefectsError(empty) = %v, want nil", err)
	}
}

// plantIndexRow writes an index row directly, bypassing PutVulnerabilityRecord.
// This is the only way to reproduce the pre-fix state: the write path no longer
// produces it, and the check has to be pinned against a store that holds one.
func plantIndexRow(t *testing.T, ctx context.Context, store *sqlite.Store, findingID string, rec domain.VulnerabilityRecord) {
	t.Helper()
	const q = `
INSERT INTO vulnerability_findings_index (
    finding_id, module_path, module_version, pipeline_version,
    snapshot_source, snapshot_version, is_reachable
) VALUES (?, ?, ?, ?, ?, ?, NULL)`
	if _, err := store.InternalDB().DB().ExecContext(ctx, q,
		findingID, rec.Coordinate.Path(), rec.Coordinate.Version(), rec.PipelineVersion,
		rec.DatabaseSnapshot.Source, rec.DatabaseSnapshot.Version,
	); err != nil {
		t.Fatalf("planting index row: %v", err)
	}
}
