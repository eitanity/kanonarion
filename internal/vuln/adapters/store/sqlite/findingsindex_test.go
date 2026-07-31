package sqlite_test

import (
	"context"
	"strings"
	"testing"
	"time"

	fetchdomain "github.com/eitanity/kanonarion/internal/fetch/domain"
	"github.com/eitanity/kanonarion/internal/vuln/adapters/store/sqlite"
	"github.com/eitanity/kanonarion/internal/vuln/domain"
	"github.com/eitanity/kanonarion/internal/vuln/vulntest"
)

// indexTestSnapshot is the one snapshot every test here re-scans against, so
// the re-scan lands on the same (module, version, pipeline, snapshot) key the
// index is reconciled on.
func indexTestSnapshot() domain.DatabaseSnapshot {
	return vulntest.MustSealOver("govulndb", "2026-07-17T19:42:05Z", time.Date(2026, 7, 17, 19, 42, 5, 0, time.UTC), []byte("advisories"))
}

// indexTestRecord builds a sealed record for the shared key carrying findings.
func indexTestRecord(t *testing.T, status domain.VulnerabilityStatus, findings ...domain.VulnerabilityFinding) domain.VulnerabilityRecord {
	t.Helper()
	return indexTestRecordAt(t, domain.RootingIsolated, "", time.Date(2026, 7, 17, 20, 0, 0, 0, time.UTC), status, findings...)
}

// indexTestRecordAt builds a sealed record for the shared key in a named
// analysis frame, at a named call-graph completeness and scan time. The ledger
// keeps every generation, so a test that wants a particular one served has to
// say which rung of the ladder puts it there.
func indexTestRecordAt(
	t *testing.T,
	rooting domain.Rooting,
	completeness string,
	scannedAt time.Time,
	status domain.VulnerabilityStatus,
	findings ...domain.VulnerabilityFinding,
) domain.VulnerabilityRecord {
	t.Helper()
	return seal(t, domain.VulnerabilityRecord{
		Ecosystem:             fetchdomain.EcosystemGo,
		Coordinate:            coord("golang.org/x/text", "v0.37.0"),
		WalkID:                "walk-1",
		Findings:              findings,
		OverallStatus:         status,
		DatabaseSnapshot:      indexTestSnapshot(),
		ScannedAt:             scannedAt,
		FirstScannedAt:        scannedAt,
		PipelineVersion:       "v14",
		CallGraphCompleteness: completeness,
		Rooting:               rooting,
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

// TestPutVulnerabilityRecord_BareCleanReScanDoesNotRetractAFinding pins the
// ledger's answer to the case the overwriting store handled by deletion.
//
// When a re-scan overwrote its predecessor, the record backing the index rows
// was gone, so the rows had to go with it or vuln-by-id answered from evidence
// no record supported. Against a ledger both generations survive, and the
// composed record is the finding-bearing one: a bare all-clear that offers no
// reason is not authority to retire a finding, which is the rule the by-finding
// ranking already applies. Retracting the index here would therefore delete the
// rows that ranking needs and make it unreachable — the answer would be "no
// modules affected" for a module whose served record says otherwise.
func TestPutVulnerabilityRecord_BareCleanReScanDoesNotRetractAFinding(t *testing.T) {
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

	// A later scan of the same key comes back clean, offering no reason.
	clean := indexTestRecordAt(t, domain.RootingIsolated, "",
		time.Date(2026, 7, 18, 20, 0, 0, 0, time.UTC), domain.StatusClean)
	if err := store.PutVulnerabilityRecord(ctx, clean); err != nil {
		t.Fatalf("re-scan: %v", err)
	}

	for _, id := range []string{"GO-2026-5970", "CVE-2026-56852"} {
		recs, err := store.ListVulnerabilityRecordsByFindingID(ctx, id, "")
		if err != nil {
			t.Fatalf("ListVulnerabilityRecordsByFindingID(%s): %v", id, err)
		}
		if len(recs) != 1 {
			t.Fatalf("after an unexplained all-clear, %s matched %d records, want 1: "+
				"a later Clean must not retire a finding", id, len(recs))
		}
	}

	// Both generations are still there, which is what makes the earlier finding
	// auditable rather than merely retained in an index.
	history, err := store.ListVulnerabilityRecordsForModule(ctx, affected.Coordinate, affected.PipelineVersion)
	if err != nil {
		t.Fatalf("ListVulnerabilityRecordsForModule: %v", err)
	}
	if len(history) != 2 {
		t.Fatalf("ledger holds %d generations, want 2", len(history))
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
// reconciliation is a rewrite, not a purge: a finding the served record still
// reports keeps its index row, and only the one that stopped applying is
// dropped.
//
// The re-scan supersedes its predecessor on the completeness rung, not on the
// clock: both records report an advisory, so the ladder's first two rungs tie
// and the better-founded call graph decides. That is the only way one
// finding-bearing record displaces another, and it is what makes the drop of
// the retired row a statement about evidence rather than about recency.
func TestPutVulnerabilityRecord_ReScanRetractsOnlyRetiredFindings(t *testing.T) {
	ctx := t.Context()
	store := newTestStore(t)

	both := indexTestRecordAt(t, domain.RootingIsolated, "METADATA_ONLY",
		time.Date(2026, 7, 17, 20, 0, 0, 0, time.UTC), domain.StatusAffected,
		finding("GO-2026-0001"), finding("GO-2026-0002"))
	if err := store.PutVulnerabilityRecord(ctx, both); err != nil {
		t.Fatalf("first scan: %v", err)
	}

	one := indexTestRecordAt(t, domain.RootingIsolated, "BUILT_WITH_BODIES",
		time.Date(2026, 7, 18, 20, 0, 0, 0, time.UTC), domain.StatusAffected,
		finding("GO-2026-0001"))
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

// TestPutVulnerabilityRecord_FramesDoNotRetractEachOther is the defect this
// conversion exists for, at the index. A target-rooted scan and an isolated scan
// of one coordinate under one snapshot are two answers to two questions; before
// the frame was recorded they shared a row, so writing either retracted the
// other's findings. Both must now stand.
func TestPutVulnerabilityRecord_FramesDoNotRetractEachOther(t *testing.T) {
	ctx := t.Context()
	store := newTestStore(t)

	isolated := indexTestRecordAt(t, domain.RootingIsolated, "",
		time.Date(2026, 7, 17, 20, 0, 0, 0, time.UTC), domain.StatusAffected,
		finding("GO-2026-0001"))
	if err := store.PutVulnerabilityRecord(ctx, isolated); err != nil {
		t.Fatalf("isolated scan: %v", err)
	}

	// The target-rooted analysis reaches this module through the target's build
	// and finds the advisory does not apply there. It says nothing about the
	// isolated question, so it must not retract the isolated answer.
	targetRooted := indexTestRecordAt(t, domain.RootingTargetRooted, "",
		time.Date(2026, 7, 18, 20, 0, 0, 0, time.UTC), domain.StatusClean)
	if err := store.PutVulnerabilityRecord(ctx, targetRooted); err != nil {
		t.Fatalf("target-rooted scan: %v", err)
	}

	recs, err := store.ListVulnerabilityRecordsByFindingID(ctx, "GO-2026-0001", "")
	if err != nil {
		t.Fatalf("ListVulnerabilityRecordsByFindingID: %v", err)
	}
	if len(recs) != 1 {
		t.Fatalf("after a target-rooted all-clear, the isolated finding matched %d records, want 1", len(recs))
	}

	// Each frame is readable on its own terms, and neither is served for the
	// other's question.
	iso, ok, err := store.GetVulnerabilityRecordAt(ctx, isolated.Coordinate, isolated.PipelineVersion, indexTestSnapshot(), domain.RootingIsolated)
	if err != nil || !ok {
		t.Fatalf("GetVulnerabilityRecordAt(isolated) = found %v, err %v", ok, err)
	}
	if iso.ContentHash != isolated.ContentHash {
		t.Fatalf("isolated frame served %q, want the isolated record %q", iso.ContentHash, isolated.ContentHash)
	}
	tr, ok, err := store.GetVulnerabilityRecordAt(ctx, isolated.Coordinate, isolated.PipelineVersion, indexTestSnapshot(), domain.RootingTargetRooted)
	if err != nil || !ok {
		t.Fatalf("GetVulnerabilityRecordAt(target-rooted) = found %v, err %v", ok, err)
	}
	if tr.ContentHash != targetRooted.ContentHash {
		t.Fatalf("target-rooted frame served %q, want the target-rooted record %q", tr.ContentHash, targetRooted.ContentHash)
	}

	defects, err := store.CheckFindingsIndex(ctx)
	if err != nil {
		t.Fatalf("CheckFindingsIndex: %v", err)
	}
	if len(defects) != 0 {
		t.Fatalf("CheckFindingsIndex found %d defect(s): %v", len(defects), sqlite.FindingsIndexDefectsError(defects))
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
    snapshot_source, snapshot_version, rooting
) VALUES (?, ?, ?, ?, ?, ?, ?)`
	if _, err := store.InternalDB().DB().ExecContext(ctx, q,
		findingID, rec.Coordinate.Path(), rec.Coordinate.Version(), rec.PipelineVersion,
		rec.DatabaseSnapshot.Source(), rec.DatabaseSnapshot.Version(), string(rec.Rooting),
	); err != nil {
		t.Fatalf("planting index row: %v", err)
	}
}
