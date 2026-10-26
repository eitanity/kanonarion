package sqlite_test

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"code.eitanity.com/kanonarion/internal/coordinate"
	fetchdomain "code.eitanity.com/kanonarion/internal/fetch/domain"
	"code.eitanity.com/kanonarion/internal/vuln/adapters/store/sqlite"
	"code.eitanity.com/kanonarion/internal/vuln/domain"
	"code.eitanity.com/kanonarion/internal/vuln/ports"
	"code.eitanity.com/kanonarion/internal/vuln/vulntest"
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

// TestPutVulnerabilityRecord_ReScanRetractsOnlyRetiredFindings proves an
// advisory is retired only across snapshots: a newer database that no longer
// matches it is served, and its key's index lists only what it still reports.
// Within one snapshot the same drop is a dispute, not a retirement.
func TestPutVulnerabilityRecord_ReScanRetractsOnlyRetiredFindings(t *testing.T) {
	ctx := t.Context()
	store := newTestStore(t)

	both := indexTestRecordAt(t, domain.RootingIsolated, "BUILT_WITH_BODIES",
		time.Date(2026, 7, 17, 20, 0, 0, 0, time.UTC), domain.StatusAffected,
		finding("GO-2026-0001"), finding("GO-2026-0002"))
	if err := store.PutVulnerabilityRecord(ctx, both); err != nil {
		t.Fatalf("first scan: %v", err)
	}

	newer := both
	newer.DatabaseSnapshot = vulntest.MustSealOver("govulndb", "2026-07-24T19:42:05Z",
		time.Date(2026, 7, 24, 19, 42, 5, 0, time.UTC), []byte("advisories, one corrected"))
	newer.ScannedAt = time.Date(2026, 7, 25, 20, 0, 0, 0, time.UTC)
	newer.Findings = []domain.VulnerabilityFinding{finding("GO-2026-0001")}
	newer = seal(t, newer)
	if err := store.PutVulnerabilityRecord(ctx, newer); err != nil {
		t.Fatalf("re-scan against the newer snapshot: %v", err)
	}

	history, err := store.ListVulnerabilityRecordsForModule(ctx, both.Coordinate, both.PipelineVersion)
	if err != nil {
		t.Fatalf("ListVulnerabilityRecordsForModule: %v", err)
	}
	served, err := domain.Compose(history)
	if err != nil {
		t.Fatalf("Compose over both snapshots: %v — a drop across snapshots is a retirement, not a dispute", err)
	}
	if served.ContentHash != newer.ContentHash {
		t.Fatalf("served %s, want the newer snapshot's record %s", served.ContentHash, newer.ContentHash)
	}
	if got := indexRowsAt(t, store, newer); !equalStrings(got, []string{"GO-2026-0001"}) {
		t.Fatalf("the newer snapshot's index = %v, want only the advisory it still reports", got)
	}

	assertByIDServesTheNewerSnapshot(t, store, both, newer)

	defects, err := store.CheckFindingsIndex(ctx)
	if err != nil {
		t.Fatalf("CheckFindingsIndex: %v", err)
	}
	if len(defects) != 0 {
		t.Fatalf("CheckFindingsIndex found %d defect(s): %v", len(defects), sqlite.FindingsIndexDefectsError(defects))
	}
}

// assertByIDServesTheNewerSnapshot checks vuln-by-id answers from the served,
// newer record: the advisory it still reports lists it, the one it dropped lists
// no module, and the older index rows stay as the lookup --timeline reads.
func assertByIDServesTheNewerSnapshot(t *testing.T, store *sqlite.Store, older, newer domain.VulnerabilityRecord) {
	t.Helper()
	ctx := t.Context()
	kept, err := store.ListVulnerabilityRecordsByFindingID(ctx, "GO-2026-0001", "")
	if err != nil || len(kept) != 1 || kept[0].ContentHash != newer.ContentHash {
		t.Fatalf("a still-reported finding matched %v, %v; want the newer record", kept, err)
	}
	if got := indexRowsAt(t, store, older); !equalStrings(got, []string{"GO-2026-0001", "GO-2026-0002"}) {
		t.Fatalf("the older snapshot's index = %v, want its rows kept", got)
	}
	retired, err := store.ListVulnerabilityRecordsByFindingID(ctx, "GO-2026-0002", "")
	if err != nil || len(retired) != 0 {
		t.Fatalf("a retired finding matched %v, %v; want no module, as vuln-show serves the newer record", retired, err)
	}
	if coords, cerr := store.ListCoordinatesByFindingID(ctx, "GO-2026-0002", ""); cerr != nil || len(coords) != 1 || coords[0] != older.Coordinate {
		t.Fatalf("history lookup = %v, %v; want the module, so --timeline still shows the retirement", coords, cerr)
	}
}

// TestPutVulnerabilityRecord_ADisputeIsAppendedIndexedAndRefused plants the
// in-snapshot drop through the store's own write path. The write appends, the
// index keeps both records' rows, the verifier agrees with the writer, and
// every composed read refuses while --history lists both.
func TestPutVulnerabilityRecord_ADisputeIsAppendedIndexedAndRefused(t *testing.T) {
	ctx := t.Context()
	store := newTestStore(t)

	both := indexTestRecordAt(t, domain.RootingIsolated, "METADATA_ONLY",
		time.Date(2026, 7, 17, 20, 0, 0, 0, time.UTC), domain.StatusAffected,
		finding("GO-2026-0001"), finding("GO-2026-0002", "CVE-2026-0002"))
	one := indexTestRecordAt(t, domain.RootingIsolated, "BUILT_WITH_BODIES",
		time.Date(2026, 7, 18, 20, 0, 0, 0, time.UTC), domain.StatusAffected,
		finding("GO-2026-0001"))
	for _, rec := range []domain.VulnerabilityRecord{both, one} {
		if err := store.PutVulnerabilityRecord(ctx, rec); err != nil {
			t.Fatalf("PutVulnerabilityRecord(%s): %v — a disputing record must still be appended", rec.ContentHash, err)
		}
	}

	if got, want := indexRowsAt(t, store, one), []string{"CVE-2026-0002", "GO-2026-0001", "GO-2026-0002"}; !equalStrings(got, want) {
		t.Fatalf("index = %v, want both records' identifiers %v", got, want)
	}
	defects, err := store.CheckFindingsIndex(ctx)
	if err != nil {
		t.Fatalf("CheckFindingsIndex: %v", err)
	}
	if len(defects) != 0 {
		t.Fatalf("CheckFindingsIndex found %d defect(s) on a disputed group: %v", len(defects), sqlite.FindingsIndexDefectsError(defects))
	}

	for _, id := range []string{"GO-2026-0001", "GO-2026-0002", "CVE-2026-0002"} {
		if _, lerr := store.ListVulnerabilityRecordsByFindingID(ctx, id, ""); !errors.Is(lerr, ports.ErrVulnConflict) {
			t.Errorf("ListVulnerabilityRecordsByFindingID(%s) = %v, want the dispute", id, lerr)
		}
	}
	if _, _, gerr := store.GetVulnerabilityRecordAt(ctx, one.Coordinate, one.PipelineVersion, indexTestSnapshot(), domain.RootingIsolated); !errors.Is(gerr, ports.ErrVulnConflict) {
		t.Errorf("GetVulnerabilityRecordAt = %v, want the dispute", gerr)
	}
	for _, hash := range []string{both.ContentHash, one.ContentHash} {
		if !strings.Contains(fmt.Sprint(composeErr(t, store, one)), hash) {
			t.Errorf("the refusal does not name %s", hash)
		}
	}

	history, err := store.ListVulnerabilityRecordsForModule(ctx, one.Coordinate, one.PipelineVersion)
	if err != nil || len(history) != 2 {
		t.Fatalf("history = %d records, %v; want both", len(history), err)
	}
}

// A dispute under an older snapshot is history once a newer snapshot is
// served: the by-advisory read answers from the newer record, and the advisory
// only the disputed group carried lists no module.
func TestListVulnerabilityRecordsByFindingID_AnOlderDisputeIsHistory(t *testing.T) {
	ctx := t.Context()
	store := newTestStore(t)

	both := indexTestRecordAt(t, domain.RootingIsolated, "", time.Date(2026, 7, 17, 20, 0, 0, 0, time.UTC),
		domain.StatusAffected, finding("GO-2026-0001"), finding("GO-2026-0002"))
	one := indexTestRecordAt(t, domain.RootingIsolated, "", time.Date(2026, 7, 18, 20, 0, 0, 0, time.UTC),
		domain.StatusAffected, finding("GO-2026-0001"))
	newer := one
	newer.DatabaseSnapshot = vulntest.MustSealOver("govulndb", "2026-07-24T19:42:05Z",
		time.Date(2026, 7, 24, 19, 42, 5, 0, time.UTC), []byte("advisories, later"))
	newer.ScannedAt = time.Date(2026, 7, 25, 20, 0, 0, 0, time.UTC)
	newer = seal(t, newer)
	for _, rec := range []domain.VulnerabilityRecord{both, one} {
		if err := store.PutVulnerabilityRecord(ctx, rec); err != nil {
			t.Fatalf("PutVulnerabilityRecord: %v", err)
		}
	}
	if _, err := store.ListVulnerabilityRecordsByFindingID(ctx, "GO-2026-0001", ""); !errors.Is(err, ports.ErrVulnConflict) {
		t.Fatalf("before the newer snapshot: %v, want the dispute", err)
	}
	if err := store.PutVulnerabilityRecord(ctx, newer); err != nil {
		t.Fatalf("PutVulnerabilityRecord(newer): %v", err)
	}

	kept, err := store.ListVulnerabilityRecordsByFindingID(ctx, "GO-2026-0001", "")
	if err != nil || len(kept) != 1 || kept[0].ContentHash != newer.ContentHash {
		t.Fatalf("GO-2026-0001 = %v, %v; want the newer record", kept, err)
	}
	dropped, err := store.ListVulnerabilityRecordsByFindingID(ctx, "GO-2026-0002", "")
	if err != nil || len(dropped) != 0 {
		t.Fatalf("GO-2026-0002 = %v, %v; want no module", dropped, err)
	}
}

// composeErr is the refusal a composed read of rec's coordinate returns.
func composeErr(t *testing.T, store *sqlite.Store, rec domain.VulnerabilityRecord) error {
	t.Helper()
	_, _, err := store.GetVulnerabilityRecordAt(t.Context(), rec.Coordinate, rec.PipelineVersion, rec.DatabaseSnapshot, domain.RecordRooting(rec))
	return err
}

// indexRowsAt is the findings index for rec's key and frame, sorted.
func indexRowsAt(t *testing.T, store *sqlite.Store, rec domain.VulnerabilityRecord) []string {
	t.Helper()
	rows, err := store.InternalDB().DB().QueryContext(t.Context(), `
SELECT finding_id FROM vulnerability_findings_index
WHERE module_path = ? AND module_version = ? AND pipeline_version = ?
  AND snapshot_source = ? AND snapshot_version = ? AND rooting = ?
ORDER BY finding_id`,
		rec.Coordinate.Path(), rec.Coordinate.Version(), rec.PipelineVersion,
		rec.DatabaseSnapshot.Source(), rec.DatabaseSnapshot.Version(), string(domain.RecordRooting(rec)))
	if err != nil {
		t.Fatalf("reading the findings index: %v", err)
	}
	defer func() { _ = rows.Close() }()
	var ids []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			t.Fatalf("scanning the findings index: %v", err)
		}
		ids = append(ids, id)
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("iterating the findings index: %v", err)
	}
	return ids
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

// After a Go upgrade one frame holds two toolchains' verdicts on one snapshot.
// The write that appends the new toolchain's record completes, the index then
// describes that toolchain's answer, and the verifier composes it the same way.
func TestPutVulnerabilityRecord_AGoUpgradeIndexesTheNewToolchain(t *testing.T) {
	ctx := t.Context()
	store := newTestStore(t)

	before := indexTestRecordAt(t, domain.RootingTargetRooted, "",
		time.Date(2026, 7, 17, 20, 0, 0, 0, time.UTC), domain.StatusAffected, finding("GO-2026-0001"))
	before.Toolchain = "go1.26.6"
	before = seal(t, before)
	if err := store.PutVulnerabilityRecord(ctx, before); err != nil {
		t.Fatalf("scan under the old toolchain: %v", err)
	}
	after := indexTestRecordAt(t, domain.RootingTargetRooted, "",
		time.Date(2026, 7, 18, 20, 0, 0, 0, time.UTC), domain.StatusAffected, finding("GO-2026-0002"))
	after.Toolchain = "go1.27.2"
	after.WalkID = "walk-2"
	after = seal(t, after)
	if err := store.PutVulnerabilityRecord(ctx, after); err != nil {
		t.Fatalf("the first scan after the upgrade refused: %v", err)
	}

	if recs, err := store.ListVulnerabilityRecordsByFindingID(ctx, "GO-2026-0001", ""); err != nil || len(recs) != 0 {
		t.Errorf("the old toolchain's advisory is still indexed: %d record(s), err %v", len(recs), err)
	}
	recs, err := store.ListVulnerabilityRecordsByFindingID(ctx, "GO-2026-0002", "")
	if err != nil || len(recs) != 1 || recs[0].ContentHash != after.ContentHash {
		t.Errorf("the new toolchain's advisory is not served from its record: %d record(s), err %v", len(recs), err)
	}
	defects, err := store.CheckFindingsIndex(ctx)
	if err != nil {
		t.Fatalf("CheckFindingsIndex: %v", err)
	}
	if len(defects) != 0 {
		t.Errorf("the verifier disagrees with the writer: %v", sqlite.FindingsIndexDefectsError(defects))
	}
	// The unpinned read still refuses: the index follows the newest build, the
	// read does not pick one for the caller.
	if _, _, err := store.GetVulnerabilityRecordAt(ctx, after.Coordinate, after.PipelineVersion, indexTestSnapshot(), domain.RootingTargetRooted); err == nil {
		t.Error("the unpinned read answered across two toolchains")
	}
}

// A walk's records are the generations its scan runs named. After a Go upgrade
// the older walk's record shares the newer walk's key; reaching it too made the
// walk-anchored reads refuse on a conflict the walk does not hold. A run that
// named no hash still reaches every generation of its key.
func TestListVulnerabilityRecordsForModuleInWalk_ReachesTheGenerationItsRunNamed(t *testing.T) {
	ctx := t.Context()
	store := newTestStore(t)
	before := indexTestRecordAt(t, domain.RootingTargetRooted, "",
		time.Date(2026, 7, 17, 20, 0, 0, 0, time.UTC), domain.StatusAffected, finding("GO-2026-0001"))
	before.Toolchain = "go1.26.6"
	before = seal(t, before)
	after := indexTestRecordAt(t, domain.RootingTargetRooted, "",
		time.Date(2026, 7, 18, 20, 0, 0, 0, time.UTC), domain.StatusAffected, finding("GO-2026-0001"), finding("GO-2026-0002"))
	after.Toolchain, after.WalkID = "go1.27.2", "walk-2"
	after = seal(t, after)
	for _, rec := range []domain.VulnerabilityRecord{before, after} {
		if err := store.PutVulnerabilityRecord(ctx, rec); err != nil {
			t.Fatalf("writing %s: %v", rec.ContentHash, err)
		}
	}
	putRunNaming(t, store, "walk-1", before)
	putRunNaming(t, store, "walk-2", after)
	putRunNaming(t, store, "walk-3", after)
	// walk-3's run predates the hash column: its membership names the key only.
	if _, err := store.InternalDB().DB().ExecContext(ctx,
		`UPDATE walk_scan_run_modules SET record_content_hash = '' WHERE walk_id = 'walk-3'`); err != nil {
		t.Fatal(err)
	}

	for walkID, want := range map[string]int{"walk-1": 1, "walk-2": 1, "walk-3": 2} {
		recs, err := store.ListVulnerabilityRecordsForModuleInWalk(ctx, after.Coordinate, after.PipelineVersion, walkID)
		if err != nil || len(recs) != want {
			t.Errorf("%s reaches %d record(s), err %v; want %d", walkID, len(recs), err, want)
		}
	}
	recs, err := store.ListVulnerabilityRecordsForModuleInWalk(ctx, after.Coordinate, after.PipelineVersion, "walk-2")
	if err == nil && len(recs) == 1 && recs[0].ContentHash != after.ContentHash {
		t.Errorf("walk-2 reaches %s, want its own record %s", recs[0].ContentHash, after.ContentHash)
	}
	for walkID, want := range map[string]string{"walk-1": before.ContentHash, "walk-2": after.ContentHash} {
		byID, err := store.ListVulnerabilityRecordsByFindingID(ctx, "GO-2026-0001", walkID)
		if err != nil || len(byID) != 1 || byID[0].ContentHash != want {
			t.Errorf("%s's advisory read = %d record(s), err %v; want its own record %s", walkID, len(byID), err, want)
		}
	}
}

// putRunNaming writes a scan run of walkID whose membership names rec's hash.
func putRunNaming(t *testing.T, store *sqlite.Store, walkID string, rec domain.VulnerabilityRecord) {
	t.Helper()
	run := sealRun(t, domain.WalkScanRun{
		ID: "run-" + walkID, WalkID: walkID, Snapshot: indexTestSnapshot(), OverallStatus: domain.WalkStatusAffected,
		PerModuleResults: map[coordinate.ModuleCoordinate]string{rec.Coordinate: rec.ContentHash},
		StartedAt:        rec.ScannedAt, CompletedAt: rec.ScannedAt.Add(time.Minute), PipelineVersion: rec.PipelineVersion,
	})
	if err := store.PutWalkScanRun(t.Context(), run); err != nil {
		t.Fatalf("writing %s: %v", run.ID, err)
	}
}

// After a Go upgrade the newer toolchain reports an advisory the older did not.
// The index lists the advisory at the shared key, but only the generation that
// carries it answers: never the older walk's record, which does not.
func TestListVulnerabilityRecordsByFindingID_ListsOnlyTheGenerationThatCarriesTheAdvisory(t *testing.T) {
	ctx := t.Context()
	store := newTestStore(t)
	before := indexTestRecordAt(t, domain.RootingTargetRooted, "",
		time.Date(2026, 7, 17, 20, 0, 0, 0, time.UTC), domain.StatusAffected, finding("GO-2026-0001"))
	before.Toolchain = "go1.26.6"
	before = seal(t, before)
	after := indexTestRecordAt(t, domain.RootingTargetRooted, "",
		time.Date(2026, 7, 18, 20, 0, 0, 0, time.UTC), domain.StatusAffected, finding("GO-2026-0001"), finding("GO-2026-0002"))
	after.Toolchain, after.WalkID = "go1.27.2", "walk-2"
	after = seal(t, after)
	for _, rec := range []domain.VulnerabilityRecord{before, after} {
		if err := store.PutVulnerabilityRecord(ctx, rec); err != nil {
			t.Fatalf("writing %s: %v", rec.ContentHash, err)
		}
	}
	putRunNaming(t, store, "walk-1", before)
	putRunNaming(t, store, "walk-2", after)

	for _, c := range []struct {
		walkID, findingID, want string
	}{
		{"walk-1", "GO-2026-0002", ""},
		{"walk-2", "GO-2026-0002", after.ContentHash},
		{"", "GO-2026-0002", after.ContentHash},
		{"walk-1", "GO-2026-0001", before.ContentHash},
		{"", "GO-2026-0001", after.ContentHash},
	} {
		recs, err := store.ListVulnerabilityRecordsByFindingID(ctx, c.findingID, c.walkID)
		if err != nil {
			t.Fatalf("%s in %q: %v", c.findingID, c.walkID, err)
		}
		got := ""
		if len(recs) == 1 {
			got = recs[0].ContentHash
		}
		if len(recs) > 1 || got != c.want {
			t.Errorf("%s in walk %q = %d record(s) %q, want %q", c.findingID, c.walkID, len(recs), got, c.want)
		}
	}
}

// Unscoped, the row is the record the index was composed from. Here the ladder
// serves the older generation, built with bodies, over a newer one that built
// no call graph; ranking by recency alone would list the record the index does
// not describe.
func TestListVulnerabilityRecordsByFindingID_UnscopedListsTheComposedRecord(t *testing.T) {
	ctx := t.Context()
	store := newTestStore(t)
	composed := indexTestRecordAt(t, domain.RootingIsolated, "BUILT_WITH_BODIES",
		time.Date(2026, 7, 17, 20, 0, 0, 0, time.UTC), domain.StatusAffected, finding("GO-2026-0001"))
	newer := indexTestRecordAt(t, domain.RootingIsolated, "",
		time.Date(2026, 7, 18, 20, 0, 0, 0, time.UTC), domain.StatusAffected, finding("GO-2026-0001"))
	for _, rec := range []domain.VulnerabilityRecord{composed, newer} {
		if err := store.PutVulnerabilityRecord(ctx, rec); err != nil {
			t.Fatalf("writing %s: %v", rec.ContentHash, err)
		}
	}
	recs, err := store.ListVulnerabilityRecordsByFindingID(ctx, "GO-2026-0001", "")
	if err != nil || len(recs) != 1 || recs[0].ContentHash != composed.ContentHash {
		t.Errorf("= %d record(s), err %v; want the composed record %s", len(recs), err, composed.ContentHash)
	}
}
