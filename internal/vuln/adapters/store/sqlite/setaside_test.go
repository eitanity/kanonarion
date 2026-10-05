package sqlite_test

import (
	"bytes"
	"errors"
	"sort"
	"testing"
	"time"

	"github.com/eitanity/kanonarion/internal/adapters/recordseal"
	"github.com/eitanity/kanonarion/internal/coordinate"
	fetchdomain "github.com/eitanity/kanonarion/internal/fetch/domain"
	"github.com/eitanity/kanonarion/internal/vuln/adapters/store/sqlite"
	"github.com/eitanity/kanonarion/internal/vuln/domain"
	"github.com/eitanity/kanonarion/internal/vuln/ports"
)

// A group holding one generation this build cannot reproduce — written by a
// build whose canonical shape differs — must not take every later write and read
// of that group down with it. These tests build such a group by hand, because a
// store written by one build never holds one.

// groupRecord is one generation of the shared group: same coordinate, pipeline,
// snapshot and frame, differing in scan time and findings.
func groupRecord(t *testing.T, at time.Time, ids ...string) domain.VulnerabilityRecord {
	t.Helper()
	rec := domain.VulnerabilityRecord{
		Ecosystem:        fetchdomain.EcosystemGo,
		Coordinate:       coord("example.com/group", "v1.0.0"),
		WalkID:           "walk-1",
		OverallStatus:    domain.StatusClean,
		DatabaseSnapshot: snap("govulndb", "v2024-01-01"),
		ScannedAt:        at,
		PipelineVersion:  "v1",
		Rooting:          domain.RootingIsolated,
	}
	for _, id := range ids {
		rec.OverallStatus = domain.StatusAffected
		rec.Findings = append(rec.Findings, domain.VulnerabilityFinding{ID: id, Summary: "advisory " + id, AffectedRange: "< v9.0.0"})
	}
	return seal(t, rec)
}

// groupWithStoredOddRow writes two readable generations and a third whose stored
// row is then replaced by bytes from rewrite, and returns the readable two as
// stored and the odd row's seal.
//
// The odd generation carries an advisory neither readable one does, so an index
// or a read that let it in would show it.
func groupWithStoredOddRow(t *testing.T, rewrite func(*testing.T, domain.VulnerabilityRecord) []byte) (*sqlite.Store, []domain.VulnerabilityRecord, string) {
	t.Helper()
	ctx := t.Context()
	store := newTestStore(t)

	first := groupRecord(t, time.Date(2024, 2, 1, 0, 0, 0, 0, time.UTC), "GO-2024-0001")
	odd := groupRecord(t, time.Date(2024, 2, 1, 1, 0, 0, 0, time.UTC), "GO-2024-0002")
	for _, rec := range []domain.VulnerabilityRecord{first, odd} {
		if err := store.PutVulnerabilityRecord(ctx, rec); err != nil {
			t.Fatalf("PutVulnerabilityRecord: %v", err)
		}
	}
	blob := rewrite(t, odd)
	oddSeal := sealIn(t, blob)
	if _, err := store.InternalDB().DB().ExecContext(ctx,
		`UPDATE vulnerability_records SET serialised = ?, content_hash = ? WHERE content_hash = ?`,
		blob, oddSeal, odd.ContentHash); err != nil {
		t.Fatalf("installing the odd row: %v", err)
	}
	return store, []domain.VulnerabilityRecord{first}, oddSeal
}

// indexedIDs is the findings index for the group, sorted.
func indexedIDs(t *testing.T, store *sqlite.Store) []string {
	t.Helper()
	rows, err := store.InternalDB().DB().QueryContext(t.Context(),
		`SELECT finding_id FROM vulnerability_findings_index WHERE module_path = 'example.com/group' AND rooting = ?`,
		string(domain.RootingIsolated))
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
	sort.Strings(ids)
	return ids
}

func findingIDs(rec domain.VulnerabilityRecord) []string {
	ids := make([]string, 0, len(rec.Findings))
	for _, f := range rec.Findings {
		ids = append(ids, f.ID)
	}
	sort.Strings(ids)
	return ids
}

// TestDriftedGeneration_SetAsideOnWriteAndRead is the regression: with one
// drifted and two readable generations in a group, the write succeeds, the
// findings index is ComposeAt over the readable two, the read composes the same,
// and both name the drifted generation by its seal.
func TestDriftedGeneration_SetAsideOnWriteAndRead(t *testing.T) {
	ctx := t.Context()
	store, readable, driftSeal := groupWithStoredOddRow(t, driftRecordBlob)

	second := groupRecord(t, time.Date(2024, 2, 1, 2, 0, 0, 0, time.UTC), "GO-2024-0003")
	err := store.PutVulnerabilityRecord(ctx, second)
	var aside *ports.SetAsideGenerations
	if !errors.As(err, &aside) {
		t.Fatalf("PutVulnerabilityRecord = %v, want the write to commit and name the drifted generation", err)
	}
	if len(aside.Rows) != 1 || aside.Rows[0].ContentHash != driftSeal {
		t.Fatalf("set aside = %v, want exactly the drifted generation %s", aside.Rows, driftSeal)
	}
	if errors.Is(err, ports.ErrVulnIntegrity) {
		t.Errorf("a drifted generation was reported as an integrity failure: %v", err)
	}
	if kept, herr := store.HasVulnerabilityRecord(ctx, second.Coordinate, second.PipelineVersion, second.DatabaseSnapshot, second.ContentHash); herr != nil || !kept {
		t.Fatalf("HasVulnerabilityRecord = (%v, %v), want the new generation stored", kept, herr)
	}

	readable = append(readable, second)
	want, ok, cerr := domain.ComposeAt(readable, domain.RootingIsolated)
	if cerr != nil || !ok {
		t.Fatalf("ComposeAt over the readable generations = (%v, %v)", ok, cerr)
	}
	if got, wantIDs := indexedIDs(t, store), findingIDs(want); !equalStrings(got, wantIDs) {
		t.Errorf("findings index = %v, want ComposeAt over the readable generations %v", got, wantIDs)
	}

	served, found, rerr := store.GetVulnerabilityRecordAt(ctx, second.Coordinate, "v1", second.DatabaseSnapshot, domain.RootingIsolated)
	if !found {
		t.Fatalf("GetVulnerabilityRecordAt found nothing (%v), want the composed record", rerr)
	}
	var readAside *ports.SetAsideGenerations
	if !errors.As(rerr, &readAside) || len(readAside.Rows) != 1 || readAside.Rows[0].ContentHash != driftSeal {
		t.Fatalf("GetVulnerabilityRecordAt error = %v, want the drifted generation %s named", rerr, driftSeal)
	}
	if served.ContentHash != want.ContentHash {
		t.Errorf("served %s, want the record ComposeAt serves over the readable generations, %s", served.ContentHash, want.ContentHash)
	}
	if !errors.Is(rerr, recordseal.ErrGenerationDrift) {
		t.Errorf("the set-aside reason does not classify as drift: %v", rerr)
	}
}

// TestAlteredGeneration_StillAbortsWriteAndRead is the control: a generation
// whose stored bytes no longer hash to their own seal is not excused. The write
// that reconciles its group and the read that composes it both refuse with the
// integrity error, exactly as before.
func TestAlteredGeneration_StillAbortsWriteAndRead(t *testing.T) {
	ctx := t.Context()
	flipOneByte := func(t *testing.T, rec domain.VulnerabilityRecord) []byte {
		t.Helper()
		blob, err := domain.VulnerabilityRecordHasher{}.Marshal(rec)
		if err != nil {
			t.Fatalf("marshalling: %v", err)
		}
		at := bytes.Index(blob, []byte("advisory GO-2024-0002"))
		if at < 0 {
			t.Fatal("fixture has no summary to alter")
		}
		blob[at] = 'A'
		return blob
	}
	store, _, _ := groupWithStoredOddRow(t, flipOneByte)

	err := store.PutVulnerabilityRecord(ctx, groupRecord(t, time.Date(2024, 2, 1, 2, 0, 0, 0, time.UTC), "GO-2024-0003"))
	if !errors.Is(err, ports.ErrVulnIntegrity) {
		t.Fatalf("PutVulnerabilityRecord = %v, want the integrity refusal", err)
	}
	var aside *ports.SetAsideGenerations
	if errors.As(err, &aside) || errors.Is(err, recordseal.ErrGenerationDrift) {
		t.Errorf("an altered generation was excused as drift: %v", err)
	}

	_, found, rerr := store.GetVulnerabilityRecordAt(ctx, coord("example.com/group", "v1.0.0"), "v1", snap("govulndb", "v2024-01-01"), domain.RootingIsolated)
	if found || !errors.Is(rerr, ports.ErrVulnIntegrity) || errors.As(rerr, &aside) {
		t.Fatalf("GetVulnerabilityRecordAt = (found %v, %v), want the integrity refusal", found, rerr)
	}
}

// TestRecordListing_AlteredRowKeepsTheListingAnIntegrityFailure pins that drift
// is excused only when it is all there is: one altered row beside a drifted one
// makes the listing an integrity failure that names both.
func TestRecordListing_AlteredRowKeepsTheListingAnIntegrityFailure(t *testing.T) {
	ctx := t.Context()
	store, bad := driftedRecordStore(t)
	if _, err := store.InternalDB().DB().ExecContext(ctx,
		`UPDATE vulnerability_records SET serialised = CAST(replace(CAST(serialised AS TEXT), 'shared advisory', 'shared advisorY') AS BLOB)
		 WHERE module_path = 'example.com/alpha'`); err != nil {
		t.Fatalf("altering a row: %v", err)
	}

	_, err := store.ListVulnerabilityRecordsByFindingID(ctx, "GO-2024-9001", "")
	var unreadable *ports.UnreadableRows
	if !errors.As(err, &unreadable) || !errors.Is(err, ports.ErrVulnIntegrity) {
		t.Fatalf("error = %v, want *ports.UnreadableRows answering to ErrVulnIntegrity", err)
	}
	if len(unreadable.Rows) != 2 {
		t.Fatalf("unreadable = %v, want the altered row and the drifted %s", unreadable.Rows, bad.Coordinate)
	}
}

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// TestRunRecords_SetAsideOnlyWhereItBoreOnTheAnswer covers the per-run read. A
// run that pinned a readable generation is served it, and a drifted sibling is
// not reported because it changed nothing. A run that pinned the drifted
// generation has no record this build can serve for that module: the module is
// left out and the generation named.
func TestRunRecords_SetAsideOnlyWhereItBoreOnTheAnswer(t *testing.T) {
	ctx := t.Context()
	store, readable, driftSeal := groupWithStoredOddRow(t, driftRecordBlob)
	first := readable[0]

	for _, run := range []struct{ id, pin string }{{"vscan-readable", first.ContentHash}, {"vscan-drifted", driftSeal}} {
		if err := store.PutWalkScanRun(ctx, sealRun(t, domain.WalkScanRun{
			ID:               run.id,
			WalkID:           "walk-1",
			Snapshot:         first.DatabaseSnapshot,
			PerModuleResults: map[coordinate.ModuleCoordinate]string{first.Coordinate: run.pin},
			StartedAt:        first.ScannedAt,
			CompletedAt:      first.ScannedAt,
			PipelineVersion:  "v1",
		})); err != nil {
			t.Fatalf("PutWalkScanRun(%s): %v", run.id, err)
		}
	}

	recs, err := store.ListVulnerabilityRecords(ctx, "vscan-readable")
	if err != nil || len(recs) != 1 || recs[0].ContentHash != first.ContentHash {
		t.Fatalf("ListVulnerabilityRecords(pinned readable) = (%d records, %v), want the pinned record and nothing set aside", len(recs), err)
	}

	recs, err = store.ListVulnerabilityRecords(ctx, "vscan-drifted")
	var aside *ports.SetAsideGenerations
	if !errors.As(err, &aside) || len(aside.Rows) != 1 || aside.Rows[0].ContentHash != driftSeal {
		t.Fatalf("ListVulnerabilityRecords(pinned drifted) error = %v, want the drifted generation %s named", err, driftSeal)
	}
	if len(recs) != 0 {
		t.Errorf("records = %d, want none: the run's own record for the module was set aside, and composing the others would report a record it never produced", len(recs))
	}
}
