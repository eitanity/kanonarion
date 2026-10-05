package sqlite_test

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"testing"
	"time"

	"github.com/eitanity/kanonarion/internal/adapters/recordseal"
	"github.com/eitanity/kanonarion/internal/adapters/sqlitestore"
	fetchdomain "github.com/eitanity/kanonarion/internal/fetch/domain"
	"github.com/eitanity/kanonarion/internal/vuln/adapters/store/sqlite"
	"github.com/eitanity/kanonarion/internal/vuln/domain"
	"github.com/eitanity/kanonarion/internal/vuln/ports"
)

// The record listings had the fault the scan-run listings were fixed for: one
// stored record this build cannot verify took out every other record in the
// answer, so a single drifted row for one module hid every other module an
// advisory touched. These tests pin the replacement contract at the seam every
// record listing goes through: the rows that verify come back, a drifted row is
// set aside and named, and an altered row still fails as an integrity error.

// driftedRecordStore returns a store holding three records for one finding, one
// of which is sealed the way a different canonical shape would have sealed it.
// The drifted one is named so a test can say which row it expects reported.
func driftedRecordStore(t *testing.T) (*sqlite.Store, domain.VulnerabilityRecord) {
	t.Helper()
	ctx := t.Context()
	db, err := sqlitestore.Open(":memory:", sqlite.Migrations(), sqlitestore.IntentCreate)
	if err != nil {
		t.Fatalf("opening in-memory db: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	store := sqlite.New(db)

	snapshot := snap("govulndb", "v2024-01-01")
	good := recordAt(t, "example.com/alpha", "v1.0.0", snapshot, time.Date(2024, 2, 1, 0, 0, 0, 0, time.UTC))
	bad := recordAt(t, "example.com/bravo", "v2.0.0", snapshot, time.Date(2024, 2, 1, 1, 0, 0, 0, time.UTC))
	other := recordAt(t, "example.com/charlie", "v3.0.0", snapshot, time.Date(2024, 2, 1, 2, 0, 0, 0, time.UTC))
	for _, rec := range []domain.VulnerabilityRecord{good, bad, other} {
		if err := store.PutVulnerabilityRecord(ctx, rec); err != nil {
			t.Fatalf("PutVulnerabilityRecord(%s): %v", rec.Coordinate, err)
		}
	}

	blob := driftRecordBlob(t, bad)
	if _, err := db.DB().ExecContext(ctx,
		`UPDATE vulnerability_records SET serialised = ?, content_hash = ?
		 WHERE module_path = ? AND module_version = ?`,
		blob, sealIn(t, blob), bad.Coordinate.Path(), bad.Coordinate.Version()); err != nil {
		t.Fatalf("installing drifted row: %v", err)
	}
	return store, bad
}

// recordAt is a sealed record carrying the shared finding, so the tests differ
// only in coordinate and scan time.
func recordAt(t *testing.T, path, version string, snapshot domain.DatabaseSnapshot, at time.Time) domain.VulnerabilityRecord {
	t.Helper()
	return seal(t, domain.VulnerabilityRecord{
		Ecosystem:        fetchdomain.EcosystemGo,
		Coordinate:       coord(path, version),
		WalkID:           "walk-1",
		OverallStatus:    domain.StatusAffected,
		DatabaseSnapshot: snapshot,
		ScannedAt:        at,
		PipelineVersion:  "v1",
		Findings: []domain.VulnerabilityFinding{
			{ID: "GO-2024-9001", Summary: "shared advisory", AffectedRange: "< v9.0.0"},
		},
	})
}

// driftRecordBlob renders rec the way a DIFFERENT canonical shape would have:
// an extra top-level field this build knows nothing about, sealed over the
// bytes as they stand. The bytes hash to the seal they carry, so nothing has
// been altered — today's struct simply cannot reproduce them.
func driftRecordBlob(t *testing.T, rec domain.VulnerabilityRecord) []byte {
	t.Helper()
	blob, err := domain.VulnerabilityRecordHasher{}.Marshal(rec)
	if err != nil {
		t.Fatalf("marshalling record: %v", err)
	}
	widened := append([]byte(`{"retired_field":"a shape this build never had",`), blob[1:]...)

	stamped := []byte(`"content_hash":"` + rec.ContentHash + `"`)
	if bytes.Count(widened, stamped) != 1 {
		t.Fatalf("fixture has %d occurrences of the top-level seal, want exactly 1", bytes.Count(widened, stamped))
	}
	blanked := bytes.Replace(widened, stamped, []byte(`"content_hash":""`), 1)
	sum := sha256.Sum256(blanked)
	sealed := hex.EncodeToString(sum[:])
	out := bytes.Replace(widened, stamped, []byte(`"content_hash":"`+sealed+`"`), 1)

	excludes := recordseal.Excluding(domain.VulnerabilityRecordHasher{}.SealExcludes()...)
	consistent, err := excludes.SelfConsistent(out, sealed)
	if err != nil || !consistent {
		t.Fatalf("drift fixture is not self-consistent (consistent=%v, err=%v); it would be "+
			"indistinguishable from altered bytes and would prove nothing", consistent, err)
	}
	return out
}

// sealIn reads back the seal a drifted blob carries, so the row's column agrees
// with its bytes the way every stored row does.
func sealIn(t *testing.T, blob []byte) string {
	t.Helper()
	const key = `"content_hash":"`
	i := bytes.LastIndex(blob, []byte(key))
	if i < 0 {
		t.Fatal("drift fixture carries no content_hash")
	}
	rest := blob[i+len(key):]
	j := bytes.IndexByte(rest, '"')
	return string(rest[:j])
}

// TestRecordListings_ReportUnreadableRowsAndKeepTheRest is the regression: the
// records that verify come back and the one that does not is named rather than
// dropped. It is drift, so it is set aside rather than reported as an integrity
// failure: a consuming command serves the rest and states it.
func TestRecordListings_ReportUnreadableRowsAndKeepTheRest(t *testing.T) {
	ctx := t.Context()
	store, bad := driftedRecordStore(t)

	for _, tc := range []struct {
		name     string
		list     func() ([]domain.VulnerabilityRecord, error)
		wantKept int
	}{
		{
			name: "ByFindingID",
			list: func() ([]domain.VulnerabilityRecord, error) {
				return store.ListVulnerabilityRecordsByFindingID(ctx, "GO-2024-9001", "")
			},
			wantKept: 2,
		},
		{
			name: "ForModule",
			list: func() ([]domain.VulnerabilityRecord, error) {
				return store.ListVulnerabilityRecordsForModule(ctx, bad.Coordinate, "v1")
			},
			wantKept: 0,
		},
		{
			name: "ForModuleAllGenerations",
			list: func() ([]domain.VulnerabilityRecord, error) {
				return store.ListVulnerabilityRecordsForModuleAllGenerations(ctx, bad.Coordinate)
			},
			wantKept: 0,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			records, err := tc.list()

			if len(records) != tc.wantKept {
				t.Fatalf("records = %d, want the %d that verify", len(records), tc.wantKept)
			}
			for _, rec := range records {
				if rec.Coordinate == bad.Coordinate {
					t.Fatalf("the unverifiable record for %s was served as a verdict", bad.Coordinate)
				}
			}

			var aside *recordseal.SetAside
			if !errors.As(err, &aside) {
				t.Fatalf("error = %v, want *recordseal.SetAside", err)
			}
			if len(aside.Rows) != 1 {
				t.Fatalf("set aside = %v, want exactly the one drifted row", aside.Rows)
			}
			row := aside.Rows[0]
			// Naming the row is the point: a caller told only that something is
			// wrong cannot go and look at it. The identity is BARE — a machine
			// surface renders it under the key a readable record uses, so a
			// coordinate spliced into a display string would have to be parsed back
			// out.
			if row.ID != bad.Coordinate.String() {
				t.Errorf("unreadable row ID = %q, want the bare coordinate %s", row.ID, bad.Coordinate)
			}
			if row.Kind != "vulnerability record" {
				t.Errorf("row kind = %q, want %q", row.Kind, "vulnerability record")
			}
			// The generation travels beside the identity, because a coordinate
			// alone does not pick one row out of a history.
			if row.Generation.PipelineVersion != bad.PipelineVersion {
				t.Errorf("pipeline version = %q, want %q", row.Generation.PipelineVersion, bad.PipelineVersion)
			}
			if row.Generation.Snapshot.Version != bad.DatabaseSnapshot.Version() {
				t.Errorf("snapshot version = %q, want %q", row.Generation.Snapshot.Version, bad.DatabaseSnapshot.Version())
			}
			if row.Generation.Snapshot.Source != bad.DatabaseSnapshot.Source() {
				t.Errorf("snapshot source = %q, want %q", row.Generation.Snapshot.Source, bad.DatabaseSnapshot.Source())
			}
			// A generation this build no longer seals must not be reported in the
			// words reserved for altered bytes.
			if !errors.Is(row.Reason, recordseal.ErrGenerationDrift) {
				t.Errorf("reason = %v, want it to classify as generation drift", row.Reason)
			}
			// The generation is named by its seal, which is what picks it out of a
			// coordinate's history.
			if row.ContentHash == "" || row.ContentHash != sealInRow(t, store, bad) {
				t.Errorf("set-aside content hash = %q, want the drifted row's own seal", row.ContentHash)
			}
			// Drift is excused: a consuming command must not fail closed on it.
			if errors.Is(err, ports.ErrVulnIntegrity) {
				t.Error("errors.Is(err, ErrVulnIntegrity) = true for a drifted row; consumers would refuse to answer")
			}
		})
	}
}

// TestRecordListings_CleanStoreIsUnchanged is the negative direction: with no
// faults the listings answer exactly as they did, error and all.
func TestRecordListings_CleanStoreIsUnchanged(t *testing.T) {
	ctx := t.Context()
	store := newTestStore(t)

	snapshot := snap("govulndb", "v2024-01-01")
	a := recordAt(t, "example.com/alpha", "v1.0.0", snapshot, time.Date(2024, 2, 1, 0, 0, 0, 0, time.UTC))
	b := recordAt(t, "example.com/bravo", "v2.0.0", snapshot, time.Date(2024, 2, 1, 1, 0, 0, 0, time.UTC))
	for _, rec := range []domain.VulnerabilityRecord{a, b} {
		if err := store.PutVulnerabilityRecord(ctx, rec); err != nil {
			t.Fatalf("PutVulnerabilityRecord(%s): %v", rec.Coordinate, err)
		}
	}

	byID, err := store.ListVulnerabilityRecordsByFindingID(ctx, "GO-2024-9001", "")
	if err != nil {
		t.Fatalf("ListVulnerabilityRecordsByFindingID on a clean store = %v, want nil", err)
	}
	if len(byID) != 2 {
		t.Errorf("records = %d, want both", len(byID))
	}

	forModule, err := store.ListVulnerabilityRecordsForModule(ctx, a.Coordinate, "v1")
	if err != nil {
		t.Fatalf("ListVulnerabilityRecordsForModule on a clean store = %v, want nil", err)
	}
	if len(forModule) != 1 {
		t.Errorf("records = %d, want the one stored", len(forModule))
	}
}

// TestComposingReads_AllDriftedIsNoServableRecord pins what a composing read
// answers when the only generation it holds is drifted: no record this build can
// serve, with the set-aside report saying why — never an empty success, and
// never an integrity failure.
func TestComposingReads_AllDriftedIsNoServableRecord(t *testing.T) {
	ctx := t.Context()
	store, bad := driftedRecordStore(t)

	type answer struct {
		found bool
		err   error
	}
	for name, read := range map[string]func() answer{
		"GetLatest": func() answer {
			_, found, err := store.GetLatestVulnerabilityRecord(ctx, bad.Coordinate, "v1")
			return answer{found, err}
		},
		"Get": func() answer {
			_, found, err := store.GetVulnerabilityRecord(ctx, bad.Coordinate, "v1", snap("govulndb", "v2024-01-01"))
			return answer{found, err}
		},
		"GetAt": func() answer {
			_, found, err := store.GetVulnerabilityRecordAt(ctx, bad.Coordinate, "v1", snap("govulndb", "v2024-01-01"), domain.RootingUnrecorded)
			return answer{found, err}
		},
	} {
		t.Run(name, func(t *testing.T) {
			got := read()
			found, err := got.found, got.err
			var aside *recordseal.SetAside
			if found || !errors.As(err, &aside) {
				t.Fatalf("read = (found %v, %v), want no servable record with the generation set aside", found, err)
			}
			if len(aside.Rows) != 1 || aside.Rows[0].ID != bad.Coordinate.String() {
				t.Errorf("set aside = %v, want the one drifted generation of %s", aside.Rows, bad.Coordinate)
			}
			if errors.Is(err, ports.ErrVulnIntegrity) {
				t.Errorf("an all-drifted group was reported as an integrity failure: %v", err)
			}
		})
	}
}

// sealInRow reads the content hash column of rec's stored row.
func sealInRow(t *testing.T, store *sqlite.Store, rec domain.VulnerabilityRecord) string {
	t.Helper()
	var hash string
	if err := store.InternalDB().DB().QueryRowContext(t.Context(),
		`SELECT content_hash FROM vulnerability_records WHERE module_path = ? AND module_version = ?`,
		rec.Coordinate.Path(), rec.Coordinate.Version()).Scan(&hash); err != nil {
		t.Fatalf("reading the stored seal: %v", err)
	}
	return hash
}

// TestRecordListings_UnparseableRowIsStillReported covers the row that will not
// even say which coordinate it is. It is reported anyway: "there is a row here
// I cannot read" is an answer, and dropping it because it will not introduce
// itself is the silent omission this contract exists to prevent.
func TestRecordListings_UnparseableRowIsStillReported(t *testing.T) {
	ctx := t.Context()
	db, err := sqlitestore.Open(":memory:", sqlite.Migrations(), sqlitestore.IntentCreate)
	if err != nil {
		t.Fatalf("opening in-memory db: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	store := sqlite.New(db)

	snapshot := snap("govulndb", "v2024-01-01")
	good := recordAt(t, "example.com/alpha", "v1.0.0", snapshot, time.Date(2024, 2, 1, 0, 0, 0, 0, time.UTC))
	bad := recordAt(t, "example.com/bravo", "v2.0.0", snapshot, time.Date(2024, 2, 1, 1, 0, 0, 0, time.UTC))
	for _, rec := range []domain.VulnerabilityRecord{good, bad} {
		if err := store.PutVulnerabilityRecord(ctx, rec); err != nil {
			t.Fatalf("PutVulnerabilityRecord(%s): %v", rec.Coordinate, err)
		}
	}
	if _, err := db.DB().ExecContext(ctx,
		`UPDATE vulnerability_records SET serialised = ? WHERE module_path = ?`,
		[]byte("not json at all"), bad.Coordinate.Path()); err != nil {
		t.Fatalf("installing unparseable row: %v", err)
	}

	records, err := store.ListVulnerabilityRecordsByFindingID(ctx, "GO-2024-9001", "")
	if len(records) != 1 || records[0].Coordinate != good.Coordinate {
		t.Fatalf("records = %d, want only the verifiable one", len(records))
	}
	var unreadable *ports.UnreadableRows
	if !errors.As(err, &unreadable) {
		t.Fatalf("error = %v, want *ports.UnreadableRows", err)
	}
	if len(unreadable.Rows) != 1 || unreadable.Rows[0].ID != "" {
		t.Fatalf("unreadable = %v, want one row with no recoverable identity", unreadable.Rows)
	}
	// Bytes that cannot be examined are not claimed to be merely old.
	if errors.Is(unreadable.Rows[0].Reason, recordseal.ErrGenerationDrift) {
		t.Error("an unparseable row was reported as generation drift; absence of evidence is not evidence")
	}
}

// A row whose JSON parses but whose coordinate does not is still reported, and
// still reported without an identity. The bytes are under suspicion, so nothing
// beyond the coordinate is read out of them and a damaged one is not guessed at.
func TestRecordListings_RowWithNoReadableCoordinateIsReportedUnnamed(t *testing.T) {
	ctx := t.Context()

	for name, blob := range map[string]string{
		"no coordinate at all": `{"pipeline_version":"v1","database_snapshot":{"version":"v2024-01-01"}}`,
		"an empty coordinate":  `{"coordinate":{"Path":"","Version":""},"pipeline_version":"v1"}`,
	} {
		t.Run(name, func(t *testing.T) {
			db, err := sqlitestore.Open(":memory:", sqlite.Migrations(), sqlitestore.IntentCreate)
			if err != nil {
				t.Fatalf("opening in-memory db: %v", err)
			}
			t.Cleanup(func() { _ = db.Close() })
			store := sqlite.New(db)

			snapshot := snap("govulndb", "v2024-01-01")
			bad := recordAt(t, "example.com/bravo", "v2.0.0", snapshot, time.Date(2024, 2, 1, 0, 0, 0, 0, time.UTC))
			if err := store.PutVulnerabilityRecord(ctx, bad); err != nil {
				t.Fatalf("PutVulnerabilityRecord: %v", err)
			}
			if _, err := db.DB().ExecContext(ctx,
				`UPDATE vulnerability_records SET serialised = ? WHERE module_path = ?`,
				[]byte(blob), bad.Coordinate.Path()); err != nil {
				t.Fatalf("installing the damaged row: %v", err)
			}

			_, err = store.ListVulnerabilityRecordsByFindingID(ctx, "GO-2024-9001", "")
			var unreadable *ports.UnreadableRows
			if !errors.As(err, &unreadable) {
				t.Fatalf("error = %v, want *ports.UnreadableRows", err)
			}
			if len(unreadable.Rows) != 1 || unreadable.Rows[0].ID != "" {
				t.Fatalf("unreadable = %v, want one row with no recoverable identity", unreadable.Rows)
			}
			// What the head DID yield is still reported. Losing the generation
			// because the coordinate was unreadable would throw away a fact that
			// was successfully parsed.
			if unreadable.Rows[0].Generation.PipelineVersion != "v1" {
				t.Errorf("pipeline version = %q, want the one the head carried",
					unreadable.Rows[0].Generation.PipelineVersion)
			}
		})
	}
}
