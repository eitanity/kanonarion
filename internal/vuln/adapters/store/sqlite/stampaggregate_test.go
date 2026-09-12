package sqlite_test

import (
	"testing"
	"time"

	fetchdomain "github.com/eitanity/kanonarion/internal/fetch/domain"
	"github.com/eitanity/kanonarion/internal/vuln/adapters/store/sqlite"
	"github.com/eitanity/kanonarion/internal/vuln/domain"
)

const (
	// The two spellings of one second the ledger holds: a whole second on rows
	// written before the stamp was widened, a fixed-width fraction after. As TEXT
	// the fractional one sorts FIRST, because '.' is 0x2E and 'Z' is 0x5A — so a
	// bare MAX returns the earlier instant and a bare MIN the later one.
	wholeSecondStamp = "2026-05-06T07:08:53Z"
	fractionalStamp  = "2026-05-06T07:08:53.900000000Z"
)

func stampRecord(at time.Time, findingID string) domain.VulnerabilityRecord {
	return domain.VulnerabilityRecord{
		Ecosystem:       fetchdomain.EcosystemGo,
		WalkID:          "walk-1",
		OverallStatus:   domain.StatusAffected,
		ScannedAt:       at,
		PipelineVersion: "v1",
		Findings: []domain.VulnerabilityFinding{
			{ID: findingID, Summary: "test vuln", AffectedRange: "< v1.1.0"},
		},
	}
}

// The census reports a generation's latest scan, and it has to be the latest
// INSTANT rather than the last string.
//
// The straddle needs no surgery: the encoding follows the value, so a scan whose
// time lands on a whole second writes the short form and one carrying a fraction
// writes the long one. Both are what this build produces.
func TestGenerationCensus_LatestScanIsTheLatestInstant(t *testing.T) {
	ctx := t.Context()
	store := newTestStore(t)

	c := coord("github.com/foo/bar", "v1.0.0")
	snapshot := snap("govulndb", "v2024-01-01")
	whole := time.Date(2026, 5, 6, 7, 8, 53, 0, time.UTC)
	fractional := whole.Add(900 * time.Millisecond)

	for i, at := range []time.Time{whole, fractional} {
		rec := stampRecord(at, "GO-2024-000"+string(rune('1'+i)))
		rec.Coordinate, rec.DatabaseSnapshot = c, snapshot
		if err := store.PutVulnerabilityRecord(ctx, seal(t, rec)); err != nil {
			t.Fatalf("PutVulnerabilityRecord %d: %v", i, err)
		}
	}

	// The fixture is the subject only if the column really holds both spellings
	// and they really invert as text.
	assertStampsStored(t, store, "scanned_at", wholeSecondStamp, fractionalStamp)
	if fractionalStamp >= wholeSecondStamp {
		t.Fatalf("the fixture does not invert: %q does not sort before %q", fractionalStamp, wholeSecondStamp)
	}

	gens, err := store.ListVulnerabilityRecordGenerationsForModule(ctx, c)
	if err != nil {
		t.Fatalf("ListVulnerabilityRecordGenerationsForModule: %v", err)
	}
	if len(gens) != 1 {
		t.Fatalf("census reports %d generations, want 1", len(gens))
	}
	if got := gens[0].LastScannedAt; !got.Equal(fractional) {
		t.Errorf("generation reports last scanned %v, want %v: the aggregate returned the earlier "+
			"of two spellings of one second", got, fractional)
	}
	// Control: an aggregate fix moves no count.
	if gens[0].Records != 2 {
		t.Errorf("census counts %d records, want 2", gens[0].Records)
	}
}

// The first-seen anchor is the EARLIEST instant, and an append must not be able
// to move it forward. A bare MIN over the same mixed column returns the LATER of
// two spellings of one second and does exactly that.
//
// The two spellings are planted, because the writer inherits the anchor it reads
// and so cannot produce the mix on its own — which is what makes a planted
// fixture the only way to exercise this aggregate at all.
func TestFirstScannedAnchor_IsTheEarliestInstant(t *testing.T) {
	ctx := t.Context()
	store := newTestStore(t)

	c := coord("github.com/foo/bar", "v1.0.0")
	snapshot := snap("govulndb", "v2024-01-01")
	whole := time.Date(2026, 5, 6, 7, 8, 53, 0, time.UTC)

	for i, at := range []time.Time{whole, whole.Add(900 * time.Millisecond)} {
		rec := stampRecord(at, "GO-2024-000"+string(rune('1'+i)))
		rec.Coordinate, rec.DatabaseSnapshot = c, snapshot
		rec.FirstScannedAt = at
		if err := store.PutVulnerabilityRecord(ctx, seal(t, rec)); err != nil {
			t.Fatalf("PutVulnerabilityRecord %d: %v", i, err)
		}
	}
	// The second write inherited the first's anchor. Restate it as the fraction so
	// the column holds one anchor in each spelling, which is the aggregate's
	// subject.
	if _, err := store.InternalDB().DB().ExecContext(ctx,
		`UPDATE vulnerability_records SET first_scanned_at = ? WHERE scanned_at = ?`,
		fractionalStamp, fractionalStamp); err != nil {
		t.Fatalf("planting the fractional anchor: %v", err)
	}
	assertStampsStored(t, store, "first_scanned_at", wholeSecondStamp, fractionalStamp)

	// A third scan inherits the anchor the ledger already holds, and it is the
	// earliest one.
	third := stampRecord(whole.Add(2*time.Second), "GO-2024-0003")
	third.Coordinate, third.DatabaseSnapshot = c, snapshot
	if err := store.PutVulnerabilityRecord(ctx, seal(t, third)); err != nil {
		t.Fatalf("PutVulnerabilityRecord (third): %v", err)
	}

	var stored string
	if err := store.InternalDB().DB().QueryRowContext(ctx,
		`SELECT first_scanned_at FROM vulnerability_records WHERE scanned_at = ?`,
		"2026-05-06T07:08:55Z").Scan(&stored); err != nil {
		t.Fatalf("reading the third record's anchor: %v", err)
	}
	got, perr := time.Parse(time.RFC3339, stored)
	if perr != nil {
		t.Fatalf("parsing the stored anchor %q: %v", stored, perr)
	}
	if !got.Equal(whole) {
		t.Errorf("the inherited anchor is %v, want %v: an append moved the first-seen time forward",
			got, whole)
	}
}

// assertStampsStored fails unless column holds exactly the spellings named, so a
// fixture that stopped constructing the straddle is reported rather than passing
// on a subject that is no longer there.
func assertStampsStored(t *testing.T, store *sqlite.Store, column string, want ...string) {
	t.Helper()
	rows, err := store.InternalDB().DB().QueryContext(t.Context(),
		`SELECT DISTINCT `+column+` FROM vulnerability_records ORDER BY 1`) //nolint:gosec // column is a literal in this file
	if err != nil {
		t.Fatalf("reading %s: %v", column, err)
	}
	defer func() { _ = rows.Close() }()
	var got []string
	for rows.Next() {
		var v string
		if serr := rows.Scan(&v); serr != nil {
			t.Fatalf("scanning %s: %v", column, serr)
		}
		got = append(got, v)
	}
	if rerr := rows.Err(); rerr != nil {
		t.Fatalf("iterating %s: %v", column, rerr)
	}
	if len(got) != len(want) {
		t.Fatalf("%s holds %v, want the two spellings %v: the fixture is not the subject it claims",
			column, got, want)
	}
	for _, w := range want {
		found := false
		for _, g := range got {
			if g == w {
				found = true
			}
		}
		if !found {
			t.Fatalf("%s holds %v, which does not include %q: the fixture is not the subject it claims",
				column, got, w)
		}
	}
}
