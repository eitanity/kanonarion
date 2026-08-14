package cli

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/eitanity/kanonarion/internal/coordinate"
	"github.com/eitanity/kanonarion/internal/coordinate/coordinatetest"
	staledomain "github.com/eitanity/kanonarion/internal/staleness/domain"
	staleports "github.com/eitanity/kanonarion/internal/staleness/ports"
)

// The scenario's module set: three pins, each behind its published latest. The
// versions are the shape the live finding had — a set every row of which the
// offline audit reported as "current" without asking anything.
var offlineStalenessPins = []coordinate.ModuleCoordinate{
	coordinatetest.MustNew("golang.org/x/net", "v0.33.0"),
	coordinatetest.MustNew("example.com/mod", "v1.2.0"),
	coordinatetest.MustNew("example.com/other", "v0.4.0"),
}

// offlineStalenessRows drives the audit row's staleness column exactly as
// buildAuditResult does — the same helper, over the same lookup wiring runAudit
// builds for the mode — and renders the table, the coverage line and the JSON
// from the rows it produced. The other columns are filled with a clean, measured
// answer so that a failure here can only be the staleness column.
func offlineStalenessRows(t *testing.T, lookup stalenessLookup) []auditModuleResult {
	t.Helper()
	var stderr strings.Builder
	rows := make([]auditModuleResult, 0, len(offlineStalenessPins))
	for _, coord := range offlineStalenessPins {
		res := auditModuleResult{
			Coordinate:      coord.String(),
			Verification:    "VerifiedBySumDBOnly",
			License:         "MIT",
			LicenseStatus:   "Detected",
			LicenseResolved: true,
			VulnStatus:      "Clean",
		}
		applyAuditStaleness(context.Background(), &res, coord, lookup, &stderr)
		rows = append(rows, res)
	}
	return rows
}

// renderAudit renders the two surfaces a reader consumes: the table and the
// stderr coverage line.
func renderAudit(t *testing.T, rows []auditModuleResult) (table, coverage string) {
	t.Helper()
	var tbl, cov strings.Builder
	if err := printAuditTable(&tbl, rows); err != nil {
		t.Fatalf("printAuditTable: %v", err)
	}
	if err := writeStalenessCoverage(&cov, auditStalenessCoverageOf(rows)); err != nil {
		t.Fatalf("writeStalenessCoverage: %v", err)
	}
	return tbl.String(), cov.String()
}

// auditJSONRows marshals the rows the way `audit --json` does and decodes them
// back, so the assertions are about the emitted keys rather than the Go struct.
func auditJSONRows(t *testing.T, rows []auditModuleResult) []map[string]any {
	t.Helper()
	data, err := json.Marshal(rows)
	if err != nil {
		t.Fatalf("marshalling rows: %v", err)
	}
	var decoded []map[string]any
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("unmarshalling rows: %v", err)
	}
	return decoded
}

// offlineLedger opens a real staleness ledger over a fresh store, which is what
// the offline lookup reads: the TTL arithmetic and the "no row for this path"
// answer both come from the store rather than from a fake that could agree with
// the code by construction.
func offlineLedger(t *testing.T) staleports.Ledger {
	t.Helper()
	ledger, cleanup, err := openStalenessLedger(t.TempDir())
	if err != nil {
		t.Fatalf("opening staleness ledger: %v", err)
	}
	t.Cleanup(func() {
		if cerr := cleanup(); cerr != nil {
			t.Errorf("closing staleness ledger: %v", cerr)
		}
	})
	return ledger
}

// offlineMode puts the process in --from-modcache mode for one test, as
// resolveModcacheMode does for a real invocation.
func offlineMode(t *testing.T) {
	t.Helper()
	prior := modcacheMode
	modcacheMode = true
	t.Cleanup(func() { modcacheMode = prior })
}

// TestAuditStaleness_OfflineRunWithNoLedgerEntriesStatesEveryRowUnmeasured is
// the scenario this change exists for. An offline audit consults no proxy; with
// nothing recorded inside the TTL it has measured nothing, and every row said
// "current" — the strongest claim the column can make — about a question it
// never asked. The failing sequence is reproduced here in full: offline wiring,
// an empty ledger, and the three surfaces a reader sees.
func TestAuditStaleness_OfflineRunWithNoLedgerEntriesStatesEveryRowUnmeasured(t *testing.T) {
	offlineMode(t)
	rows := offlineStalenessRows(t, newOfflineStalenessLookup(offlineLedger(t), time.Hour))

	table, coverage := renderAudit(t, rows)
	if strings.Contains(table, "current") {
		t.Errorf("an offline run with nothing measured claimed a pin is current:\n%s", table)
	}
	if got := strings.Count(table, "unmeasured (offline)"); got != len(offlineStalenessPins) {
		t.Errorf("the table states unmeasured on %d of %d rows:\n%s", got, len(offlineStalenessPins), table)
	}

	// The count is the second half: a column nobody measured is a fact about the
	// run, and the reader must not have to total the rows to learn it.
	for _, want := range []string{
		"staleness coverage over 3 module(s)",
		"measured                               0",
		"unmeasured (offline)                   3",
	} {
		if !strings.Contains(coverage, want) {
			t.Errorf("the coverage line does not say %q:\n%s", want, coverage)
		}
	}

	for _, row := range auditJSONRows(t, rows) {
		if got, present := row["is_latest"]; !present || got != nil {
			t.Errorf("%s: is_latest = %v, want null on an unmeasured row", row["coordinate"], got)
		}
		if got := row["staleness_source"]; got != stalenessSourceUnmeasured {
			t.Errorf("%s: staleness_source = %v, want %q", row["coordinate"], got, stalenessSourceUnmeasured)
		}
		if got := row["staleness_unmeasured"]; got != stalenessOfflineNoEntry {
			t.Errorf("%s: staleness_unmeasured = %v, want %q", row["coordinate"], got, stalenessOfflineNoEntry)
		}
		if _, present := row["latest_version"]; present {
			t.Errorf("%s: an unmeasured row named a latest version", row["coordinate"])
		}
	}
}

// TestAuditStaleness_OfflineRunServesAnInTTLLedgerEntryWithItsAge is the other
// half of the decision: a recorded measurement IS a measurement, so an offline
// run may serve one inside the TTL — and must say how old it is, because a
// served answer that does not date itself is indistinguishable from a live one.
// The modules with no entry stay unmeasured in the same table.
func TestAuditStaleness_OfflineRunServesAnInTTLLedgerEntryWithItsAge(t *testing.T) {
	offlineMode(t)
	ledger := offlineLedger(t)

	served := offlineStalenessPins[0]
	lookedUpAt := time.Now().Add(-20 * time.Minute)
	if err := ledger.PutStaleness(context.Background(), staledomain.Record{
		ModulePath:        served.Path(),
		LatestVersion:     "v0.57.0",
		LatestPublishedAt: time.Now().Add(-72 * time.Hour),
		LookedUpAt:        lookedUpAt,
		NewerMajor:        staledomain.NewerMajor{Probed: true, FromMajor: staledomain.ProbeStartMajor(served.Path(), served.Version())},
	}); err != nil {
		t.Fatalf("seeding the staleness ledger: %v", err)
	}

	rows := offlineStalenessRows(t, newOfflineStalenessLookup(ledger, time.Hour))
	table, coverage := renderAudit(t, rows)

	for _, want := range []string{"latest: v0.57.0", "3 days ago", "[from ledger, 20m0s old]"} {
		if !strings.Contains(table, want) {
			t.Errorf("the served row does not say %q:\n%s", want, table)
		}
	}
	if got := strings.Count(table, "unmeasured (offline)"); got != len(offlineStalenessPins)-1 {
		t.Errorf("the rows with no ledger entry are stated on %d rows, want %d:\n%s", got, len(offlineStalenessPins)-1, table)
	}
	for _, want := range []string{
		"measured                               1",
		"measured (served from ledger)        1",
		"unmeasured (offline)                   2",
	} {
		if !strings.Contains(coverage, want) {
			t.Errorf("the coverage line does not say %q:\n%s", want, coverage)
		}
	}

	decoded := auditJSONRows(t, rows)[0]
	if got := decoded["is_latest"]; got != false {
		t.Errorf("is_latest = %v, want false: the served answer names a newer version", got)
	}
	if got := decoded["staleness_source"]; got != stalenessSourceLedger {
		t.Errorf("staleness_source = %v, want %q", got, stalenessSourceLedger)
	}
	if _, present := decoded["staleness_unmeasured"]; present {
		t.Error("a served row carries an unmeasured reason")
	}
	at, present := decoded["staleness_looked_up_at"].(string)
	if !present {
		t.Fatalf("staleness_looked_up_at is absent from a served row: %v", decoded)
	}
	if got, err := time.Parse(time.RFC3339Nano, at); err != nil {
		t.Errorf("staleness_looked_up_at %q does not parse: %v", at, err)
	} else if got.Sub(lookedUpAt).Abs() > time.Second {
		t.Errorf("staleness_looked_up_at = %s, want the ledger's %s: a served answer must carry the ORIGINAL lookup time", got, lookedUpAt)
	}
}

// stubEveryPathLatest answers @latest for the module paths it knows and reports
// every other path — the major-suffixed probe candidates — absent, which is the
// sentinel that ends the probe after one request per module.
type stubEveryPathLatest struct {
	versions map[string]string
	calls    int
}

func (s *stubEveryPathLatest) LatestInfo(_ context.Context, path string) (staleports.LatestInfo, error) {
	s.calls++
	v, ok := s.versions[path]
	if !ok {
		return staleports.LatestInfo{}, staleports.ErrPathAbsent
	}
	return staleports.LatestInfo{Version: v, Time: time.Now().Add(-48 * time.Hour)}, nil
}

// TestAuditStaleness_OnlineControlMeasuresEveryRow is the zero-pairing control.
// The same rows, the same renderer, the network wiring: every row is measured,
// the column carries versions, and the word "unmeasured" appears nowhere.
// Without it the offline assertions above would pass just as well against a
// column that had stopped answering at all.
func TestAuditStaleness_OnlineControlMeasuresEveryRow(t *testing.T) {
	proxy := &stubEveryPathLatest{versions: map[string]string{
		"golang.org/x/net":  "v0.57.0",
		"example.com/mod":   "v1.2.0",
		"example.com/other": "v0.9.0",
	}}
	resolver := newAuditStalenessResolver(proxy, nil, time.Hour)
	rows := offlineStalenessRows(t, resolver)

	if proxy.calls == 0 {
		t.Fatal("the online control asked the proxy nothing; it is not a control")
	}
	table, coverage := renderAudit(t, rows)
	for _, want := range []string{"latest: v0.57.0", "latest: v0.9.0", "current"} {
		if !strings.Contains(table, want) {
			t.Errorf("the online table does not say %q:\n%s", want, table)
		}
	}
	if strings.Contains(table, "unmeasured") {
		t.Errorf("a measured row reported itself unmeasured:\n%s", table)
	}
	if strings.Contains(table, "from ledger") {
		t.Errorf("a live answer claimed to come from the ledger:\n%s", table)
	}
	for _, want := range []string{
		"measured                               3",
		"measured (asked upstream)            3",
	} {
		if !strings.Contains(coverage, want) {
			t.Errorf("the coverage line does not say %q:\n%s", want, coverage)
		}
	}
	for _, row := range auditJSONRows(t, rows) {
		if row["is_latest"] == nil {
			t.Errorf("%s: is_latest is null on a measured row", row["coordinate"])
		}
		if got := row["staleness_source"]; got != stalenessSourceProxy {
			t.Errorf("%s: staleness_source = %v, want %q", row["coordinate"], got, stalenessSourceProxy)
		}
	}
}

// TestAuditStaleness_OnlineRunReportsAFailedProbeAsUnmeasured covers the third
// state on the network path: one module's lookup fails mid-sweep. That row is
// unmeasured too — it must not fall back onto the clean answer — while the rows
// either side of it stay measured.
func TestAuditStaleness_OnlineRunReportsAFailedProbeAsUnmeasured(t *testing.T) {
	// example.com/mod is absent from the map, so its @latest lookup fails.
	proxy := &stubEveryPathLatest{versions: map[string]string{
		"golang.org/x/net":  "v0.57.0",
		"example.com/other": "v0.9.0",
	}}
	rows := offlineStalenessRows(t, newAuditStalenessResolver(proxy, nil, time.Hour))

	table, coverage := renderAudit(t, rows)
	if !strings.Contains(table, "unmeasured (lookup failed)") {
		t.Errorf("the failed row does not state its own failure:\n%s", table)
	}
	if got := strings.Count(table, "unmeasured"); got != 1 {
		t.Errorf("%d rows reported unmeasured, want exactly the one whose lookup failed:\n%s", got, table)
	}
	for _, want := range []string{
		"measured                               2",
		"unmeasured (lookup failed)             1",
	} {
		if !strings.Contains(coverage, want) {
			t.Errorf("the coverage line does not say %q:\n%s", want, coverage)
		}
	}
}

// TestAuditStaleness_OfflineRunWillNotServeALapsedLedgerEntry is the boundary
// the mode turns on. A ledger row OUTSIDE the TTL is not a measurement of now,
// and an offline run cannot refresh it, so it is not served — the row is
// unmeasured, exactly as if the ledger had never held it. (A store carrying
// months of expired lookups is the ordinary case; serving them would restore
// the claim this change removes, dated to a stale answer.)
func TestAuditStaleness_OfflineRunWillNotServeALapsedLedgerEntry(t *testing.T) {
	offlineMode(t)
	ledger := offlineLedger(t)

	served := offlineStalenessPins[0]
	if err := ledger.PutStaleness(context.Background(), staledomain.Record{
		ModulePath:    served.Path(),
		LatestVersion: "v0.57.0",
		LookedUpAt:    time.Now().Add(-90 * time.Minute),
	}); err != nil {
		t.Fatalf("seeding the staleness ledger: %v", err)
	}

	rows := offlineStalenessRows(t, newOfflineStalenessLookup(ledger, time.Hour))
	table, coverage := renderAudit(t, rows)
	if strings.Contains(table, "v0.57.0") {
		t.Errorf("a lookup older than the TTL was served on an offline run:\n%s", table)
	}
	if got := strings.Count(table, "unmeasured (offline)"); got != len(offlineStalenessPins) {
		t.Errorf("the table states unmeasured on %d of %d rows:\n%s", got, len(offlineStalenessPins), table)
	}
	if !strings.Contains(coverage, "measured                               0") {
		t.Errorf("the coverage line counts a lapsed row as measured:\n%s", coverage)
	}
}

// TestAuditStaleness_LookupWithNoLedgerIsUnmeasured: an offline run against a
// command that opened no ledger has nothing to serve and says so, rather than
// answering from the absence.
func TestAuditStaleness_LookupWithNoLedgerIsUnmeasured(t *testing.T) {
	offlineMode(t)
	rows := offlineStalenessRows(t, newOfflineStalenessLookup(nil, time.Hour))
	for _, r := range rows {
		if r.IsLatest != nil || r.StalenessUnmeasured != stalenessOfflineNoEntry {
			t.Errorf("%s: is_latest %v / reason %q, want an unmeasured offline row", r.Coordinate, r.IsLatest, r.StalenessUnmeasured)
		}
	}
}

// TestAuditStalenessColumn_RendersEveryUnmeasuredReason pins the phrasing each
// reason reads as, including the toolchain row: the standard library has no
// proxy "latest", and the cell must not resolve that into "current".
func TestAuditStalenessColumn_RendersEveryUnmeasuredReason(t *testing.T) {
	cases := map[string]string{
		stalenessOfflineNoEntry:  "unmeasured (offline)",
		stalenessLookupFailed:    "unmeasured (lookup failed)",
		stalenessToolchainPinned: "unmeasured (toolchain-pinned)",
		"":                       "unmeasured",
		"some_new_reason":        "unmeasured (some_new_reason)",
	}
	for reason, want := range cases {
		var row auditModuleResult
		row.markStalenessUnmeasured(reason)
		if got := auditStalenessCell(row); got != want {
			t.Errorf("reason %q renders as %q, want %q", reason, got, want)
		}
	}
}

// TestAuditStalenessColumn_StatesASubMinuteLedgerAgeInWords: a lookup made
// moments ago is not stated as "0s old", which reads as a precision a
// minute-resolution rendering does not have.
func TestAuditStalenessColumn_StatesASubMinuteLedgerAgeInWords(t *testing.T) {
	measured := true
	row := auditModuleResult{IsLatest: &measured, stalenessLedgerAge: 12 * time.Second}
	if got, want := auditStalenessCell(row), "current [from ledger, under a minute old]"; got != want {
		t.Errorf("column = %q, want %q", got, want)
	}
}

// TestAuditStalenessColumn_StatesALedgerAgeInHours covers the other side of the
// age rendering: a TTL measured in hours produces ages a minute resolution would
// only clutter.
func TestAuditStalenessColumn_StatesALedgerAgeInHours(t *testing.T) {
	measured := true
	row := auditModuleResult{IsLatest: &measured, stalenessLedgerAge: 5*time.Hour + 4*time.Minute}
	if got, want := auditStalenessCell(row), "current [from ledger, 5h0m0s old]"; got != want {
		t.Errorf("column = %q, want %q", got, want)
	}
}

// TestWriteStalenessCoverage_SaysNothingAboutAnEmptyRun: no rows, no claim.
func TestWriteStalenessCoverage_SaysNothingAboutAnEmptyRun(t *testing.T) {
	var out strings.Builder
	if err := writeStalenessCoverage(&out, auditStalenessCoverageOf(nil)); err != nil {
		t.Fatalf("writeStalenessCoverage: %v", err)
	}
	if out.String() != "" {
		t.Errorf("an empty run reported coverage: %q", out.String())
	}
}

// failingLedger is the fault seam: a ledger whose read fails.
type failingLedger struct{}

func (failingLedger) GetStaleness(context.Context, string) (staledomain.Record, bool, error) {
	return staledomain.Record{}, false, errors.New("database is locked")
}
func (failingLedger) PutStaleness(context.Context, staledomain.Record) error { return nil }

// TestAuditStaleness_OfflineLedgerReadFailureIsReportedNotSwallowed: a ledger
// that cannot be read is a different condition from one that holds nothing, and
// it is the one a reader must hear about — the offline "nothing recorded" answer
// is silent by design, so a broken store must not borrow that silence.
func TestAuditStaleness_OfflineLedgerReadFailureIsReportedNotSwallowed(t *testing.T) {
	offlineMode(t)
	var stderr strings.Builder
	coord := offlineStalenessPins[0]
	var row auditModuleResult
	applyAuditStaleness(context.Background(), &row, coord, newOfflineStalenessLookup(failingLedger{}, time.Hour), &stderr)

	if row.IsLatest != nil {
		t.Errorf("is_latest = %v, want null when the ledger could not be read", *row.IsLatest)
	}
	if row.StalenessUnmeasured != stalenessLookupFailed {
		t.Errorf("staleness_unmeasured = %q, want %q", row.StalenessUnmeasured, stalenessLookupFailed)
	}
	if !strings.Contains(stderr.String(), "database is locked") {
		t.Errorf("the ledger failure was swallowed: %q", stderr.String())
	}
}
