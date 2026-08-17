package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"strings"
	"testing"
	"time"

	staledomain "github.com/eitanity/kanonarion/internal/staleness/domain"
	staleports "github.com/eitanity/kanonarion/internal/staleness/ports"
)

// The module the offline `latest` cases are about, and the two ledger ages that
// decide the answer: one inside the TTL, one outside it.
const offlineLatestModule = "example.com/offline"

// seedOfflineLatestRow files one lookup for offlineLatestModule, recorded age
// ago, and returns the ledger.
func seedOfflineLatestRow(t *testing.T, age time.Duration) staleports.Ledger {
	t.Helper()
	ledger := offlineLedger(t)
	row := staledomain.Record{
		ModulePath:        offlineLatestModule,
		LatestVersion:     "v1.4.0",
		LatestPublishedAt: cliNow().Add(-72 * time.Hour),
		NewerMajor:        staledomain.NewerMajor{Probed: true, FromMajor: 2},
		LookedUpAt:        cliNow().Add(-age),
	}
	if err := ledger.PutStaleness(context.Background(), row); err != nil {
		t.Fatalf("filing staleness row: %v", err)
	}
	return ledger
}

// TestLatestModules_OfflineServesFreshLedgerRow is the case this change exists
// for. An environment that declares no module fetching refused before it read
// anything, so an answer sitting in the store inside its TTL was never reached
// and the operator was told the data was absent when it was present and current.
func TestLatestModules_OfflineServesFreshLedgerRow(t *testing.T) {
	restore := SetClockForTest(time.Date(2026, 2, 28, 12, 0, 0, 0, time.UTC))
	t.Cleanup(restore)
	prev := jsonOut
	jsonOut = true
	t.Cleanup(func() { jsonOut = prev })

	ledger := seedOfflineLatestRow(t, 10*time.Minute)
	lookup := newOfflineStalenessLookup(ledger, time.Hour)

	var stdout bytes.Buffer
	if err := runLatestModules(context.Background(),
		[]string{offlineLatestModule}, lookup, &stdout, io.Discard); err != nil {
		t.Fatalf("runLatestModules offline with a fresh row: %v", err)
	}
	var decoded map[string]any
	if err := json.Unmarshal(stdout.Bytes(), &decoded); err != nil {
		t.Fatalf("unmarshalling: %v\noutput: %s", err, stdout.String())
	}
	if decoded["latest"] != "v1.4.0" {
		t.Errorf("latest = %v, want v1.4.0 from the ledger", decoded["latest"])
	}
	// The two facts that make the answer readable: it says it was served, and it
	// says WHEN the proxy was asked — the original lookup, never this run.
	if decoded["served_from_store"] != true {
		t.Errorf("served_from_store = %v, want true", decoded["served_from_store"])
	}
	wantLookedUp := cliNow().Add(-10 * time.Minute).UTC().Format(time.RFC3339)
	if decoded["looked_up_at"] != wantLookedUp {
		t.Errorf("looked_up_at = %v, want %s", decoded["looked_up_at"], wantLookedUp)
	}

	// Nothing is written offline: an offline run learns no new upstream fact, so
	// the row it served is the row still stored, at its original date.
	rec, found, err := ledger.GetStaleness(context.Background(), offlineLatestModule)
	if err != nil || !found {
		t.Fatalf("re-reading the row: err=%v found=%v", err, found)
	}
	if !rec.LookedUpAt.Equal(cliNow().Add(-10 * time.Minute)) {
		t.Errorf("LookedUpAt moved to %s: an offline serve wrote to the ledger", rec.LookedUpAt)
	}
}

// TestLatestModules_OfflineRefusesWithoutAFreshRow is the non-zero control, in
// both its forms. Offline is not a licence to serve a stale answer — a
// week-old lookup presented as current is a worse defect than refusing — and it
// is not a licence to invent one for a module nothing was ever recorded for.
func TestLatestModules_OfflineRefusesWithoutAFreshRow(t *testing.T) {
	restore := SetClockForTest(time.Date(2026, 2, 28, 12, 0, 0, 0, time.UTC))
	t.Cleanup(restore)
	prev := jsonOut
	jsonOut = true
	t.Cleanup(func() { jsonOut = prev })

	tests := []struct {
		name   string
		ledger func(t *testing.T) staleports.Ledger
	}{
		{
			name:   "stale row",
			ledger: func(t *testing.T) staleports.Ledger { return seedOfflineLatestRow(t, 8*time.Hour) },
		},
		{
			name:   "no row at all",
			ledger: offlineLedger,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var stdout bytes.Buffer
			err := runLatestModules(context.Background(), []string{offlineLatestModule},
				newOfflineStalenessLookup(tc.ledger(t), time.Hour), &stdout, io.Discard)
			if err == nil {
				t.Fatalf("offline run answered without a fresh row; output: %s", stdout.String())
			}
			if code, ok := ExitCodeFromError(err); !ok || code != ExitConfig {
				t.Errorf("exit code = %v (carried %v), want ExitConfig", code, ok)
			}
			// The refusal names the obstacle it actually hit.
			for _, want := range []string{offlineLatestModule, "staleness.ttl", "no proxy fetching"} {
				if !strings.Contains(err.Error(), want) {
					t.Errorf("refusal does not mention %q: %v", want, err)
				}
			}
			// And not the two module-BYTES remedies the adapter refusal carried.
			// Neither yields an @latest version, so both sent the reader after
			// something that cannot work.
			for _, unwanted := range []string{"--from-modcache", "use --recursive"} {
				if strings.Contains(err.Error(), unwanted) {
					t.Errorf("refusal still offers %q, which cannot answer @latest: %v", unwanted, err)
				}
			}
		})
	}
}

// TestLatestRowFor_OfflineWithoutARowIsUnmeasuredNotAnError covers the --gomod
// table's cell for the same condition. Offline with nothing recorded is the
// mode working as designed, and reporting it as "(error resolving latest)"
// reads as a fault in a run where nothing went wrong.
func TestLatestRowFor_OfflineWithoutARowIsUnmeasuredNotAnError(t *testing.T) {
	restore := SetClockForTest(time.Date(2026, 2, 28, 12, 0, 0, 0, time.UTC))
	t.Cleanup(restore)

	var stderr bytes.Buffer
	row, _ := latestRowFor(context.Background(), newOfflineStalenessLookup(offlineLedger(t), time.Hour),
		offlineLatestModule, "v1.0.0", &stderr)
	if row.Latest == "(error)" {
		t.Errorf("offline row reported as an error: %+v", row)
	}
	if row.StalenessUnmeasured != stalenessOfflineNoEntry {
		t.Errorf("staleness_unmeasured = %q, want %q", row.StalenessUnmeasured, stalenessOfflineNoEntry)
	}
	if stderr.Len() != 0 {
		t.Errorf("an error line was printed for a working offline row: %s", stderr.String())
	}
	var out bytes.Buffer
	if err := printLatestTable(&out, []latestResult{row}); err != nil {
		t.Fatalf("printLatestTable: %v", err)
	}
	if !strings.Contains(out.String(), stalenessUnmeasuredLabel(stalenessOfflineNoEntry)) {
		t.Errorf("table cell does not state the offline absence:\n%s", out.String())
	}
}

// TestRunLatest_OfflineWiringOrder drives runLatest itself, which is where the
// defect was: the proxy adapter was constructed before the store was opened, so
// GOPROXY=off refused before any code that could serve a recorded answer ran.
// It is asserted here at the command entry point rather than at the lookup,
// because the lookup was never reached.
//
// The `direct` leg is the deliberate boundary. GOPROXY=direct asks for
// VCS-origin fetching, a route this adapter has not got; it is not a statement
// that the network is forbidden, so the ledger is not consulted for it and the
// refusal that names the mode stands — with a fresh row sitting right there.
func TestRunLatest_OfflineWiringOrder(t *testing.T) {
	restore := SetClockForTest(time.Date(2026, 2, 28, 12, 0, 0, 0, time.UTC))
	t.Cleanup(restore)
	prevJSON, prevRoot, prevTTL := jsonOut, storeRoot, activeConfig.Staleness.TTL
	jsonOut = true
	storeRoot = t.TempDir()
	// The package default leaves the TTL at zero, which disables serving; the
	// shipped default is 1h and that is what the wiring is being exercised under.
	activeConfig.Staleness.TTL = time.Hour
	t.Cleanup(func() { jsonOut, storeRoot, activeConfig.Staleness.TTL = prevJSON, prevRoot, prevTTL })

	ledger, cleanup, err := openStalenessLedger(storeRoot)
	if err != nil {
		t.Fatalf("opening the ledger under the test store root: %v", err)
	}
	row := staledomain.Record{
		ModulePath:    offlineLatestModule,
		LatestVersion: "v1.4.0",
		NewerMajor:    staledomain.NewerMajor{Probed: true, FromMajor: 2},
		LookedUpAt:    cliNow().Add(-10 * time.Minute),
	}
	if err := ledger.PutStaleness(context.Background(), row); err != nil {
		t.Fatalf("filing the row: %v", err)
	}
	if cerr := cleanup(); cerr != nil {
		t.Fatalf("closing the ledger: %v", cerr)
	}

	tests := []struct {
		name    string
		goproxy string
		fresh   bool
		wantErr bool
	}{
		{name: "off serves the fresh row", goproxy: "off"},
		{name: "off with --fresh still refuses", goproxy: "off", fresh: true, wantErr: true},
		{name: "direct still refuses", goproxy: "direct", wantErr: true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var stdout bytes.Buffer
			err := runLatest(context.Background(), []string{offlineLatestModule},
				latestFlags{goproxy: tc.goproxy, fresh: tc.fresh}, &stdout, io.Discard)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("expected a refusal, got: %s", stdout.String())
				}
				return
			}
			if err != nil {
				t.Fatalf("runLatest under GOPROXY=off with a fresh row: %v", err)
			}
			if !strings.Contains(stdout.String(), `"served_from_store": true`) {
				t.Errorf("the answer does not say it was served:\n%s", stdout.String())
			}
		})
	}
}

// Offline behaviour is unchanged by the batched latest, and this asserts it
// from both sides.
//
// The batch source is `go list -m -u`, which under GOPROXY=off exits 0 and
// reports every module as having no update — output byte-identical to "your
// whole dependency set is current". So the offline path never reaches the batch
// at all: it is the ledger, exactly as before. A row inside the TTL is served
// with its ORIGINAL lookup time, and a module without one is refused rather than
// answered.
func TestLatest_OfflineIsStillTheLedgerAndStillRefusesBeyondTheTTL(t *testing.T) {
	restore := SetClockForTest(time.Date(2026, 2, 28, 12, 0, 0, 0, time.UTC))
	t.Cleanup(restore)

	recordedAt := cliNow().Add(-10 * time.Minute)

	t.Run("inside the TTL, served with its own lookup time", func(t *testing.T) {
		var stderr bytes.Buffer
		row, err := latestRowFor(context.Background(),
			newOfflineStalenessLookup(seedOfflineLatestRow(t, 10*time.Minute), time.Hour),
			offlineLatestModule, "v1.0.0", &stderr)
		if err != nil {
			t.Fatalf("latestRowFor: %v", err)
		}
		if row.Latest != "v1.4.0" {
			t.Errorf("latest = %q, want the recorded v1.4.0", row.Latest)
		}
		if !row.Served {
			t.Error("the row does not say it came from the store")
		}
		if !row.LookedUpAt.Equal(recordedAt) {
			t.Errorf("looked_up_at = %v, want the ORIGINAL lookup time %v", row.LookedUpAt, recordedAt)
		}
		// The offline answer states its deprecation only when the recorded row
		// established it. This row was recorded before anything asked, so the
		// state is "not established" — never "not deprecated".
		if row.Deprecated != nil {
			t.Errorf("deprecated = %q, want null for a row nothing asked about", *row.Deprecated)
		}
	})

	t.Run("beyond the TTL, refused, never answered as current", func(t *testing.T) {
		var stderr bytes.Buffer
		row, err := latestRowFor(context.Background(),
			newOfflineStalenessLookup(seedOfflineLatestRow(t, 90*time.Minute), time.Hour),
			offlineLatestModule, "v1.0.0", &stderr)
		if err != nil {
			t.Fatalf("latestRowFor: %v", err)
		}
		if row.IsLatest != nil {
			t.Errorf("is_latest = %v, want null — nothing was measured", *row.IsLatest)
		}
		if row.Latest != "" {
			t.Errorf("latest = %q, want empty — a stale row is not served", row.Latest)
		}
		if row.StalenessUnmeasured != stalenessOfflineNoEntry {
			t.Errorf("staleness_unmeasured = %q, want %q", row.StalenessUnmeasured, stalenessOfflineNoEntry)
		}
	})
}

// A deprecation recorded by an online run is served back offline, with the
// lookup time of the run that recorded it. The notice is part of the answer that
// lookup gave, so it travels with it.
func TestLatest_OfflineServesARecordedDeprecation(t *testing.T) {
	restore := SetClockForTest(time.Date(2026, 2, 28, 12, 0, 0, 0, time.UTC))
	t.Cleanup(restore)

	const notice = "aws-sdk-go is deprecated. Use aws-sdk-go-v2."
	ledger := offlineLedger(t)
	if err := ledger.PutStaleness(context.Background(), staledomain.Record{
		ModulePath:    offlineLatestModule,
		LatestVersion: "v1.4.0",
		NewerMajor:    staledomain.NewerMajor{Probed: true, FromMajor: 2},
		Deprecation:   staledomain.Deprecation{Checked: true, Notice: notice},
		LookedUpAt:    cliNow().Add(-10 * time.Minute),
	}); err != nil {
		t.Fatalf("filing staleness row: %v", err)
	}

	var stderr bytes.Buffer
	row, err := latestRowFor(context.Background(), newOfflineStalenessLookup(ledger, time.Hour),
		offlineLatestModule, "v1.0.0", &stderr)
	if err != nil {
		t.Fatalf("latestRowFor: %v", err)
	}
	if row.Deprecated == nil || *row.Deprecated != notice {
		t.Fatalf("deprecated = %v, want the recorded notice", row.Deprecated)
	}
	var out bytes.Buffer
	if err := printLatestTable(&out, []latestResult{row}); err != nil {
		t.Fatalf("printLatestTable: %v", err)
	}
	if !strings.Contains(out.String(), "deprecated by its author: "+notice) {
		t.Errorf("offline table does not state the recorded notice:\n%s", out.String())
	}
}
