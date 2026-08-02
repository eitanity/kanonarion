package cli

import (
	"bytes"
	"strings"
	"testing"
	"time"

	vulndomain "github.com/eitanity/kanonarion/internal/vuln/domain"
	"github.com/eitanity/kanonarion/internal/vuln/vulntest"
	walkdomain "github.com/eitanity/kanonarion/internal/walk/domain"
)

// TestAuditDerivation_NamesTheReusedRunsAndTheirDates is the reporting half of
// the fix. A reader cannot otherwise tell a fresh measurement from a served one,
// and the two carry different weight in exactly the cases — release evidence,
// incident response — where the distinction decides what the answer is worth.
func TestAuditDerivation_NamesTheReusedRunsAndTheirDates(t *testing.T) {
	walkedAt := time.Date(2026, 8, 2, 4, 14, 4, 0, time.UTC)
	scannedAt := time.Date(2026, 8, 2, 4, 14, 9, 0, time.UTC)

	var out bytes.Buffer
	err := writeAuditDerivation(&out, auditDerivation{
		walkReused: true,
		walkRecord: walkdomain.WalkRecord{ID: "01KZ0AVM2897N6J6YE4GABYG27", CompletedAt: walkedAt},
		scanReused: true,
		scanRun: vulndomain.WalkScanRun{
			ID:          "vscan-01KZ0AVM2897N6J6YE4GABYG27-1754107449",
			CompletedAt: scannedAt,
			Snapshot:    vulntest.MustNew("vuln.go.dev", "2026-07-27T20:14:16Z"),
		},
	})
	if err != nil {
		t.Fatalf("writeAuditDerivation: %v", err)
	}

	got := out.String()
	for _, want := range []string{
		"01KZ0AVM2897N6J6YE4GABYG27",
		"2026-08-02T04:14:04Z",
		"vscan-01KZ0AVM2897N6J6YE4GABYG27-1754107449",
		"2026-08-02T04:14:09Z",
		"2026-07-27T20:14:16Z",
		"--force",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("the derivation statement does not name %q:\n%s", want, got)
		}
	}
}

// TestAuditDerivation_SaysWhenItMeasured pins the other word. A run that
// derived its own answers must not read as a served one, and the walk line must
// not claim work was skipped that was not: the resolution ran either way.
func TestAuditDerivation_SaysWhenItMeasured(t *testing.T) {
	var out bytes.Buffer
	err := writeAuditDerivation(&out, auditDerivation{
		walkRecord: walkdomain.WalkRecord{ID: "01KZ0BSYX0YSP6HPWWW6Y134SW"},
	})
	if err != nil {
		t.Fatalf("writeAuditDerivation: %v", err)
	}

	got := out.String()
	if strings.Contains(got, "reused") {
		t.Errorf("a fully re-derived audit reported reuse:\n%s", got)
	}
	if !strings.Contains(got, "01KZ0BSYX0YSP6HPWWW6Y134SW") {
		t.Errorf("the derivation statement does not name the walk it derived:\n%s", got)
	}
	if !strings.Contains(got, "derived by this run") {
		t.Errorf("the derivation statement does not say the answers were derived:\n%s", got)
	}
}

// TestAuditDerivation_ReportsAReusedWalkWithAFreshScan covers the mixed case: a
// new advisory snapshot re-scans a walk that did not change, and the statement
// has to distinguish the two halves rather than collapse them into one word.
func TestAuditDerivation_ReportsAReusedWalkWithAFreshScan(t *testing.T) {
	var out bytes.Buffer
	err := writeAuditDerivation(&out, auditDerivation{
		walkReused: true,
		walkRecord: walkdomain.WalkRecord{
			ID:          "01KZ0AVM2897N6J6YE4GABYG27",
			CompletedAt: time.Date(2026, 8, 2, 4, 14, 4, 0, time.UTC),
		},
	})
	if err != nil {
		t.Fatalf("writeAuditDerivation: %v", err)
	}

	got := out.String()
	if !strings.Contains(got, "that record was reused") {
		t.Errorf("the walk half does not report reuse:\n%s", got)
	}
	if !strings.Contains(got, "vulnerability scan: derived by this run") {
		t.Errorf("the scan half does not report that it measured:\n%s", got)
	}
}
