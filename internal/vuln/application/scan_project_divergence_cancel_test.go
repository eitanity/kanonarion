package application_test

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"

	application "github.com/eitanity/kanonarion/internal/vuln/application"
	"github.com/eitanity/kanonarion/internal/vuln/domain"
)

// An advisory match the run's cancellation stopped records nothing: it is not an
// advisory set that could not be read, and a ScanFailed record of it would keep
// answering after the run. A match that genuinely failed still records the fault.
func TestScanWalk_DivergedProjectMatchStoppedByTheCancellationRecordsNothing(t *testing.T) {
	cases := []struct {
		name      string
		lookupErr error
		cancelled bool
	}{
		{"cancelled", fmt.Errorf("reading advisories: %w", context.Canceled), true},
		{"genuine failure", errors.New("advisory index unreadable"), false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f, _, dir := recordedProjectFixture(t)
			writeProjectGoMod(t, dir, map[string]string{
				f.depA.Path(): "v3.0.2",
				f.depB.Path(): f.depB.Version(),
			})
			f.db.errOnLookup = tc.lookupErr
			ctx, cancel := context.WithCancel(t.Context())
			if tc.cancelled {
				cancel()
			}
			defer cancel()

			_, err := f.walkUC.Scan(ctx, application.ScanWalkParams{WalkID: f.walkID, Operator: "tester"})
			rec, ok, rerr := f.vulnStore.GetLatestVulnerabilityRecordForWalk(t.Context(), f.depA, "v1", f.walkID)
			if rerr != nil {
				t.Fatalf("reading back: %v", rerr)
			}
			if tc.cancelled {
				if !errors.Is(err, context.Canceled) {
					t.Errorf("err = %v, want the cancellation", err)
				}
				if ok {
					t.Errorf("a stopped match was recorded: status %s, detail %q", rec.OverallStatus, rec.ErrorDetail)
				}
				if strings.Contains(f.logs.String(), "advisory match by coordinate failed") {
					t.Errorf("a stopped match was logged as a failure:\n%s", f.logs.String())
				}
				return
			}
			if !ok || rec.OverallStatus != domain.StatusScanFailed {
				t.Errorf("a genuinely failed match recorded ok=%v status=%s, want ScanFailed", ok, rec.OverallStatus)
			}
		})
	}
}
