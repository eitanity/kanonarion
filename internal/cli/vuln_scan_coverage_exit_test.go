package cli

import (
	"strings"
	"testing"

	vuldomain "github.com/eitanity/kanonarion/internal/vuln/domain"
)

// TestVulnScanCoverageExit is the regression test for the exit code that said
// the work completed when it had not.
//
// A vuln-scan whose target could not be loaded printed its coverage gap and
// exited 0. The exit code is the one signal an automation caller reads without
// parsing prose, so leaving it at 0 made an un-run scan indistinguishable from a
// passing one for every consumer that branches on it.
func TestVulnScanCoverageExit(t *testing.T) {
	run := func(coverage vuldomain.CoverageStatus, unscannable, failed, total int) vuldomain.WalkScanRun {
		return vuldomain.WalkScanRun{
			CoverageStatus: coverage,
			Counts:         vuldomain.WalkScanCounts{Total: total, Unscannable: unscannable, Failed: failed},
		}
	}

	tests := []struct {
		name     string
		run      vuldomain.WalkScanRun
		wantCode int
		wantText string
	}{
		{
			name:     "complete coverage exits OK",
			run:      run(vuldomain.CoverageComplete, 0, 0, 12),
			wantCode: ExitOK,
		},
		{
			// The live reproduction: one module, never analysed.
			name:     "a sole target that was never analysed is partial, not OK",
			run:      run(vuldomain.CoveragePartial, 1, 0, 1),
			wantCode: ExitPartial,
			wantText: "1 of 1 modules were not analysed",
		},
		{
			name:     "a partial run names how much went unanalysed",
			run:      run(vuldomain.CoveragePartial, 3, 1, 40),
			wantCode: ExitPartial,
			wantText: "4 of 40 modules were not analysed",
		},
		{
			name:     "a run that analysed nothing at all is failed",
			run:      run(vuldomain.CoverageFailed, 0, 7, 7),
			wantCode: ExitFailed,
			wantText: "the scan established nothing",
		},
		{
			// An unknown coverage word is not a statement that the run completed.
			name:     "an unrecognised coverage status degrades to partial",
			run:      run(vuldomain.CoverageStatus("Whatever"), 0, 0, 3),
			wantCode: ExitPartial,
			wantText: "unrecognised coverage status",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := vulnScanCoverageExit(tc.run)
			if tc.wantCode == ExitOK {
				if err != nil {
					t.Fatalf("vulnScanCoverageExit = %v, want nil", err)
				}
				return
			}
			if err == nil {
				t.Fatalf("vulnScanCoverageExit = nil, want exit %d", tc.wantCode)
			}
			code, ok := ExitCodeFromError(err)
			if !ok {
				t.Fatalf("error carries no exit code: %v", err)
			}
			if code != tc.wantCode {
				t.Errorf("exit code = %d, want %d", code, tc.wantCode)
			}
			if !strings.Contains(err.Error(), tc.wantText) {
				t.Errorf("message = %q, want it to contain %q", err.Error(), tc.wantText)
			}
		})
	}
}

// TestVulnScanCoverageExit_FindingsDoNotDecideTheExitCode pins the gate to the
// coverage axis alone. A complete run that found vulnerabilities did its work
// and reports them; whether that should fail a build is a policy question, and
// ExitPolicy is where policy gates live — collapsing the two would make "the
// scan could not run" indistinguishable from "the scan ran and found something".
func TestVulnScanCoverageExit_FindingsDoNotDecideTheExitCode(t *testing.T) {
	affected := vuldomain.WalkScanRun{
		CoverageStatus: vuldomain.CoverageComplete,
		FindingsStatus: vuldomain.FindingsAffected,
		Counts:         vuldomain.WalkScanCounts{Total: 9, Affected: 4},
	}
	if err := vulnScanCoverageExit(affected); err != nil {
		t.Errorf("vulnScanCoverageExit = %v, want nil for a complete run that found advisories", err)
	}
}
