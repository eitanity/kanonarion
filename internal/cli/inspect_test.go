package cli

import (
	"bytes"
	"encoding/json"
	vuldomain "github.com/eitanity/kanonarion/internal/vuln/domain"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// A summary over a dependency set where any stage failed must never report
// AllClean: node failures, extract failures, or scan failures leave some of
// the dependency set unanalysed, and presenting absence of scan results as a
// clean verdict is the absence-as-answer defect class.
func TestInspectSummaryStatus_FailuresAreNeverAllClean(t *testing.T) {
	cases := []struct {
		name                                         string
		nodeFails, extractFails, scanFails, affected int
		scanStatus                                   vuldomain.WalkScanStatus
		want                                         string
	}{
		{"all stages clean", 0, 0, 0, 0, vuldomain.WalkStatusAllClean, "AllClean"},
		{"findings without failures", 0, 0, 0, 2, vuldomain.WalkStatusAffected, "Affected"},
		{"every scan failed", 0, 0, 11, 0, vuldomain.WalkStatusFailed, "ScanFailed"},
		{"one scan failed", 0, 0, 1, 0, vuldomain.WalkStatusAllClean, "Partial"},
		{"extract failed", 0, 1, 0, 0, vuldomain.WalkStatusAllClean, "Partial"},
		{"node failures", 1, 0, 0, 0, vuldomain.WalkStatusAllClean, "Partial"},
		{"failures alongside findings", 0, 0, 3, 2, vuldomain.WalkStatusAffected, "Partial"},
		{"scan run itself Partial (metadata-only coverage gap)", 0, 0, 0, 0, vuldomain.WalkStatusPartial, "Partial"},
		// The scan run's own ScanFailed verdict must surface: every module failed
		// (or the walk had no modules), which produced no stage failure here and
		// previously fell through to a confident AllClean.
		{"scan run ScanFailed with no stage failure", 0, 0, 0, 0, vuldomain.WalkStatusFailed, "ScanFailed"},
		// An unreadable or absent scan run is an unknown outcome, never a clean one.
		{"no scan run recorded", 0, 0, 0, 0, "", "Partial"},
		// A status added to the enum later must not degrade to AllClean.
		{"unrecognised future status", 0, 0, 0, 0, vuldomain.WalkScanStatus("SomethingNew"), "Partial"},
		// The run says Affected even though the per-run count was not set.
		{"affected from run status only", 0, 0, 0, 0, vuldomain.WalkStatusAffected, "Affected"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := inspectSummaryStatus(tc.nodeFails, tc.extractFails, tc.scanFails, tc.affected, tc.scanStatus)
			if got != tc.want {
				t.Errorf("inspectSummaryStatus(%d, %d, %d, %d, %q) = %q, want %q",
					tc.nodeFails, tc.extractFails, tc.scanFails, tc.affected, tc.scanStatus, got, tc.want)
			}
		})
	}
}

// A module with no Go source files produces an empty code scope; inspect
// reports that and exits cleanly without spinning up the project walk.
func TestInspectCmd_GomodAllIndirect(t *testing.T) {
	gomod := "module example.com/app\n\ngo 1.21\n\nrequire (\n\tgithub.com/only/indirect v1.0.0 // indirect\n)\n"
	dir := t.TempDir()
	path := filepath.Join(dir, "go.mod")
	if err := os.WriteFile(path, []byte(gomod), 0o600); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	err := Run([]string{"inspect", "--gomod", path}, &stdout, &stderr)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(stdout.String(), "no code dependencies found") {
		t.Errorf("expected empty-scope message, got: %q", stdout.String())
	}
}

// inspectSummary must not contain walk_count (removed with the per-module
// model) and must contain node_fails (added to reflect per-node failures
// within the single project walk).
func TestInspectSummary_JSONShape(t *testing.T) {
	s := inspectSummary{
		ModuleCount:   21,
		NodeFails:     0,
		ExtractFails:  0,
		ScanFails:     0,
		OverallStatus: "AllClean",
		AffectedCount: 0,
		WalkIDs:       []string{"01KXXX"},
	}
	b, err := json.Marshal(s)
	if err != nil {
		t.Fatalf("marshal inspectSummary: %v", err)
	}
	raw := string(b)
	if strings.Contains(raw, `"walk_count"`) {
		t.Errorf("JSON still contains walk_count (old per-module field): %s", raw)
	}
	for _, want := range []string{`"module_count"`, `"overall_status"`, `"walk_ids"`} {
		if !strings.Contains(raw, want) {
			t.Errorf("JSON missing required field %s: %s", want, raw)
		}
	}
}
