package cli

import (
	"bytes"
	"encoding/json"
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
		want                                         string
	}{
		{"all stages clean", 0, 0, 0, 0, "AllClean"},
		{"findings without failures", 0, 0, 0, 2, "Affected"},
		{"every scan failed", 0, 0, 11, 0, "Partial"},
		{"one scan failed", 0, 0, 1, 0, "Partial"},
		{"extract failed", 0, 1, 0, 0, "Partial"},
		{"node failures", 1, 0, 0, 0, "Partial"},
		{"failures alongside findings", 0, 0, 3, 2, "Partial"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := inspectSummaryStatus(tc.nodeFails, tc.extractFails, tc.scanFails, tc.affected)
			if got != tc.want {
				t.Errorf("inspectSummaryStatus(%d, %d, %d, %d) = %q, want %q",
					tc.nodeFails, tc.extractFails, tc.scanFails, tc.affected, got, tc.want)
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
