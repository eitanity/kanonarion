package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/eitanity/kanonarion/internal/cli/testfakes"
	"github.com/eitanity/kanonarion/internal/coordinate"
	"github.com/eitanity/kanonarion/internal/coordinate/coordinatetest"
	vuldomain "github.com/eitanity/kanonarion/internal/vuln/domain"
)

// A summary over a dependency set where any stage failed must never report
// AllClean: node failures, extract failures, or scan failures leave some of
// the dependency set unanalysed, and presenting absence of scan results as a
// clean verdict is the absence-as-answer defect class.
func TestInspectSummaryStatus_FailuresAreNeverAllClean(t *testing.T) {
	cases := []struct {
		name                               string
		nodeFails, extractFails, scanFails int
		scanStatus                         vuldomain.WalkScanStatus
		want                               string
	}{
		{"all stages clean", 0, 0, 0, vuldomain.WalkStatusAllClean, "AllClean"},
		{"findings without failures", 0, 0, 0, vuldomain.WalkStatusAffected, "Affected"},
		{"every scan failed", 0, 0, 11, vuldomain.WalkStatusFailed, "ScanFailed"},
		{"one scan failed", 0, 0, 1, vuldomain.WalkStatusAllClean, "Partial"},
		{"extract failed", 0, 1, 0, vuldomain.WalkStatusAllClean, "Partial"},
		{"node failures", 1, 0, 0, vuldomain.WalkStatusAllClean, "Partial"},
		{"failures alongside findings", 0, 0, 3, vuldomain.WalkStatusAffected, "Partial"},
		// A Partial scan run stays Partial. This holds whether or not the run also
		// has findings: the word is coverage-first (findings are shown on their own
		// line), so it does not take a finding count as input and cannot be flipped
		// to Affected — which would hide the coverage gap and make inspect disagree
		// with vuln-scan's "Partial coverage, Affected (N)".
		{"scan run itself Partial (metadata-only coverage gap)", 0, 0, 0, vuldomain.WalkStatusPartial, "Partial"},
		// The scan run's own ScanFailed verdict must surface: every module failed
		// (or the walk had no modules), which produced no stage failure here and
		// previously fell through to a confident AllClean.
		{"scan run ScanFailed with no stage failure", 0, 0, 0, vuldomain.WalkStatusFailed, "ScanFailed"},
		// An unreadable or absent scan run is an unknown outcome, never a clean one.
		{"no scan run recorded", 0, 0, 0, "", "Partial"},
		// A status added to the enum later must not degrade to AllClean.
		{"unrecognised future status", 0, 0, 0, vuldomain.WalkScanStatus("SomethingNew"), "Partial"},
		{"affected from run status", 0, 0, 0, vuldomain.WalkStatusAffected, "Affected"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := inspectSummaryStatus(tc.nodeFails, tc.extractFails, tc.scanFails, tc.scanStatus)
			if got != tc.want {
				t.Errorf("inspectSummaryStatus(%d, %d, %d, %q) = %q, want %q",
					tc.nodeFails, tc.extractFails, tc.scanFails, tc.scanStatus, got, tc.want)
			}
		})
	}
}

// The inspect summary's affected count must be the real number of modules
// whose per-module verdict is Affected, not a 0/1 flag off OverallStatus: a run
// with several affected modules must count every one of them. A not-found record
// is a coverage gap, not an affected verdict, so it is excluded rather than
// fabricated into the set.
func TestAffectedSetForRun_CountsEveryAffectedModule(t *testing.T) {
	aff1 := coordinatetest.MustNew("example.com/a", "v1.0.0")
	aff2 := coordinatetest.MustNew("example.com/b", "v1.0.0")
	aff3 := coordinatetest.MustNew("example.com/c", "v1.0.0")
	clean := coordinatetest.MustNew("example.com/d", "v1.0.0")
	missing := coordinatetest.MustNew("example.com/e", "v1.0.0")

	vuln := testfakes.NewFakeQueryVuln()
	vuln.AddRecord(aff1, aff(aff1))
	vuln.AddRecord(aff2, aff(aff2))
	vuln.AddRecord(aff3, aff(aff3))
	vuln.AddRecord(clean, cln(clean))
	// `missing` is present in the run but has no record → a coverage gap, not
	// evidence of Affected, so it is excluded.

	run := vuldomain.WalkScanRun{
		WalkID:        "walk-1",
		OverallStatus: vuldomain.WalkStatusAffected,
		PerModuleResults: map[coordinate.ModuleCoordinate]string{
			aff1: "", aff2: "", aff3: "", clean: "", missing: "",
		},
	}

	got, err := affectedSetForRun(context.Background(), vuln, run)
	if err != nil {
		t.Fatalf("affectedSetForRun returned error: %v", err)
	}
	if len(got) != 3 {
		t.Errorf("affected count = %d, want 3 (only the three Affected records); got set %v", len(got), got)
	}
	if _, ok := got[clean]; ok {
		t.Errorf("clean module %v must not be counted as affected", clean)
	}
	if _, ok := got[missing]; ok {
		t.Errorf("not-found module %v is a coverage gap, must not be fabricated into the affected set", missing)
	}
}

// A store read error must not be fabricated into an affected verdict: presenting
// a peer as affected when the store could only not be read is the error-as-answer
// defect. affectedSetForRun propagates the fault instead.
func TestAffectedSetForRun_ReadErrorPropagatedNotFabricated(t *testing.T) {
	coord := coordinatetest.MustNew("example.com/a", "v1.0.0")
	vuln := testfakes.NewFakeQueryVuln()
	vuln.Err = errors.New("store unreadable")

	run := vuldomain.WalkScanRun{
		WalkID:           "walk-1",
		OverallStatus:    vuldomain.WalkStatusAffected,
		PerModuleResults: map[coordinate.ModuleCoordinate]string{coord: ""},
	}

	got, err := affectedSetForRun(context.Background(), vuln, run)
	if err == nil {
		t.Fatalf("affectedSetForRun = %v, nil; want a propagated read error, not a fabricated affected set", got)
	}
	if !strings.Contains(err.Error(), "store unreadable") {
		t.Errorf("error = %v, want it to wrap the store read error", err)
	}
}

// --gomod --reachability roots at the dependency closure, not the project's own
// code. The disclosure banner must make that unmistakable: it names the closure
// rooting, states the app->dependency edge is absent, and points the reader to
// `kanonarion local` to root at the application.
func TestReachabilityClosureBanner_DisclosesClosureRooting(t *testing.T) {
	var buf bytes.Buffer
	printReachabilityClosureBanner(&buf, "/home/user/proj/go.mod")
	out := buf.String()

	for _, want := range []string{
		"DEPENDENCY CLOSURE",
		"consumer-mode",
		"kanonarion local /home/user/proj",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("banner missing %q:\n%s", want, out)
		}
	}
	// It must not claim to be rooted at the project entrypoints.
	if strings.Contains(out, "rooted at the project entrypoint") && !strings.Contains(out, "one hop") {
		t.Errorf("banner must not imply app-rooted reachability:\n%s", out)
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
