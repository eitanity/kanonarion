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
	extractdomain "github.com/eitanity/kanonarion/internal/extract/domain"
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

	got, err := affectedSetForRun(context.Background(), vuln, run, vulnFrameAnchor{walkID: "walk-1"})
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

	got, err := affectedSetForRun(context.Background(), vuln, run, vulnFrameAnchor{walkID: "walk-1"})
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

// inspect's extract tally must equal the failed-stage count on the run it just
// made. It was derived from whether runExtract returned a Go error, which a
// partial run does not, so a run the store records as partial — with named
// modules whose public API went unmeasured — was summarised as
// `extract_fails: 0` and rolled up to AllClean.
func TestInspectExtractTally_CountsTheRunsFailedStages(t *testing.T) {
	run := extractdomain.ExtractionRun{
		ID:            "01EXTRACTRUN00000000000001",
		OverallStatus: extractdomain.ExtractionRunPartial,
		PerModuleResults: map[coordinate.ModuleCoordinate]extractdomain.ModuleExtractionResult{
			coordinatetest.MustNew("example.com/a", "v1.0.0"): {
				Stages: map[string]extractdomain.StageResult{
					"callgraph": {Status: extractdomain.StageFailed, Error: "no go.mod was synthesised"},
					"license":   {Status: extractdomain.StageSucceeded},
				},
			},
			coordinatetest.MustNew("example.com/b", "v2.0.0"): {
				Stages: map[string]extractdomain.StageResult{
					"callgraph": {Status: extractdomain.StageFailed},
					"interface": {Status: extractdomain.StageFailed},
				},
			},
		},
	}

	count, failures := inspectExtractTally(run, nil)
	if count != 3 {
		t.Errorf("extract_fails = %d, want 3 — the run's own failed-stage count, not a 0/1 flag", count)
	}
	if len(failures) != count {
		t.Errorf("named %d failures for a count of %d; the two are one reading of one run", len(failures), count)
	}
	// The roll-up must move off AllClean on the strength of that count alone.
	if got := inspectSummaryStatus(0, count, 0, vuldomain.WalkStatusAllClean); got == "AllClean" {
		t.Errorf("status = %q over a partial extraction; AllClean over unmeasured modules is the defect", got)
	}

	// Control: a run in which every stage succeeded still counts zero and names
	// nothing, and still rolls up AllClean.
	clean := extractdomain.ExtractionRun{
		OverallStatus: extractdomain.ExtractionRunSucceeded,
		PerModuleResults: map[coordinate.ModuleCoordinate]extractdomain.ModuleExtractionResult{
			coordinatetest.MustNew("example.com/a", "v1.0.0"): {
				Stages: map[string]extractdomain.StageResult{"license": {Status: extractdomain.StageSucceeded}},
			},
		},
	}
	cleanCount, cleanFailures := inspectExtractTally(clean, nil)
	if cleanCount != 0 || len(cleanFailures) != 0 {
		t.Errorf("clean run tallied %d/%v, want 0 and nothing named", cleanCount, cleanFailures)
	}
	if got := inspectSummaryStatus(0, cleanCount, 0, vuldomain.WalkStatusAllClean); got != "AllClean" {
		t.Errorf("clean run status = %q, want AllClean", got)
	}

	// An extraction that produced no run at all has no breakdown to count. The
	// summary reports one rather than zero: nothing was measured, and zero is the
	// answer it must not give.
	errCount, errFailures := inspectExtractTally(extractdomain.ExtractionRun{}, errors.New("initialising store"))
	if errCount != 1 {
		t.Errorf("failed extraction tallied %d, want 1", errCount)
	}
	if errFailures == nil || len(errFailures) != 0 {
		t.Errorf("failed extraction named %v, want an empty non-nil list", errFailures)
	}
}

// The summary document must name what its extract tally counts. A number with
// no coordinates behind it tells a consumer that some module's public API is
// unmeasured without saying whose, and neither stream carried the pairs.
func TestInspectSummary_JSONCarriesTheExtractFailures(t *testing.T) {
	b, err := json.Marshal(inspectSummary{
		ExtractFails: 1,
		ExtractFailures: []extractStageFailure{
			{Module: "example.com/a@v1.0.0", Stage: "callgraph", Error: "no go.mod was synthesised"},
		},
		OverallStatus: "Partial",
		WalkIDs:       []string{"01KXXX"},
	})
	if err != nil {
		t.Fatalf("marshal inspectSummary: %v", err)
	}
	raw := string(b)
	for _, want := range []string{`"extract_failures"`, `"example.com/a@v1.0.0"`, `"callgraph"`, `"no go.mod was synthesised"`} {
		if !strings.Contains(raw, want) {
			t.Errorf("JSON missing %s: %s", want, raw)
		}
	}
	// Emitted at zero, like the tallies beside it: a clean run's document is the
	// same document, with the list empty rather than absent.
	empty, err := json.Marshal(inspectSummary{ExtractFailures: []extractStageFailure{}, WalkIDs: []string{}})
	if err != nil {
		t.Fatalf("marshal empty inspectSummary: %v", err)
	}
	if !strings.Contains(string(empty), `"extract_failures":[]`) {
		t.Errorf("a clean run must emit extract_failures as an empty list: %s", empty)
	}
}

// A --gomod roll-up of Partial must reach the exit code. Moving the word off
// AllClean fixed what a human reads; the process still reported success, so a
// caller branching on the exit code — which is the only thing a CI step reads —
// still learned nothing about a dependency set that went unanalysed.
//
// The status under test is derived from a run the store recorded as partial and
// carried through the same two functions the command uses, rather than being a
// string set by hand: the defect was the chain, not any one link.
func TestInspectExit_PartialRollUpIsNotASuccess(t *testing.T) {
	run := extractdomain.ExtractionRun{
		ID:            "01EXTRACTRUN00000000000001",
		OverallStatus: extractdomain.ExtractionRunPartial,
		PerModuleResults: map[coordinate.ModuleCoordinate]extractdomain.ModuleExtractionResult{
			coordinatetest.MustNew("modernc.org/libc", "v1.73.5"): {
				Stages: map[string]extractdomain.StageResult{
					"callgraph": {Status: extractdomain.StageFailed, Error: "conflicting call graph records"},
					"license":   {Status: extractdomain.StageSucceeded},
				},
			},
			coordinatetest.MustNew("modernc.org/sqlite", "v1.53.0"): {
				Stages: map[string]extractdomain.StageResult{
					"callgraph": {Status: extractdomain.StageFailed, Error: "conflicting call graph records"},
				},
			},
		},
	}
	extractFails, _ := inspectExtractTally(run, nil)
	status := inspectSummaryStatus(0, extractFails, 0, vuldomain.WalkStatusAllClean)
	if status != string(vuldomain.WalkStatusPartial) {
		t.Fatalf("roll-up = %q, want Partial: the rest of this test is about the code that word earns", status)
	}

	err := inspectExit(status)
	if err == nil {
		t.Fatalf("roll-up %q returned no error: the process reports success over %d unmeasured stage(s)", status, extractFails)
	}
	code, ok := ExitCodeFromError(err)
	if !ok {
		t.Fatalf("roll-up %q returned an error carrying no exit code: %v", status, err)
	}
	if code != ExitPartial {
		t.Errorf("exit code = %d, want %d (%v)", code, ExitPartial, err)
	}

	// Controls. An answer is not a gap: a clean set, a set with real findings,
	// and a scan that failed outright all keep the code they have today.
	for _, answer := range []vuldomain.WalkScanStatus{
		vuldomain.WalkStatusAllClean, vuldomain.WalkStatusAffected, vuldomain.WalkStatusFailed,
	} {
		clean := inspectSummaryStatus(0, 0, 0, answer)
		if got := inspectExit(clean); got != nil {
			t.Errorf("roll-up %q returned %v, want no error", clean, got)
		}
	}
}

// inspect's document is a per-module context and had nowhere to say which walk,
// which scan and which advisory database answered for it. Those facts reached
// the reader on stderr, where no machine reader sees them.
//
// The section is inserted beside the per-module content, never into it: the
// bytes `context` rendered come through unchanged, key for key and byte for
// byte, so a consumer that indexes into the document reads what it read before.
func TestSpliceInspectRun_AddsTheRunBesideTheUnchangedDocument(t *testing.T) {
	doc := []byte("{\n  \"module\": {\n    \"path\": \"example.com/dep\"\n  },\n  \"license\": null\n}\n")
	run := inspectRunSection{
		WalkID:    "01JS0NGARD0000000000000WA1",
		Walk:      inspectStageReused,
		ScanRunID: "vscan-1",
		Scan:      inspectStageMeasured,
		Snapshot:  vulnScanSnapshotJSON{Source: "govulndb", Version: "v2026-03-01"},
		Toolchain: unjudgedToolchainSection("the walk recorded no build toolchain version"),
	}

	out, err := spliceInspectRun(doc, run)
	if err != nil {
		t.Fatalf("spliceInspectRun: %v", err)
	}

	var got map[string]any
	if uerr := json.Unmarshal(out, &got); uerr != nil {
		t.Fatalf("the spliced document is not JSON: %v\n%s", uerr, out)
	}
	section, ok := got["run"].(map[string]any)
	if !ok {
		t.Fatalf("the document carries no run section:\n%s", out)
	}
	for key, want := range map[string]any{
		"walk_id": "01JS0NGARD0000000000000WA1", "walk": inspectStageReused,
		"scan_run_id": "vscan-1", "scan": inspectStageMeasured,
	} {
		if section[key] != want {
			t.Errorf("run.%s = %v, want %v", key, section[key], want)
		}
	}

	// The per-module half is byte-identical: strip the section back out and the
	// original document must return exactly.
	idx := bytes.Index(out, []byte(",\n  \"module\""))
	if idx < 0 {
		t.Fatalf("the run section did not precede the document's own first key:\n%s", out)
	}
	if stripped := append([]byte("{"), out[idx+1:]...); !bytes.Equal(stripped, doc) {
		t.Errorf("the per-module content changed.\nwant: %q\ngot:  %q", doc, stripped)
	}
}

// A stage that did not run is a value the document states, not a key it leaves
// out: an absent toolchain judgment reads as a clear one, which is the reading
// this whole section exists to prevent.
func TestInspectRunNotStarted_StatesTheStagesItDidNotRun(t *testing.T) {
	run := inspectRunNotStarted()
	if run.Walk != inspectStageNotRun || run.Scan != inspectStageNotRun {
		t.Errorf("stages = walk %q, scan %q; want both %q", run.Walk, run.Scan, inspectStageNotRun)
	}
	if run.Toolchain.Judged {
		t.Error("a pipeline that ran no scan reports a judged toolchain")
	}
	if run.Toolchain.Status != string(vuldomain.ToolchainUnjudged) {
		t.Errorf("toolchain status = %q, want %q", run.Toolchain.Status, vuldomain.ToolchainUnjudged)
	}
	if run.Toolchain.Reason == "" || run.Toolchain.Statement == "" {
		t.Errorf("an unjudged toolchain states no reason: %+v", run.Toolchain)
	}

	// Every field is present in the encoding, so no consumer reads a missing key
	// as "nothing to report".
	raw, err := json.Marshal(run)
	if err != nil {
		t.Fatalf("marshalling the run section: %v", err)
	}
	var doc map[string]any
	if uerr := json.Unmarshal(raw, &doc); uerr != nil {
		t.Fatalf("decoding the run section: %v", uerr)
	}
	for _, key := range []string{"walk_id", "walk", "scan_run_id", "scan", "snapshot", "toolchain"} {
		if _, ok := doc[key]; !ok {
			t.Errorf("the run section omits %q: %s", key, raw)
		}
	}
	if _, ok := doc["toolchain"].(map[string]any)["judged"]; !ok {
		t.Errorf("the toolchain section omits judged: %s", raw)
	}
}

// A document with nowhere to put the key is refused rather than printed without
// its run facts: printing the answer anyway is the silence the section closes.
func TestSpliceInspectRun_RefusesADocumentThatIsNotAnObject(t *testing.T) {
	if _, err := spliceInspectRun([]byte("[]\n"), inspectRunNotStarted()); err == nil {
		t.Error("an array document was accepted, so the run facts would be dropped")
	}
}
