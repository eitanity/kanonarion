package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/eitanity/kanonarion/internal/config/domain"
	"github.com/eitanity/kanonarion/internal/coordinate"
	fetchdomain "github.com/eitanity/kanonarion/internal/fetch/domain"
	vuldomain "github.com/eitanity/kanonarion/internal/vuln/domain"

	"github.com/eitanity/kanonarion/internal/cli/testfakes"
)

// TestVulnScanProgressScanFailedReason verifies that the progress callback
// prints a reason sub-line when ErrorDetail is set on a ScanFailed record.
func TestVulnScanProgressScanFailedReason(t *testing.T) {
	coord, _ := coordinate.NewModuleCoordinate("example.com/app", "v1.0.0")
	record := vuldomain.VulnerabilityRecord{
		Coordinate:    coord,
		OverallStatus: vuldomain.StatusScanFailed,
		ErrorDetail:   "govulncheck: exit status 1: module zip not found",
	}

	var buf strings.Builder
	writeVulnScanProgress(record, coord, 1, 1, &buf)

	got := buf.String()
	if !strings.Contains(got, "ScanFailed") {
		t.Errorf("expected ScanFailed in output, got:\n%s", got)
	}
	if !strings.Contains(got, "reason: govulncheck: exit status 1") {
		t.Errorf("expected error detail in output, got:\n%s", got)
	}
}

// TestVulnScanProgressUnscannableReason verifies that the per-module line for an
// Unscannable record carries the reason's label and not its free text. The free
// text is constant across every module carrying the reason, so it belongs to the
// end-of-run roll-up; the label is the part that varies per module and stays.
func TestVulnScanProgressUnscannableReason(t *testing.T) {
	coord, _ := coordinate.NewModuleCoordinate("example.com/nogomod", "v1.0.0")
	record := vuldomain.VulnerabilityRecord{
		Coordinate:        coord,
		OverallStatus:     vuldomain.StatusUnscannable,
		UnscanReason:      vuldomain.UnscanReasonNoGoMod,
		UnscannableReason: "no go.mod found in module zip",
	}

	var buf strings.Builder
	writeVulnScanProgress(record, coord, 1, 1, &buf)

	got := buf.String()
	if !strings.Contains(got, "Metadata-only (module zip has no go.mod") {
		t.Errorf("expected the reason's label on the per-module line, got:\n%s", got)
	}
	if strings.Contains(got, "reason: no go.mod found") {
		t.Errorf("shared free-text reason must not be repeated per module, got:\n%s", got)
	}
}

// TestVulnScanProgressNoReasonWhenEmpty verifies that no reason sub-line is
// printed when ErrorDetail / UnscannableReason is empty.
func TestVulnScanProgressNoReasonWhenEmpty(t *testing.T) {
	coord, _ := coordinate.NewModuleCoordinate("example.com/app", "v1.0.0")

	for _, status := range []vuldomain.VulnerabilityStatus{
		vuldomain.StatusScanFailed,
		vuldomain.StatusUnscannable,
	} {
		record := vuldomain.VulnerabilityRecord{Coordinate: coord, OverallStatus: status}
		var buf strings.Builder
		writeVulnScanProgress(record, coord, 1, 1, &buf)
		if strings.Contains(buf.String(), "reason:") {
			t.Errorf("status %s: unexpected reason line when detail is empty:\n%s", status, buf.String())
		}
	}
}

// ---- printVulnScanResult ------------------------------------------------

// TestPrintVulnScanResult_FindingsOnStdout verifies that affected modules and
// their CVE IDs appear on stdout, not lost in stderr noise.
func TestPrintVulnScanResult_FindingsOnStdout(t *testing.T) {
	coord := mustVulnCoord(t, "github.com/gorilla/csrf", "v1.7.3")
	rec := vuldomain.VulnerabilityRecord{
		Coordinate:    coord,
		OverallStatus: vuldomain.StatusAffected,
		Findings: []vuldomain.VulnerabilityFinding{
			{ID: "GO-2025-3884", Summary: "CSRF token bypass"},
		},
	}
	run := vuldomain.WalkScanRun{
		ID:            "run-001",
		OverallStatus: vuldomain.WalkStatusAffected,
	}
	affected := []vulnScanAffected{{coord: "github.com/gorilla/csrf@v1.7.3", record: rec}}

	var stdout bytes.Buffer
	if err := printVulnScanResult(run, affected, nil, nil, false, &stdout); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	out := stdout.String()
	if !strings.Contains(out, "GO-2025-3884") {
		t.Errorf("CVE ID missing from stdout: %q", out)
	}
	if !strings.Contains(out, "github.com/gorilla/csrf@v1.7.3") {
		t.Errorf("module coordinate missing from stdout: %q", out)
	}
	if !strings.Contains(out, "Findings") {
		t.Errorf("findings header missing from stdout: %q", out)
	}
}

// TestPrintVulnScanResult_CleanWalkNoFindingsBlock verifies that a clean walk
// produces no "Findings" block on stdout — only the status line.
func TestPrintVulnScanResult_CleanWalkNoFindingsBlock(t *testing.T) {
	run := vuldomain.WalkScanRun{
		ID:            "run-002",
		OverallStatus: vuldomain.WalkStatusAllClean,
	}

	var stdout bytes.Buffer
	if err := printVulnScanResult(run, nil, nil, nil, false, &stdout); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	out := stdout.String()
	if strings.Contains(out, "Findings") {
		t.Errorf("clean walk must not emit a Findings block, got: %q", out)
	}
	if !strings.Contains(out, "AllClean") {
		t.Errorf("expected status in stdout, got: %q", out)
	}
}

// TestPrintVulnScanResult_JSONOnStdout verifies that --json emits parseable
// JSON on stdout and not a human-readable summary.
func TestPrintVulnScanResult_JSONOnStdout(t *testing.T) {
	run := vuldomain.WalkScanRun{
		ID:            "run-003",
		OverallStatus: vuldomain.WalkStatusAffected,
	}

	var stdout bytes.Buffer
	if err := printVulnScanResult(run, nil, nil, nil, true, &stdout); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	out := stdout.String()
	if strings.Contains(out, "Scan completed") {
		t.Errorf("JSON mode must not emit human-readable summary, got: %q", out)
	}

	var decoded vuldomain.WalkScanRun
	if err := json.Unmarshal([]byte(out), &decoded); err != nil {
		t.Fatalf("stdout is not valid JSON: %v\noutput: %q", err, out)
	}
	if decoded.ID != run.ID {
		t.Errorf("decoded.ID = %q, want %q", decoded.ID, run.ID)
	}
}

// TestVulnScanProgressToStderr verifies that progress output (per-module lines,
// Unscannable/ScanFailed reasons) goes to stderr and NOT to stdout.
func TestVulnScanProgressToStderr(t *testing.T) {
	coord := mustVulnCoord(t, "example.com/pkg", "v1.0.0")

	cases := []struct {
		name   string
		record vuldomain.VulnerabilityRecord
	}{
		{
			name: "unscannable",
			record: vuldomain.VulnerabilityRecord{
				Coordinate:        coord,
				OverallStatus:     vuldomain.StatusUnscannable,
				UnscannableReason: "Windows-only package: not buildable on Linux",
			},
		},
		{
			name: "scan failed",
			record: vuldomain.VulnerabilityRecord{
				Coordinate:    coord,
				OverallStatus: vuldomain.StatusScanFailed,
				ErrorDetail:   "govulncheck: exit status 1",
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var stdout, stderr strings.Builder
			// Reproduce the Progress callback wiring from runVulnScan.
			writeVulnScanProgress(tc.record, coord, 1, 1, &stderr)

			if stdout.Len() != 0 {
				t.Errorf("progress wrote to stdout; want only stderr. stdout: %q", stdout.String())
			}
			if stderr.Len() == 0 {
				t.Errorf("expected progress on stderr, got nothing")
			}
		})
	}
}

// TestVulnScanProgress_OutOfToolchainReadsAsExpected verifies that an
// out-of-toolchain module (version-not-in-toolchain) renders as an
// informational metadata-only outcome, while a genuine Unscannable failure keeps
// its own label. The per-module line carries the label and nothing else: the
// explanation and the direction are properties of the reason, not the module,
// and are printed once per run by the roll-up.
func TestVulnScanProgress_OutOfToolchainReadsAsExpected(t *testing.T) {
	coord := mustVulnCoord(t, "example.com/pkg", "v1.0.0")

	t.Run("out of toolchain is expected, not a failure", func(t *testing.T) {
		rec := vuldomain.VulnerabilityRecord{
			Coordinate:        coord,
			OverallStatus:     vuldomain.StatusUnscannable,
			UnscanReason:      vuldomain.UnscanReasonVersionNotInToolchain,
			UnscannableReason: "source analysis unavailable: requires a module version outside the analysed project toolchain",
		}
		var stderr strings.Builder
		writeVulnScanProgress(rec, coord, 1, 1, &stderr)
		out := stderr.String()

		if !strings.Contains(out, "Metadata-only (version not in project build)") {
			t.Errorf("expected metadata-only label, got: %q", out)
		}
		if strings.Contains(out, "— Unscannable") {
			t.Errorf("out-of-toolchain line must not read as a bare Unscannable failure, got: %q", out)
		}
	})

	t.Run("another reason is named, not left bare, and keeps its own presentation", func(t *testing.T) {
		rec := vuldomain.VulnerabilityRecord{
			Coordinate:        coord,
			OverallStatus:     vuldomain.StatusUnscannable,
			UnscanReason:      vuldomain.UnscanReasonWindowsOnly,
			UnscannableReason: "Windows-only package: not buildable on Linux",
		}
		var stderr strings.Builder
		writeVulnScanProgress(rec, coord, 1, 1, &stderr)
		out := stderr.String()

		if !strings.Contains(out, "Metadata-only (builds on Windows only)") {
			t.Errorf("windows-only must render its own label, got: %q", out)
		}
		if strings.Contains(out, "— Unscannable") {
			t.Errorf("a mapped reason must not render as a bare Unscannable, got: %q", out)
		}
		if strings.Contains(out, "Metadata-only (version not in project build)") {
			t.Errorf("this reason must not borrow the out-of-toolchain label, got: %q", out)
		}
	})
}

// TestVulnScanProgress_SharedTextIsNotRepeatedPerModule pins the fix for the
// repetition defect: on a walk where many modules carry the same Unscannable
// reason, the explanation, the direction and the scanner's free-text reason are
// identical for every one of them, so the per-module stream must not carry them
// at all. What the stream keeps is the part that varies — the counter and the
// status label — because removing those would trade noise for silence.
func TestVulnScanProgress_SharedTextIsNotRepeatedPerModule(t *testing.T) {
	const modules = 40

	var stream strings.Builder
	rollup := newUnscannableRollup()
	for i := 0; i < modules; i++ {
		coord := mustVulnCoord(t, fmt.Sprintf("example.com/mod%d", i), "v1.0.0")
		rec := vuldomain.VulnerabilityRecord{
			Coordinate:        coord,
			OverallStatus:     vuldomain.StatusUnscannable,
			UnscanReason:      vuldomain.UnscanReasonNoGoMod,
			UnscannableReason: "no go.mod found in module zip",
		}
		writeVulnScanProgress(rec, coord, i+1, modules, &stream)
		rollup.add(rec.UnscanReason, coord.String(), rec.UnscannableReason)
	}

	streamed := stream.String()
	if n := strings.Count(streamed, "no go.mod found in module zip"); n != 0 {
		t.Errorf("shared scanner reason appears %d times in the per-module stream, want 0; got:\n%s", n, streamed)
	}
	if n := strings.Count(streamed, "Metadata-only (module zip has no go.mod"); n != modules {
		t.Errorf("per-module status label appears %d times, want %d (one per module)", n, modules)
	}
	if n := strings.Count(streamed, "\n"); n != modules {
		t.Errorf("per-module stream is %d lines, want exactly %d (one per module):\n%s", n, modules, streamed)
	}

	var summary strings.Builder
	writeUnscannableRollup(rollup, &summary)
	if n := strings.Count(summary.String(), "no go.mod found in module zip"); n != 1 {
		t.Errorf("shared scanner reason appears %d times in the roll-up, want exactly 1; got:\n%s", n, summary.String())
	}
	if !strings.Contains(summary.String(), fmt.Sprintf("(%d modules)", modules)) {
		t.Errorf("roll-up must say how many modules shared the reason; got:\n%s", summary.String())
	}
}

// TestVulnScanProgress_OutOfToolchainExplanationIsOncePerRun is the same rule
// for the reason that carries both an explanation and a direction: 116 modules
// produced 116 identical explanation lines and 117 identical hint lines, which
// is the condition under which the one real fault in the same stream is missed.
func TestVulnScanProgress_OutOfToolchainExplanationIsOncePerRun(t *testing.T) {
	const modules = 25

	var stream strings.Builder
	rollup := newUnscannableRollup()
	for i := 0; i < modules; i++ {
		coord := mustVulnCoord(t, fmt.Sprintf("example.com/mod%d", i), "v1.0.0")
		rec := vuldomain.VulnerabilityRecord{
			Coordinate:        coord,
			OverallStatus:     vuldomain.StatusUnscannable,
			UnscanReason:      vuldomain.UnscanReasonVersionNotInToolchain,
			UnscannableReason: "source analysis unavailable: requires a module version outside the analysed project toolchain",
		}
		writeVulnScanProgress(rec, coord, i+1, modules, &stream)
		rollup.add(rec.UnscanReason, coord.String(), rec.UnscannableReason)
	}

	if n := strings.Count(stream.String(), reachabilityLocalHint); n != 0 {
		t.Errorf("direction appears %d times in the per-module stream, want 0", n)
	}
	if n := strings.Count(stream.String(), "advisories matched, reachability not computed here"); n != 0 {
		t.Errorf("explanation appears %d times in the per-module stream, want 0", n)
	}

	var summary strings.Builder
	writeUnscannableRollup(rollup, &summary)
	got := summary.String()
	if n := strings.Count(got, reachabilityLocalHint); n != 1 {
		t.Errorf("direction appears %d times in the roll-up, want exactly 1; got:\n%s", n, got)
	}
	if n := strings.Count(got, "advisories matched, reachability not computed here"); n != 1 {
		t.Errorf("explanation appears %d times in the roll-up, want exactly 1; got:\n%s", n, got)
	}
	if !strings.Contains(got, fmt.Sprintf("version not in project build (%d):", modules)) {
		t.Errorf("roll-up heading must carry the count; got:\n%s", got)
	}
	// The curated explanation supersedes the scanner's own wording of the same
	// category; printing both would put the redundancy back one level up.
	if strings.Contains(got, "source analysis unavailable: requires a module version") {
		t.Errorf("scanner free text must not restate the curated explanation; got:\n%s", got)
	}
}

// TestUnscannableRollup_DistinctDetailsAllSurvive guards the other side of the
// dedup: collapsing repeated text must not collapse text that genuinely differs,
// or a per-module scanner message would be lost rather than merely de-repeated.
func TestUnscannableRollup_DistinctDetailsAllSurvive(t *testing.T) {
	r := newUnscannableRollup()
	r.add(vuldomain.UnscanReasonBuildIncompatible, "example.com/a@v1.0.0", "undefined: syscall.Mount")
	r.add(vuldomain.UnscanReasonBuildIncompatible, "example.com/b@v1.0.0", "undefined: syscall.Mount")
	r.add(vuldomain.UnscanReasonBuildIncompatible, "example.com/c@v1.0.0", "cannot find package foo")

	var out strings.Builder
	writeUnscannableRollup(r, &out)
	got := out.String()

	if !strings.Contains(got, "reason: undefined: syscall.Mount (2 modules)") {
		t.Errorf("repeated detail must be counted, not repeated; got:\n%s", got)
	}
	if !strings.Contains(got, "reason: cannot find package foo\n") {
		t.Errorf("a distinct detail must survive the roll-up; got:\n%s", got)
	}
	if strings.Contains(got, "cannot find package foo (") {
		t.Errorf("a single-module detail must not carry a count; got:\n%s", got)
	}
}

// ---- test helpers -------------------------------------------------------

func mustVulnCoord(t *testing.T, path, version string) coordinate.ModuleCoordinate {
	t.Helper()
	c, err := coordinate.NewModuleCoordinate(path, version)
	if err != nil {
		t.Fatalf("NewModuleCoordinate(%q, %q): %v", path, version, err)
	}
	return c
}

const (
	fixtureWalkID = "01JWALKFIXTURE000000000001"
	fixtureScanID = "01JSCANRUN0000000000000001"
)

var fixtureSnap = vuldomain.DatabaseSnapshot{
	Source:      "govulndb",
	Version:     "v2025-01-01T00-00-00",
	RetrievedAt: time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC),
	ContentHash: "sha256:fixture",
}

func fixtureRunAndRec(t *testing.T) (vuldomain.WalkScanRun, vuldomain.VulnerabilityRecord) {
	t.Helper()
	app := mustVulnCoord(t, "example.com/app", "v1.0.0")
	scannedAt := time.Date(2025, 1, 1, 12, 0, 0, 0, time.UTC)

	vulnRec := vuldomain.VulnerabilityRecord{
		Coordinate:       app,
		WalkID:           fixtureWalkID,
		OverallStatus:    vuldomain.StatusAffected,
		DatabaseSnapshot: fixtureSnap,
		Findings: []vuldomain.VulnerabilityFinding{
			{
				ID:            "GO-2025-0001",
				Aliases:       []string{"CVE-2025-0001"},
				Summary:       "example vulnerability",
				AffectedRange: "<v1.1.0",
				FixedIn:       "v1.1.0",
				PublishedAt:   scannedAt,
				ModifiedAt:    scannedAt,
			},
		},
		ScannedAt:       scannedAt,
		PipelineVersion: "v1",
		ContentHash:     "sha256:vulnrec",
	}

	run := vuldomain.WalkScanRun{
		ID:       fixtureScanID,
		WalkID:   fixtureWalkID,
		Snapshot: fixtureSnap,
		PerModuleResults: map[coordinate.ModuleCoordinate]string{
			app: vulnRec.ContentHash,
		},
		StartedAt:       scannedAt,
		CompletedAt:     scannedAt.Add(time.Second),
		OverallStatus:   vuldomain.WalkStatusAffected,
		PipelineVersion: "v1",
		Operator:        "test",
		ContentHash:     "sha256:run1",
	}
	return run, vulnRec
}

// ---- runScanList --------------------------------------------------------

func TestRunScanList_WithResults(t *testing.T) {
	run, _ := fixtureRunAndRec(t)
	uc := testfakes.NewFakeQueryScanRuns()
	uc.AddRun(run)

	var buf bytes.Buffer
	if err := runScanList(context.Background(), fixtureWalkID, 50, uc, &buf); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, fixtureScanID) {
		t.Errorf("expected scan run ID in output, got: %q", out)
	}
	if !strings.Contains(out, "Affected") {
		t.Errorf("expected 'Affected' in output, got: %q", out)
	}
}

func TestRunScanList_AllRuns(t *testing.T) {
	run, _ := fixtureRunAndRec(t)
	uc := testfakes.NewFakeQueryScanRuns()
	uc.AddRun(run)

	var buf bytes.Buffer
	if err := runScanList(context.Background(), "", 50, uc, &buf); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(buf.String(), fixtureScanID) {
		t.Errorf("expected scan run ID in output, got: %q", buf.String())
	}
}

func TestRunScanList_UnknownWalk(t *testing.T) {
	uc := testfakes.NewFakeQueryScanRuns()

	var buf bytes.Buffer
	if err := runScanList(context.Background(), "DOESNOTEXIST", 50, uc, &buf); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(buf.String(), "no scan runs found") {
		t.Errorf("expected 'no scan runs found', got: %q", buf.String())
	}
}

// ---- resolveSnapshot ----------------------------------------------------

func TestResolveSnapshot_Found(t *testing.T) {
	uc := testfakes.NewFakeQueryScanRuns()
	want := vuldomain.DatabaseSnapshot{
		Source:      "osv",
		Version:     "2026-05-07T19:21:40Z",
		RetrievedAt: time.Date(2026, 5, 7, 19, 21, 40, 0, time.UTC),
		ContentHash: "sha256:deadbeef",
	}
	uc.AddSnapshot(vuldomain.DatabaseSnapshot{Source: "osv", Version: "2026-01-01T00:00:00Z"})
	uc.AddSnapshot(want)

	got, found, err := resolveSnapshot(context.Background(), uc, "osv", "2026-05-07T19:21:40Z")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !found {
		t.Fatal("expected snapshot to be found")
	}
	if got != want {
		t.Errorf("got %+v, want %+v", got, want)
	}
}

func TestResolveSnapshot_NotFound(t *testing.T) {
	uc := testfakes.NewFakeQueryScanRuns()
	uc.AddSnapshot(vuldomain.DatabaseSnapshot{Source: "osv", Version: "2026-01-01T00:00:00Z"})

	got, found, err := resolveSnapshot(context.Background(), uc, "osv", "nonexistent")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if found {
		t.Errorf("expected not found, got %+v", got)
	}
}

func TestResolveSnapshot_EmptyStore(t *testing.T) {
	uc := testfakes.NewFakeQueryScanRuns()

	_, found, err := resolveSnapshot(context.Background(), uc, "osv", "v1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if found {
		t.Error("expected not found for empty snapshot store")
	}
}

func TestResolveSnapshot_ListError(t *testing.T) {
	uc := testfakes.NewFakeQueryScanRuns()
	uc.ListErr = errors.New("boom")

	_, found, err := resolveSnapshot(context.Background(), uc, "osv", "v1")
	if err == nil {
		t.Fatal("expected error when ListSnapshots fails")
	}
	if found {
		t.Error("expected found=false on error")
	}
	if !strings.Contains(err.Error(), "listing snapshots") {
		t.Errorf("expected wrapped 'listing snapshots' error, got: %v", err)
	}
	if !errors.Is(err, uc.ListErr) {
		t.Errorf("expected wrapped sentinel via errors.Is, got: %v", err)
	}
}

// ---- runScanRescan ------------------------------------------------------

// runScanRescan validates that --snapshot-source and --snapshot-version are
// supplied together; this guard runs before any store is opened, so it is
// unit-testable without a container. (The post-validation rescan path goes
// through NewContainer and is exercised by the txtar integration fixtures.)
func TestRunScanRescan_SnapshotFlagsMustBePaired(t *testing.T) {
	cases := []struct {
		name    string
		source  string
		version string
	}{
		{"source without version", "osv", ""},
		{"version without source", "", "2026-05-07T19:21:40Z"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			err := runScanRescan(
				context.Background(), "01KQDBVW092ER1HNXZ60X27CMD",
				commonWalkFlags{}, false, "", "tester",
				tc.source, tc.version, &stdout, &stderr,
			)
			if err == nil {
				t.Fatal("expected error for unpaired snapshot flags")
			}
			if !strings.Contains(err.Error(), "must be provided together") {
				t.Errorf("expected pairing error, got: %v", err)
			}
			if stdout.Len() != 0 {
				t.Errorf("expected no stdout before validation fails, got: %q", stdout.String())
			}
		})
	}
}

// ---- runScanShow --------------------------------------------------------

func TestRunScanShow_TextOutput(t *testing.T) {
	run, vulnRec := fixtureRunAndRec(t)
	app := mustVulnCoord(t, "example.com/app", "v1.0.0")

	ucRuns := testfakes.NewFakeQueryScanRuns()
	ucRuns.AddRun(run)

	ucVuln := testfakes.NewFakeQueryVuln()
	ucVuln.AddRecord(app, vulnRec)

	var buf bytes.Buffer
	if err := runScanShow(context.Background(), fixtureScanID, false, ucRuns, ucVuln, &buf); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	out := buf.String()
	for _, want := range []string{fixtureScanID, fixtureWalkID, "Affected", "Operator"} {
		if !strings.Contains(out, want) {
			t.Errorf("expected %q in output, got: %q", want, out)
		}
	}
}

func TestRunScanShow_NotFound(t *testing.T) {
	ucRuns := testfakes.NewFakeQueryScanRuns()
	ucVuln := testfakes.NewFakeQueryVuln()

	var buf bytes.Buffer
	err := runScanShow(context.Background(), "DOESNOTEXIST", false, ucRuns, ucVuln, &buf)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !strings.Contains(err.Error(), "scan run not found") {
		t.Errorf("expected 'scan run not found' in error, got: %v", err)
	}
}

// ---- runVulnShow --------------------------------------------------------

func TestRunVulnShow_WithWalkID(t *testing.T) {
	_, vulnRec := fixtureRunAndRec(t)
	app := mustVulnCoord(t, "example.com/app", "v1.0.0")

	uc := testfakes.NewFakeQueryVuln()
	uc.AddRecord(app, vulnRec)

	var buf bytes.Buffer
	if err := runVulnShow(context.Background(), "example.com/app@v1.0.0", fixtureWalkID, false, false, uc, &buf); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, "example.com/app@v1.0.0") {
		t.Errorf("expected coord in output, got: %q", out)
	}
	if !strings.Contains(out, "Affected") {
		t.Errorf("expected 'Affected' in output, got: %q", out)
	}
}

func TestRunVulnShow_NoWalkID(t *testing.T) {
	_, vulnRec := fixtureRunAndRec(t)
	app := mustVulnCoord(t, "example.com/app", "v1.0.0")

	uc := testfakes.NewFakeQueryVuln()
	uc.AddRecord(app, vulnRec)

	var buf bytes.Buffer
	if err := runVulnShow(context.Background(), "example.com/app@v1.0.0", "", false, false, uc, &buf); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(buf.String(), "example.com/app@v1.0.0") {
		t.Errorf("expected coord in output, got: %q", buf.String())
	}
}

// TestRunVulnShow_SurfacesRemediation verifies vuln-show renders the affected
// range, the at-risk symbol, and an explicit "no fix available" line for an
// unpatched finding — never a blank where the remediation answer belongs.
func TestRunVulnShow_SurfacesRemediation(t *testing.T) {
	app := mustVulnCoord(t, "github.com/gorilla/csrf", "v1.7.3")
	scannedAt := time.Date(2025, 6, 1, 0, 0, 0, 0, time.UTC)
	rec := vuldomain.VulnerabilityRecord{
		Ecosystem:     fetchdomain.EcosystemGo,
		Coordinate:    app,
		OverallStatus: vuldomain.StatusAffected,
		Findings: []vuldomain.VulnerabilityFinding{{
			ID:              "GO-2025-3884",
			Summary:         "CSRF bypass",
			AffectedRange:   ">= v1.7.3",
			AffectedSymbols: []string{"TrustedOrigins"},
			PublishedAt:     scannedAt,
		}},
		ScannedAt:       scannedAt,
		PipelineVersion: vulnPipelineVersion,
	}
	uc := testfakes.NewFakeQueryVuln()
	uc.AddRecord(app, rec)

	var buf bytes.Buffer
	if err := runVulnShow(context.Background(), "github.com/gorilla/csrf@v1.7.3", "", false, false, uc, &buf); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	out := buf.String()
	for _, want := range []string{">= v1.7.3", "no fix available", "TrustedOrigins"} {
		if !strings.Contains(out, want) {
			t.Errorf("expected %q in output, got:\n%s", want, out)
		}
	}
}

// TestRunVulnShow_FixedVersionRendered verifies a patched advisory renders its
// fixed version rather than the no-fix line.
func TestRunVulnShow_FixedVersionRendered(t *testing.T) {
	app := mustVulnCoord(t, "github.com/foo/bar", "v1.0.0")
	rec := vuldomain.VulnerabilityRecord{
		Ecosystem:     fetchdomain.EcosystemGo,
		Coordinate:    app,
		OverallStatus: vuldomain.StatusAffected,
		Findings: []vuldomain.VulnerabilityFinding{{
			ID:            "GO-2024-0042",
			Summary:       "patched issue",
			AffectedRange: "< v1.2.0",
			FixedIn:       "v1.2.0",
		}},
		PipelineVersion: vulnPipelineVersion,
	}
	uc := testfakes.NewFakeQueryVuln()
	uc.AddRecord(app, rec)

	var buf bytes.Buffer
	if err := runVulnShow(context.Background(), "github.com/foo/bar@v1.0.0", "", false, false, uc, &buf); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, "fixed in v1.2.0") {
		t.Errorf("expected 'fixed in v1.2.0' in output, got:\n%s", out)
	}
	if strings.Contains(out, "no fix available") {
		t.Errorf("unexpected no-fix line for patched advisory:\n%s", out)
	}
}

func TestRunVulnShow_NotFound(t *testing.T) {
	uc := testfakes.NewFakeQueryVuln()

	var buf bytes.Buffer
	err := runVulnShow(context.Background(), "example.com/missing@v9.9.9", "", false, false, uc, &buf)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !strings.Contains(err.Error(), "no vulnerability record") {
		t.Errorf("expected 'no vulnerability record' in error, got: %v", err)
	}
}

// ---- runVulnByID --------------------------------------------------------

func TestRunVulnByID_WithResults(t *testing.T) {
	app := mustVulnCoord(t, "example.com/app", "v1.0.0")
	scannedAt := time.Date(2025, 1, 1, 12, 0, 0, 0, time.UTC)
	rec := vuldomain.VulnerabilityRecord{
		Coordinate:       app,
		WalkID:           fixtureWalkID,
		OverallStatus:    vuldomain.StatusAffected,
		DatabaseSnapshot: fixtureSnap,
		Findings: []vuldomain.VulnerabilityFinding{
			{ID: "GO-2025-0001", Summary: "example vulnerability", PublishedAt: scannedAt, ModifiedAt: scannedAt},
		},
		ScannedAt:       scannedAt,
		PipelineVersion: "v1",
	}

	uc := testfakes.NewFakeQueryVuln()
	uc.SetByID([]vuldomain.VulnerabilityRecord{rec})

	var buf bytes.Buffer
	if err := runVulnByID(context.Background(), "GO-2025-0001", false, uc, &buf); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(buf.String(), "example.com/app@v1.0.0") {
		t.Errorf("expected coord in output, got: %q", buf.String())
	}
}

func TestRunVulnByID_NoResults(t *testing.T) {
	uc := testfakes.NewFakeQueryVuln()

	var buf bytes.Buffer
	if err := runVulnByID(context.Background(), "GO-9999-9999", false, uc, &buf); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(buf.String(), "no modules affected") {
		t.Errorf("expected 'no modules affected', got: %q", buf.String())
	}
}

// ---- runSnapshotList ----------------------------------------------------

func TestRunSnapshotList_WithResults(t *testing.T) {
	uc := testfakes.NewFakeQueryScanRuns()
	uc.AddSnapshot(fixtureSnap)

	var buf bytes.Buffer
	if err := runSnapshotList(context.Background(), false, uc, &buf); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, "govulndb") {
		t.Errorf("expected 'govulndb' in output, got: %q", out)
	}
	if !strings.Contains(out, "v2025-01-01T00-00-00") {
		t.Errorf("expected version in output, got: %q", out)
	}
}

func TestRunSnapshotList_Empty(t *testing.T) {
	uc := testfakes.NewFakeQueryScanRuns()

	var buf bytes.Buffer
	if err := runSnapshotList(context.Background(), false, uc, &buf); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(buf.String(), "no snapshots found") {
		t.Errorf("expected 'no snapshots found', got: %q", buf.String())
	}
}

// ---- runSnapshotShow ----------------------------------------------------

func TestRunSnapshotShow_Found(t *testing.T) {
	uc := testfakes.NewFakeQueryScanRuns()
	uc.AddSnapshot(fixtureSnap)

	var buf bytes.Buffer
	if err := runSnapshotShow(context.Background(), "govulndb", "v2025-01-01T00-00-00", false, uc, &buf); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, "govulndb") {
		t.Errorf("expected source in output, got: %q", out)
	}
	if !strings.Contains(out, "v2025-01-01T00-00-00") {
		t.Errorf("expected version in output, got: %q", out)
	}
}

func TestRunSnapshotShow_NotFound(t *testing.T) {
	uc := testfakes.NewFakeQueryScanRuns()

	var buf bytes.Buffer
	err := runSnapshotShow(context.Background(), "govulndb", "v9999-01-01T00-00-00", false, uc, &buf)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !strings.Contains(err.Error(), "snapshot not found") {
		t.Errorf("expected 'snapshot not found' in error, got: %v", err)
	}
}

// ---- runScanHistory -----------------------------------------------------

func TestRunScanHistory_WithResults(t *testing.T) {
	run, _ := fixtureRunAndRec(t)
	uc := testfakes.NewFakeQueryScanRuns()
	uc.AddRun(run)

	var buf bytes.Buffer
	if err := runScanHistory(context.Background(), fixtureWalkID, false, uc, &buf); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, "RUN ID") {
		t.Errorf("expected 'RUN ID' header in output, got: %q", out)
	}
	if !strings.Contains(out, fixtureScanID) {
		t.Errorf("expected scan run ID in output, got: %q", out)
	}
}

func TestRunScanHistory_NoRuns(t *testing.T) {
	uc := testfakes.NewFakeQueryScanRuns()

	var buf bytes.Buffer
	if err := runScanHistory(context.Background(), "DOESNOTEXIST", false, uc, &buf); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(buf.String(), "no scan runs found") {
		t.Errorf("expected 'no scan runs found', got: %q", buf.String())
	}
}

// ---- runScanDiff --------------------------------------------------------

func TestRunScanDiff_Success(t *testing.T) {
	run, _ := fixtureRunAndRec(t)
	run2 := vuldomain.WalkScanRun{
		ID:               "01JSCANRUN0000000000000002",
		WalkID:           fixtureWalkID,
		Snapshot:         fixtureSnap,
		PerModuleResults: map[coordinate.ModuleCoordinate]string{},
		StartedAt:        time.Date(2025, 1, 1, 13, 0, 0, 0, time.UTC),
		CompletedAt:      time.Date(2025, 1, 1, 13, 0, 1, 0, time.UTC),
		OverallStatus:    vuldomain.WalkStatusAllClean,
		PipelineVersion:  "v1",
		Operator:         "test",
	}

	ucDiff := &testfakes.FakeDiffScanRuns{
		Result: vuldomain.ScanRunDiff{RunA: run, RunB: run2},
	}

	var buf bytes.Buffer
	if err := runScanDiff(context.Background(), fixtureScanID, run2.ID, false, ucDiff, &buf); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, "Diff:") {
		t.Errorf("expected 'Diff:' in output, got: %q", out)
	}
	if !strings.Contains(out, "Walk:") {
		t.Errorf("expected 'Walk:' in output, got: %q", out)
	}
}

func TestRunScanDiff_Error(t *testing.T) {
	ucDiff := &testfakes.FakeDiffScanRuns{
		Err: errors.New("run not found"),
	}

	var buf bytes.Buffer
	err := runScanDiff(context.Background(), "DOESNOTEXIST", "OTHER", false, ucDiff, &buf)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !strings.Contains(err.Error(), "computing scan diff") {
		t.Errorf("expected 'computing scan diff' in error, got: %v", err)
	}
}

// ---- runVulnShow ScanFailed fallback (from vuln_error_messages.txtar) ---

func TestRunVulnShow_ScanFailed(t *testing.T) {
	// Simulate: GetLatestRecordForWalk returns not-found,
	// but GetLatestRecord finds a ScanFailed record with ErrorDetail.
	app := mustVulnCoord(t, "example.com/failed", "v1.0.0")
	scannedAt := time.Date(2025, 1, 1, 12, 0, 0, 0, time.UTC)
	failedRec := vuldomain.VulnerabilityRecord{
		Coordinate:       app,
		WalkID:           "01JWALKPARTIAL00000000001",
		OverallStatus:    vuldomain.StatusScanFailed,
		DatabaseSnapshot: fixtureSnap,
		ErrorDetail:      "govulncheck failed: exit status 1",
		ScannedAt:        scannedAt,
		PipelineVersion:  "v1",
	}

	uc := testfakes.NewFakeQueryVuln()
	uc.AddRecord(app, failedRec)
	// Force GetLatestRecordForWalk to return not-found so the fallback path runs.
	uc.ForceLatestRecordForWalkNotFound = true

	var buf bytes.Buffer
	err := runVulnShow(context.Background(), "example.com/failed@v1.0.0",
		"01JWALKPARTIAL00000000001", false, false, uc, &buf)
	if err == nil {
		t.Fatal("expected error for ScanFailed fallback path, got nil")
	}
	if !strings.Contains(err.Error(), "govulncheck failed") {
		t.Errorf("expected error detail in error message, got: %v", err)
	}
}

// TestNewContainer_NoConcurrentDBLeak verifies that calling NewContainer
// ---- runVulnShowHistory -------------------------------------------------

func TestRunVulnShowHistory_Empty(t *testing.T) {
	uc := testfakes.NewFakeQueryVuln()
	coord := mustVulnCoord(t, "example.com/mod", "v1.0.0")
	var buf bytes.Buffer
	err := runVulnShowHistory(context.Background(), coord, false, uc, &buf)
	if err == nil {
		t.Fatal("expected error for empty history")
	}
	if !strings.Contains(err.Error(), "no vulnerability records") {
		t.Errorf("expected 'no vulnerability records' in error, got: %v", err)
	}
}

func TestRunVulnShowHistory_WithRecord_Text(t *testing.T) {
	_, vulnRec := fixtureRunAndRec(t)
	uc := testfakes.NewFakeQueryVuln()
	uc.AddRecord(vulnRec.Coordinate, vulnRec)
	var buf bytes.Buffer
	err := runVulnShowHistory(context.Background(), vulnRec.Coordinate, false, uc, &buf)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, "example.com/app@v1.0.0") {
		t.Errorf("expected coord in output, got: %q", out)
	}
	if !strings.Contains(out, "scan record") {
		t.Errorf("expected 'scan record' count in output, got: %q", out)
	}
}

func TestRunVulnShowHistory_JSON(t *testing.T) {
	_, vulnRec := fixtureRunAndRec(t)
	uc := testfakes.NewFakeQueryVuln()
	uc.AddRecord(vulnRec.Coordinate, vulnRec)
	var buf bytes.Buffer
	err := runVulnShowHistory(context.Background(), vulnRec.Coordinate, true, uc, &buf)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(buf.String(), `"overall_status"`) && !strings.Contains(buf.String(), `"OverallStatus"`) && !strings.Contains(buf.String(), `"coordinate"`) {
		t.Errorf("expected JSON output, got: %q", buf.String())
	}
}

// twice sequentially on the same store root does not leave a dangling DB
// connection that would cause SQLITE_BUSY on the second open.
func TestNewContainer_NoConcurrentDBLeak(t *testing.T) {
	storeRoot := t.TempDir()
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))

	for i := range 2 {
		ctr, cleanup, err := NewContainer(storeRoot, "", "", false, domain.DefaultConfig(), logger)
		if err != nil {
			t.Fatalf("iteration %d: NewContainer: %v", i, err)
		}
		if err := cleanup(); err != nil {
			t.Fatalf("iteration %d: cleanup: %v", i, err)
		}
		_ = ctr
	}
}

// ---- vuln-scan --tool --------------------------------------------------------

func TestVulnScanCmd_ToolAndArgMutuallyExclusive(t *testing.T) {
	var stdout, stderr bytes.Buffer
	err := Run([]string{"vuln-scan", "--tool", "01JWALKFIXTURE000000000001"}, &stdout, &stderr)
	if err == nil {
		t.Fatal("expected error when --tool and walk-id both provided")
	}
	if !strings.Contains(err.Error(), "mutually exclusive") {
		t.Errorf("expected 'mutually exclusive' in error, got: %v", err)
	}
}

func TestVulnScanCmd_ToolAndModuleMutuallyExclusive(t *testing.T) {
	var stdout, stderr bytes.Buffer
	err := Run([]string{"vuln-scan", "--tool", "--module", "github.com/foo/bar@v1.0.0"}, &stdout, &stderr)
	if err == nil {
		t.Fatal("expected error when --tool and --module both provided")
	}
	if !strings.Contains(err.Error(), "mutually exclusive") {
		t.Errorf("expected 'mutually exclusive' in error, got: %v", err)
	}
}

func TestVulnScanCmd_ToolNoGomodFound(t *testing.T) {
	orig, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	if err := os.Chdir(dir); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = os.Chdir(orig) }()

	var stdout, stderr bytes.Buffer
	runErr := Run([]string{"vuln-scan", "--tool"}, &stdout, &stderr)
	if runErr == nil {
		t.Fatal("expected error when no go.mod present")
	}
	if !strings.Contains(runErr.Error(), "not found") {
		t.Errorf("expected 'not found' in error, got: %v", runErr)
	}
}

// A tool-scoped scan with no prior tool-scoped project walk fails loudly with a
// suggestion to run the walk first, rather than silently reporting nothing.
func TestVulnScanCmd_ToolNoWalkFound(t *testing.T) {
	dir := t.TempDir()
	storeDir := t.TempDir()
	gomod := "module example.com/myapp\n\ngo 1.24\n"
	gomodPath := filepath.Join(dir, "go.mod")
	if err := os.WriteFile(gomodPath, []byte(gomod), 0o600); err != nil {
		t.Fatal(err)
	}

	var stdout, stderr bytes.Buffer
	err := Run([]string{"vuln-scan", "--tool", "--gomod", gomodPath, "--store-root", storeDir}, &stdout, &stderr)
	if err == nil {
		t.Fatal("expected error when no tool-scoped project walk exists")
	}
	if !strings.Contains(err.Error(), "no succeeded tool project walk") {
		t.Errorf("expected 'no succeeded tool project walk' in error, got: %v", err)
	}
	if !strings.Contains(err.Error(), "walk --gomod") || !strings.Contains(err.Error(), "--tool") {
		t.Errorf("expected a 'walk --gomod ... --tool' suggestion in error, got: %v", err)
	}
}

// TestVulnScanRescan_DeprecatedRegateAlias verifies the rescan command still
// accepts the old 'vuln-scan-regate' name so existing scripts keep working
// after the rename.
func TestVulnScanRescan_DeprecatedRegateAlias(t *testing.T) {
	var stdout, stderr bytes.Buffer
	cmd := newVulnScanRescanCmd(&stdout, &stderr)

	if cmd.Name() != "vuln-scan-rescan" {
		t.Errorf("expected command name 'vuln-scan-rescan', got %q", cmd.Name())
	}
	if !cmd.HasAlias("vuln-scan-regate") {
		t.Errorf("expected deprecated alias 'vuln-scan-regate', aliases: %v", cmd.Aliases)
	}
}
