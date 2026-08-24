package cli

import (
	"bytes"
	"strings"
	"testing"

	"github.com/eitanity/kanonarion/internal/coordinate"
	"github.com/eitanity/kanonarion/internal/coordinate/coordinatetest"

	domain "github.com/eitanity/kanonarion/internal/extract/domain"
)

func TestExtractListCmd_EmptyStore(t *testing.T) {
	dir := t.TempDir()
	var stdout, stderr bytes.Buffer
	err := Run([]string{"extract", "list", "--store-root", dir}, &stdout, &stderr)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// A header with no rows under it is not an answer, so an empty store gets
	// the zero-result statement in place of the table.
	out := stdout.String()
	if !strings.Contains(out, "the store holds no extraction run at all") {
		t.Errorf("expected the empty-store statement, got: %q", out)
	}
	if strings.Contains(out, "RUN ID") {
		t.Errorf("a listing with no rows must not print column headings, got: %q", out)
	}
}

func TestExtractShowCmd_NotFound(t *testing.T) {
	dir := t.TempDir()
	tests := []struct{ name, args string }{
		{"text", ""},
		{"json", "--json"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			args := []string{"extract", "show", "--store-root", dir}
			if tt.args != "" {
				args = append(args, tt.args)
			}
			args = append(args, "invalid-id")
			err := Run(args, &stdout, &stderr)
			if err == nil {
				t.Fatal("expected error for missing run ID")
			}
			if !strings.Contains(err.Error(), "not found") {
				t.Errorf("expected 'not found' in error, got: %v", err)
			}
		})
	}
}

// TestExtractCmd_StatusPreambleGoesToStderr asserts that the "Starting
// extraction…" status line is written to stderr, not stdout, so that
// `extract --json` produces a stdout stream that pipes cleanly to jq.
// Regression for the case where the preamble was written to stdout and
// broke pipelines that parsed the JSON body. The extraction itself will
// fail because the walk-id does not exist in the empty store, but the
// preamble runs before that failure, so stdout/stderr can still be
// asserted.
func TestExtractCmd_StatusPreambleGoesToStderr(t *testing.T) {
	dir := t.TempDir()
	for _, mode := range []string{"text", "json"} {
		t.Run(mode, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			args := []string{"extract", "--store-root", dir}
			if mode == "json" {
				args = append(args, "--json")
			}
			args = append(args, "01ARZ3NDEKTSV4RRFFQ69G5FAV") // non-existent walk
			_ = Run(args, &stdout, &stderr)

			if strings.Contains(stdout.String(), "Starting extraction") {
				t.Errorf("preamble leaked to stdout (breaks --json piping):\nstdout=%q", stdout.String())
			}
			if !strings.Contains(stderr.String(), "Starting extraction") {
				t.Errorf("preamble missing from stderr (interactive runs would be silent):\nstderr=%q", stderr.String())
			}
		})
	}
}

func TestPrintExtractionFailures_NoFailures(t *testing.T) {
	run := domain.ExtractionRun{
		PerModuleResults: map[coordinate.ModuleCoordinate]domain.ModuleExtractionResult{
			coordinatetest.MustNew("example.com/mod", "v1.0.0"): {
				Stages: map[string]domain.StageResult{
					"license": {Status: domain.StageSucceeded},
				},
			},
		},
	}
	var buf strings.Builder
	printExtractionFailures(&buf, run)
	if buf.Len() != 0 {
		t.Errorf("expected no output for all-succeeded run, got: %s", buf.String())
	}
}

func TestPrintExtractionFailures_WithFailures(t *testing.T) {
	run := domain.ExtractionRun{
		PerModuleResults: map[coordinate.ModuleCoordinate]domain.ModuleExtractionResult{
			coordinatetest.MustNew("example.com/mod", "v1.0.0"): {
				Stages: map[string]domain.StageResult{
					"license":   {Status: domain.StageSucceeded},
					"callgraph": {Status: domain.StageFailed, Error: "analysis error"},
				},
			},
			coordinatetest.MustNew("example.com/other", "v2.0.0"): {
				Stages: map[string]domain.StageResult{
					"interface": {Status: domain.StageFailed, Error: ""},
				},
			},
		},
	}
	var buf strings.Builder
	printExtractionFailures(&buf, run)
	got := buf.String()

	if !strings.Contains(got, "Failed stages (2):") {
		t.Errorf("expected failure count header, got:\n%s", got)
	}
	if !strings.Contains(got, "callgraph") {
		t.Errorf("expected callgraph stage in output, got:\n%s", got)
	}
	if !strings.Contains(got, "analysis error") {
		t.Errorf("expected error message in output, got:\n%s", got)
	}
	if !strings.Contains(got, "interface") {
		t.Errorf("expected interface stage in output, got:\n%s", got)
	}
}

func TestPrintExtractionFailures_SortedOutput(t *testing.T) {
	run := domain.ExtractionRun{
		PerModuleResults: map[coordinate.ModuleCoordinate]domain.ModuleExtractionResult{
			coordinatetest.MustNew("example.com/z", "v1.0.0"): {
				Stages: map[string]domain.StageResult{
					"license": {Status: domain.StageFailed},
				},
			},
			coordinatetest.MustNew("example.com/a", "v1.0.0"): {
				Stages: map[string]domain.StageResult{
					"license": {Status: domain.StageFailed},
				},
			},
		},
	}
	var buf strings.Builder
	printExtractionFailures(&buf, run)
	got := buf.String()

	aIdx := strings.Index(got, "example.com/a")
	zIdx := strings.Index(got, "example.com/z")
	if aIdx > zIdx {
		t.Errorf("output not sorted: example.com/a at %d, example.com/z at %d\ngot:\n%s", aIdx, zIdx, got)
	}
}

// An extraction run that recorded a failed stage must not exit 0. The stages
// that ran are stored and the breakdown names the rest, which is exit 1's
// meaning; a run reaching a CI step as a success left named modules' public API
// permanently unmeasured and nothing the step reads said so.
func TestExtractionExit_RecordedStatusReachesTheExitCode(t *testing.T) {
	t.Parallel()

	partial := func(status domain.ExtractionRunStatus) domain.ExtractionRun {
		return domain.ExtractionRun{
			ID:            "01EXTRACTRUN00000000000001",
			OverallStatus: status,
			PerModuleResults: map[coordinate.ModuleCoordinate]domain.ModuleExtractionResult{
				coordinatetest.MustNew("example.com/mod", "v1.0.0"): {
					Stages: map[string]domain.StageResult{
						"license":   {Status: domain.StageSucceeded},
						"interface": {Status: domain.StageFailed, Error: "conflicting interface records"},
					},
				},
			},
		}
	}

	cases := []struct {
		name   string
		status domain.ExtractionRunStatus
		want   int
	}{
		{"succeeded", domain.ExtractionRunSucceeded, ExitOK},
		{"partial", domain.ExtractionRunPartial, ExitPartial},
		{"failed", domain.ExtractionRunFailed, ExitFailed},
		{"cancelled", domain.ExtractionRunCancelled, ExitCancelled},
		// A status this build does not know is not a clean run. Falling through to
		// 0 is how a later enum member would quietly become a success.
		{"unrecognised future status", domain.ExtractionRunStatus(99), ExitPartial},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			err := extractionExit(partial(tc.status))
			if tc.want == ExitOK {
				if err != nil {
					t.Fatalf("status %s returned %v, want no error", tc.status, err)
				}
				return
			}
			if err == nil {
				t.Fatalf("status %s returned no error: a caller reading the exit code learns nothing", tc.status)
			}
			code, ok := ExitCodeFromError(err)
			if !ok {
				t.Fatalf("status %s returned an error carrying no exit code: %v", tc.status, err)
			}
			if code != tc.want {
				t.Errorf("exit code = %d, want %d (%v)", code, tc.want, err)
			}
		})
	}
}

// The document and the process must agree. `--json` already reported
// "overall_status": 1 while the process reported 0, so a caller that read the
// document and a caller that read the exit code got opposite answers about one
// run.
func TestRenderExtraction_JSONAndTextExitAlike(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name   string
		status domain.ExtractionRunStatus
		want   int
	}{
		{"partial", domain.ExtractionRunPartial, ExitPartial},
		{"succeeded", domain.ExtractionRunSucceeded, ExitOK},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			run := domain.ExtractionRun{
				SchemaVersion: domain.ExtractionRunSchemaVersion,
				ID:            "01EXTRACTRUN00000000000001",
				OverallStatus: tc.status,
				PerModuleResults: map[coordinate.ModuleCoordinate]domain.ModuleExtractionResult{
					coordinatetest.MustNew("example.com/mod", "v1.0.0"): {
						Stages: map[string]domain.StageResult{
							"interface": {Status: domain.StageFailed, Error: "boom"},
						},
					},
				},
			}
			var text, jsonBuf bytes.Buffer
			textErr := renderExtraction(run, false, &text)
			jsonErr := renderExtraction(run, true, &jsonBuf)

			textCode, jsonCode := ExitCodeForError(textErr), ExitCodeForError(jsonErr)
			if textCode != tc.want || jsonCode != tc.want {
				t.Errorf("exit codes: text=%d json=%d, want %d for both", textCode, jsonCode, tc.want)
			}
		})
	}
}

// The count and the pairs behind it come from one reading of the run, so the
// number inspect prints and the list it emits cannot disagree.
func TestExtractionFailures_NamesEveryFailedStage(t *testing.T) {
	t.Parallel()

	run := domain.ExtractionRun{
		OverallStatus: domain.ExtractionRunPartial,
		PerModuleResults: map[coordinate.ModuleCoordinate]domain.ModuleExtractionResult{
			coordinatetest.MustNew("example.com/z", "v1.0.0"): {
				Stages: map[string]domain.StageResult{
					"callgraph": {Status: domain.StageFailed, Error: "divergence"},
					"license":   {Status: domain.StageSucceeded},
				},
			},
			coordinatetest.MustNew("example.com/a", "v1.0.0"): {
				Stages: map[string]domain.StageResult{
					"interface": {Status: domain.StageFailed},
					"callgraph": {Status: domain.StageFailed},
				},
			},
		},
	}

	got := extractionFailures(run)
	if len(got) != 3 {
		t.Fatalf("failure count = %d, want 3; got %v", len(got), got)
	}
	want := []extractStageFailure{
		{Module: "example.com/a@v1.0.0", Stage: "callgraph"},
		{Module: "example.com/a@v1.0.0", Stage: "interface"},
		{Module: "example.com/z@v1.0.0", Stage: "callgraph", Error: "divergence"},
	}
	for i, w := range want {
		if got[i] != w {
			t.Errorf("failure %d = %+v, want %+v", i, got[i], w)
		}
	}
	// A clean run counts zero and names nothing, and the empty list must be a
	// list: a JSON consumer must not have to tell null from [].
	clean := domain.ExtractionRun{PerModuleResults: map[coordinate.ModuleCoordinate]domain.ModuleExtractionResult{
		coordinatetest.MustNew("example.com/mod", "v1.0.0"): {
			Stages: map[string]domain.StageResult{"license": {Status: domain.StageSucceeded}},
		},
	}}
	if cleanFailures := extractionFailures(clean); cleanFailures == nil || len(cleanFailures) != 0 {
		t.Errorf("clean run failures = %v, want an empty non-nil list", cleanFailures)
	}
}
