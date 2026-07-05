package cli

import (
	"bytes"
	"strings"
	"testing"

	fetchdomain "github.com/eitanity/kanonarion/internal/fetch/domain"

	domain "github.com/eitanity/kanonarion/internal/extract/domain"
)

func TestExtractListCmd_EmptyStore(t *testing.T) {
	dir := t.TempDir()
	var stdout, stderr bytes.Buffer
	err := Run([]string{"extract", "list", "--store-root", dir}, &stdout, &stderr)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	out := stdout.String()
	if !strings.Contains(out, "RUN ID") {
		t.Errorf("expected 'RUN ID' header, got: %q", out)
	}
	if !strings.Contains(out, "STATUS") {
		t.Errorf("expected 'STATUS' header, got: %q", out)
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
		PerModuleResults: map[fetchdomain.ModuleCoordinate]domain.ModuleExtractionResult{
			{Path: "example.com/mod", Version: "v1.0.0"}: {
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
		PerModuleResults: map[fetchdomain.ModuleCoordinate]domain.ModuleExtractionResult{
			{Path: "example.com/mod", Version: "v1.0.0"}: {
				Stages: map[string]domain.StageResult{
					"license":   {Status: domain.StageSucceeded},
					"callgraph": {Status: domain.StageFailed, Error: "analysis error"},
				},
			},
			{Path: "example.com/other", Version: "v2.0.0"}: {
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
		PerModuleResults: map[fetchdomain.ModuleCoordinate]domain.ModuleExtractionResult{
			{Path: "example.com/z", Version: "v1.0.0"}: {
				Stages: map[string]domain.StageResult{
					"license": {Status: domain.StageFailed},
				},
			},
			{Path: "example.com/a", Version: "v1.0.0"}: {
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
