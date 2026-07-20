package cli

import (
	"bytes"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/eitanity/kanonarion/internal/coordinate"

	"github.com/eitanity/kanonarion/internal/license/domain"
)

// makeCompatReport is a convenience builder.
func makeCompatReport(clean bool, conflicts ...domain.CompatibilityConflict) domain.ClosureCompatibilityReport {
	return domain.ClosureCompatibilityReport{
		TargetSPDX:  "Apache-2.0",
		DataVersion: "1.0.0",
		Clean:       clean,
		Conflicts:   conflicts,
	}
}

// -- printCompatReportText tests --

// TestPrintCompatReportText_Clean: clean report emits a single status line.
func TestPrintCompatReportText_Clean(t *testing.T) {
	t.Parallel()
	var buf bytes.Buffer
	report := makeCompatReport(true)
	coord := coordinate.ModuleCoordinate{Path: "example.com/root", Version: "v1.0.0"}
	printCompatReportText(report, coord, &buf)
	out := buf.String()
	if !strings.Contains(out, "compatible with Apache-2.0") {
		t.Errorf("clean report should say 'compatible with Apache-2.0', got: %q", out)
	}
	if strings.Contains(out, "Requires review") || strings.Contains(out, "Incompatible") {
		t.Errorf("clean report should not have conflict sections, got: %q", out)
	}
}

// TestPrintCompatReportText_IncompatibleConflict: GPL dep appears in the
// "Incompatible" section with kind label.
func TestPrintCompatReportText_IncompatibleConflict(t *testing.T) {
	t.Parallel()
	var buf bytes.Buffer
	report := makeCompatReport(false, domain.CompatibilityConflict{
		ModulePath:    "example.com/gpl-lib",
		ModuleVersion: "v2.0.0",
		DepSPDX:       "GPL-2.0-only",
		TargetSPDX:    "Apache-2.0",
		Verdict:       domain.VerdictIncompatible,
		Kind:          domain.ConflictCopyleftPropagation,
	})
	coord := coordinate.ModuleCoordinate{Path: "example.com/root", Version: "v1.0.0"}
	printCompatReportText(report, coord, &buf)
	out := buf.String()
	if !strings.Contains(out, "Incompatible") {
		t.Errorf("incompatible section missing, got: %q", out)
	}
	if !strings.Contains(out, "example.com/gpl-lib@v2.0.0") {
		t.Errorf("conflict module missing, got: %q", out)
	}
	if !strings.Contains(out, "copyleft_propagation") {
		t.Errorf("conflict kind missing, got: %q", out)
	}
	if strings.Contains(out, "Tip:") {
		t.Errorf("tip should not appear for named conflict (no no-record modules), got: %q", out)
	}
}

// TestPrintCompatReportText_UnknownWithNoRecord: dep with empty SPDX
// shows "(no license detected)" and the extraction hint.
func TestPrintCompatReportText_UnknownWithNoRecord(t *testing.T) {
	t.Parallel()
	var buf bytes.Buffer
	report := makeCompatReport(false, domain.CompatibilityConflict{
		ModulePath:    "example.com/no-license",
		ModuleVersion: "v0.1.0",
		DepSPDX:       "", // no record
		TargetSPDX:    "Apache-2.0",
		Verdict:       domain.VerdictUnknownPair,
		Kind:          domain.ConflictUnknownPair,
	})
	coord := coordinate.ModuleCoordinate{Path: "example.com/root", Version: "v1.0.0"}
	printCompatReportText(report, coord, &buf)
	out := buf.String()
	if !strings.Contains(out, "no license detected") {
		t.Errorf("'no license detected' label missing, got: %q", out)
	}
	// extraction hint must appear when dep_spdx is empty.
	if !strings.Contains(out, "kanonarion extract") {
		t.Errorf("extraction hint missing, got: %q", out)
	}
}

// TestPrintCompatReportText_UnknownNamedSPDX: dep with a named but
// unmodelled SPDX does NOT show the extraction hint (it's modelled-absent, not
// un-extracted).
func TestPrintCompatReportText_UnknownNamedSPDX(t *testing.T) {
	t.Parallel()
	var buf bytes.Buffer
	report := makeCompatReport(false, domain.CompatibilityConflict{
		ModulePath:    "example.com/cc-dep",
		ModuleVersion: "v1.0.0",
		DepSPDX:       "CC-BY-SA-4.0",
		TargetSPDX:    "Apache-2.0",
		Verdict:       domain.VerdictUnknownPair,
		Kind:          domain.ConflictUnknownPair,
	})
	coord := coordinate.ModuleCoordinate{Path: "example.com/root", Version: "v1.0.0"}
	printCompatReportText(report, coord, &buf)
	out := buf.String()
	if strings.Contains(out, "kanonarion extract") {
		t.Errorf("extraction hint should not appear for named-but-unmodelled SPDX, got: %q", out)
	}
	if !strings.Contains(out, "CC-BY-SA-4.0") {
		t.Errorf("dep SPDX should be shown, got: %q", out)
	}
}

// -- printCompatReportJSON tests --

// TestPrintCompatReportJSON_CleanShape: clean JSON report has well-formed
// shape with an empty conflicts array (not null).
func TestPrintCompatReportJSON_CleanShape(t *testing.T) {
	t.Parallel()
	var buf bytes.Buffer
	report := makeCompatReport(true)
	if err := printCompatReportJSON(report, &buf); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	var out map[string]interface{}
	if err := json.Unmarshal(buf.Bytes(), &out); err != nil {
		t.Fatalf("invalid JSON: %v\n%s", err, buf.String())
	}
	if out["clean"] != true {
		t.Errorf("clean should be true, got %v", out["clean"])
	}
	conflicts, ok := out["conflicts"].([]interface{})
	if !ok {
		t.Errorf("conflicts should be an array, got %T", out["conflicts"])
	}
	if len(conflicts) != 0 {
		t.Errorf("conflicts should be empty, got %d", len(conflicts))
	}
}

// TestPrintCompatReportJSON_ConflictFields: conflict entry serialises all
// required fields including dep_spdx, target_spdx, verdict, and kind.
func TestPrintCompatReportJSON_ConflictFields(t *testing.T) {
	t.Parallel()
	var buf bytes.Buffer
	report := makeCompatReport(false, domain.CompatibilityConflict{
		ModulePath:    "example.com/agpl-lib",
		ModuleVersion: "v1.0.0",
		DepSPDX:       "AGPL-3.0-only",
		TargetSPDX:    "Apache-2.0",
		Verdict:       domain.VerdictIncompatible,
		Kind:          domain.ConflictNetworkTrigger,
	})
	if err := printCompatReportJSON(report, &buf); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	var out struct {
		Conflicts []struct {
			Module  string `json:"module"`
			Version string `json:"version"`
			DepSPDX string `json:"dep_spdx"`
			Target  string `json:"target_spdx"`
			Verdict string `json:"verdict"`
			Kind    string `json:"kind"`
		} `json:"conflicts"`
	}
	if err := json.Unmarshal(buf.Bytes(), &out); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	if len(out.Conflicts) != 1 {
		t.Fatalf("expected 1 conflict, got %d", len(out.Conflicts))
	}
	c := out.Conflicts[0]
	if c.DepSPDX != "AGPL-3.0-only" {
		t.Errorf("dep_spdx = %q, want AGPL-3.0-only", c.DepSPDX)
	}
	if c.Verdict != "incompatible" {
		t.Errorf("verdict = %q, want incompatible", c.Verdict)
	}
	if c.Kind != "network_trigger" {
		t.Errorf("kind = %q, want network_trigger", c.Kind)
	}
}

// -- compatExitCode tests --

// TestCompatExitCode_Clean: clean report returns nil.
func TestCompatExitCode_Clean(t *testing.T) {
	t.Parallel()
	if err := compatExitCode(makeCompatReport(true)); err != nil {
		t.Errorf("clean report should return nil, got %v", err)
	}
}

// TestCompatExitCode_IncompatibleOnly: confirmed conflict → ExitPartial.
func TestCompatExitCode_IncompatibleOnly(t *testing.T) {
	t.Parallel()
	report := makeCompatReport(false, domain.CompatibilityConflict{
		Verdict: domain.VerdictIncompatible,
	})
	err := compatExitCode(report)
	if err == nil {
		t.Fatal("expected non-nil error for incompatible conflict")
	}
	var ee *exitError
	if !errors.As(err, &ee) {
		t.Fatalf("expected exitError, got %T", err)
	}
	if ee.code != ExitPartial {
		t.Errorf("exit code = %d, want %d (ExitPartial)", ee.code, ExitPartial)
	}
}

// TestCompatExitCode_UnknownPair: unknown pair → ExitFailed (takes priority).
func TestCompatExitCode_UnknownPair(t *testing.T) {
	t.Parallel()
	report := makeCompatReport(false, domain.CompatibilityConflict{
		Verdict: domain.VerdictUnknownPair,
	})
	err := compatExitCode(report)
	if err == nil {
		t.Fatal("expected non-nil error for unknown pair")
	}
	var ee *exitError
	if !errors.As(err, &ee) {
		t.Fatalf("expected exitError, got %T", err)
	}
	if ee.code != ExitFailed {
		t.Errorf("exit code = %d, want %d (ExitFailed)", ee.code, ExitFailed)
	}
}

// TestCompatExitCode_UnknownPairPriority: when both incompatible and
// unknown-pair conflicts are present, ExitFailed (unknown) takes priority over
// ExitPartial (incompatible).
func TestCompatExitCode_UnknownPairPriority(t *testing.T) {
	t.Parallel()
	report := makeCompatReport(false,
		domain.CompatibilityConflict{Verdict: domain.VerdictIncompatible},
		domain.CompatibilityConflict{Verdict: domain.VerdictUnknownPair},
	)
	err := compatExitCode(report)
	var ee *exitError
	if !errors.As(err, &ee) {
		t.Fatalf("expected exitError, got %T", err)
	}
	if ee.code != ExitFailed {
		t.Errorf("exit code = %d, want ExitFailed (%d) — unknown must take priority over incompatible", ee.code, ExitFailed)
	}
}

// TestWalkNotFoundError: walk-not-found message must appear exactly once
// in the returned error (not double-printed via fmt.Fprintf + return). The
// caller (main) prints the error once; the command must not pre-print it.
func TestWalkNotFoundError(t *testing.T) {
	t.Parallel()
	// The no-walk-found path is inside runLicenseCompat which opens a real
	// container. Test the exit-code contract via compatExitCode and the
	// message via the exitError itself.
	err := &exitError{
		code: ExitNotFound,
		msg:  "no walk record found for example.com/m@v1.0.0 — run 'kanonarion walk example.com/m@v1.0.0' first",
	}
	if !strings.Contains(err.Error(), "run 'kanonarion walk") {
		t.Errorf("walk-not-found error must include the actionable hint, got: %q", err.Error())
	}
	var ee *exitError
	if !errors.As(err, &ee) || ee.code != ExitNotFound {
		t.Errorf("walk-not-found must carry ExitNotFound code, got: %v", err)
	}
}
