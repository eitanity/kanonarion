package application_test

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"
	"testing"

	"code.eitanity.com/kanonarion/internal/coordinate"
	fetchdomain "code.eitanity.com/kanonarion/internal/fetch/domain"
	"code.eitanity.com/kanonarion/internal/fetch/fetchtest"

	"code.eitanity.com/kanonarion/internal/vuln/application"
	"code.eitanity.com/kanonarion/internal/vuln/domain"
)

const malformedModuleHash = "not-an-algorithm-value-pair"

// logLine is one captured JSON log line.
type logLine map[string]any

// captureLogs returns a debug-level JSON logger and a reader of what it wrote.
func captureLogs(t *testing.T) (*slog.Logger, func() []logLine) {
	t.Helper()
	var buf bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug}))
	return logger, func() []logLine {
		var out []logLine
		for raw := range strings.SplitSeq(strings.TrimSpace(buf.String()), "\n") {
			if raw == "" {
				continue
			}
			var l logLine
			if err := json.Unmarshal([]byte(raw), &l); err != nil {
				t.Fatalf("log line %q: %v", raw, err)
			}
			out = append(out, l)
		}
		return out
	}
}

// linesAt returns the captured lines at level whose message contains msg.
func linesAt(lines []logLine, level, msg string) []logLine {
	var out []logLine
	for _, l := range lines {
		if l["level"] == level && strings.Contains(fmt.Sprint(l["msg"]), msg) {
			out = append(out, l)
		}
	}
	return out
}

// malformedTargetFixture seeds the target's fact record with a module hash
// that does not parse. served decides how the store answers for it: composed,
// as every production store does, or handed back raw through the fault seam.
func malformedTargetFixture(t *testing.T, logger *slog.Logger, scanner *fakeScanner, raw bool) targetScanFixture {
	t.Helper()
	f := newLoggedTargetScanFixture(t, logger, scanner)
	f.markAllVulnerable()
	opts := []fetchtest.Option{
		fetchtest.Coordinate(f.target),
		fetchtest.PipelineVersion("v1"),
		fetchtest.Content("zip-" + f.target.Path()),
		func(r *fetchdomain.FactRecord) { r.ModuleHash = malformedModuleHash },
	}
	if raw {
		f.facts.uncomposed = map[coordinate.ModuleCoordinate]fetchdomain.FactRecord{f.target: fetchtest.Record(t, opts...)}
		return f
	}
	if err := f.facts.PutFetchRecord(t.Context(), fetchtest.Sealed(t, opts...)); err != nil {
		t.Fatalf("PutFetchRecord: %v", err)
	}
	return f
}

// assertTargetFailedNamingTheHash checks the target's answer is a ScanFailed
// that states the parse error, never a clean verdict.
func assertTargetFailedNamingTheHash(t *testing.T, f targetScanFixture) {
	t.Helper()
	rec, ok, err := f.vulnStore.GetLatestVulnerabilityRecordForWalk(t.Context(), f.target, "v1", f.walkID)
	if err != nil || !ok {
		t.Fatalf("target record: ok=%v err=%v", ok, err)
	}
	if rec.OverallStatus != domain.StatusScanFailed {
		t.Errorf("target status = %v, want ScanFailed", rec.OverallStatus)
	}
	if !strings.Contains(rec.ErrorDetail, malformedModuleHash) {
		t.Errorf("target ErrorDetail = %q, want it to name the parse error", rec.ErrorDetail)
	}
}

// A record served whole whose module hash does not parse is a corrupt record,
// never a target with no zip. The target-rooted scan states that at warn with
// the error, falls back, and the isolated scan of the target fails closed on
// the same record.
func TestScanWalk_CoordinateKeyed_MalformedTargetHashIsStatedNotReportedAsNoZip(t *testing.T) {
	logger, logs := captureLogs(t)
	scanner := &fakeScanner{targetRooted: true}
	f := malformedTargetFixture(t, logger, scanner, true)

	if _, err := f.walkUC.Scan(t.Context(), application.ScanWalkParams{WalkID: f.walkID, Operator: "tester"}); err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if scanner.targetCalls != 0 {
		t.Errorf("target-rooted scan attempted on an underivable zip address; calls = %d", scanner.targetCalls)
	}

	lines := logs()
	warns := linesAt(lines, "WARN", "carries a module hash that does not parse, falling back to isolated scans")
	if len(warns) != 1 {
		t.Fatalf("warn lines naming the unparseable hash = %d, want 1; logs: %v", len(warns), lines)
	}
	if got := fmt.Sprint(warns[0]["error"]); !strings.Contains(got, malformedModuleHash) {
		t.Errorf("warn error = %q, want the parse error naming %q", got, malformedModuleHash)
	}
	if got := fmt.Sprint(warns[0]["target"]); got != f.target.String() {
		t.Errorf("warn target = %q, want %q", got, f.target)
	}
	if n := len(linesAt(lines, "INFO", "names no module zip")); n != 0 {
		t.Errorf("the malformed hash was also reported as no zip (%d lines)", n)
	}
	assertTargetFailedNamingTheHash(t, f)
}

// Through a composing store, which is every production store, the same record
// is refused at the read itself: the warn names the read failure and its parse
// error, and the target's answer is the same ScanFailed.
func TestScanWalk_CoordinateKeyed_MalformedTargetHashRefusedByTheComposedRead(t *testing.T) {
	logger, logs := captureLogs(t)
	scanner := &fakeScanner{targetRooted: true}
	f := malformedTargetFixture(t, logger, scanner, false)

	if _, err := f.walkUC.Scan(t.Context(), application.ScanWalkParams{WalkID: f.walkID, Operator: "tester"}); err != nil {
		t.Fatalf("Scan: %v", err)
	}
	lines := logs()
	warns := linesAt(lines, "WARN", "could not read the target's fetch record, falling back to isolated scans")
	if len(warns) != 1 {
		t.Fatalf("warn lines naming the refused read = %d, want 1; logs: %v", len(warns), lines)
	}
	if got := fmt.Sprint(warns[0]["error"]); !strings.Contains(got, malformedModuleHash) {
		t.Errorf("warn error = %q, want the parse error naming %q", got, malformedModuleHash)
	}
	if n := len(linesAt(lines, "INFO", "no module zip")) + len(linesAt(lines, "INFO", "has no source")); n != 0 {
		t.Errorf("the malformed hash was reported as an absence (%d lines)", n)
	}
	assertTargetFailedNamingTheHash(t, f)
}

// Control: a go.mod-only target keeps its Info "no source" line and logs
// nothing at warn from the target-rooted path.
func TestScanWalk_CoordinateKeyed_GoModOnlyTargetLogsNoSourceAtInfoOnly(t *testing.T) {
	ctx := t.Context()
	logger, logs := captureLogs(t)
	scanner := &fakeScanner{targetRooted: true}
	f := newLoggedTargetScanFixture(t, logger, scanner)
	f.markAllVulnerable()

	if err := f.facts.PutFetchRecord(ctx, fetchtest.Sealed(t,
		fetchtest.Coordinate(f.target),
		fetchtest.PipelineVersion("v1"),
		fetchtest.GoMod("gomod-only-handle"),
	)); err != nil {
		t.Fatalf("PutFetchRecord: %v", err)
	}

	if _, err := f.walkUC.Scan(ctx, application.ScanWalkParams{WalkID: f.walkID, Operator: "tester"}); err != nil {
		t.Fatalf("Scan: %v", err)
	}
	lines := logs()
	if n := len(linesAt(lines, "INFO", "target module has no source in the blob store")); n != 1 {
		t.Errorf("info no-source lines = %d, want 1; logs: %v", n, lines)
	}
	if n := len(linesAt(lines, "WARN", "target-rooted scan")); n != 0 {
		t.Errorf("target-rooted warn lines = %d, want 0 for a go.mod-only target; logs: %v", n, lines)
	}
}

// assertStepWarns checks every warn line names the step and carries an error
// containing wantErr, and that there is at least one.
func assertStepWarns(t *testing.T, warns []logLine, wantStep, wantErr string) {
	t.Helper()
	if len(warns) == 0 {
		t.Fatal("no warn line for the unreadable go.mod")
	}
	for _, w := range warns {
		if w["step"] != wantStep {
			t.Errorf("warn step = %v, want %q", w["step"], wantStep)
		}
		if e := fmt.Sprint(w["error"]); !strings.Contains(e, wantErr) {
			t.Errorf("warn error = %q, want it to contain %q", e, wantErr)
		}
	}
}
