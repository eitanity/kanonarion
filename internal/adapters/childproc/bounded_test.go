package childproc

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

const testPrefix = "callgraph progress: "

// TestRunBounded_KillsAChildThatStopsReportingProgress is the whole point of the
// two deadlines.
//
// The child is CONSTRUCTED to stall rather than waited for: no observed run has
// produced a real hang, so a green run over a subject that never stalls proves
// nothing. This one reports twice and then sits forever, which is exactly the
// shape a wedged type-checker has.
func TestRunBounded_KillsAChildThatStopsReportingProgress(t *testing.T) {
	t.Parallel()
	var narration bytes.Buffer
	b := Bounds{
		Stall:          300 * time.Millisecond,
		Ceiling:        30 * time.Second,
		ProgressPrefix: testPrefix,
		Progress:       &narration,
	}

	start := time.Now()
	stderr, err := RunBounded(t.Context(), b, "/bin/sh", "-c",
		`echo "`+testPrefix+`loading" >&2; echo "`+testPrefix+`building" >&2; sleep 30`)
	elapsed := time.Since(start)

	if !errors.Is(err, ErrStalled) {
		t.Fatalf("err = %v, want ErrStalled", err)
	}
	// Within the stall window rather than at the ceiling: the whole distinction
	// is that a stalled subprocess ends on silence, not on elapsed time.
	if elapsed > 5*time.Second {
		t.Errorf("the stalled subprocess took %s to end; the stall window is %s and the ceiling %s",
			elapsed, b.Stall, b.Ceiling)
	}
	if errors.Is(err, ErrCeiling) {
		t.Error("a stalled child must not be reported as having reached the ceiling")
	}
	if got := narration.String(); !strings.Contains(got, "building") {
		t.Errorf("the operator saw %q; the phases the parent decided on must reach them", got)
	}
	if strings.Contains(string(stderr), testPrefix) {
		t.Errorf("progress lines must not be kept as failure detail, got %q", stderr)
	}
}

// TestRunBounded_LetsASlowButWorkingChildFinish is the control the wall-clock
// deadline could not pass: a child that keeps reporting runs for longer than any
// single stall window and is not killed.
//
// This is the measured defect in miniature. The module that failed needed seven
// minutes of a ten-minute cap and was killed under a busy pool; under a stall
// detector the same child, descheduled or not, keeps saying it moved on.
func TestRunBounded_LetsASlowButWorkingChildFinish(t *testing.T) {
	t.Parallel()
	b := Bounds{
		Stall:          400 * time.Millisecond,
		Ceiling:        30 * time.Second,
		ProgressPrefix: testPrefix,
	}

	// Runs for about a second: two and a half stall windows, none of them silent.
	_, err := RunBounded(t.Context(), b, "/bin/sh", "-c",
		`for i in 1 2 3 4 5 6 7 8 9 10; do echo "`+testPrefix+`step $i" >&2; sleep 0.1; done`)
	if err != nil {
		t.Fatalf("a subprocess that never stopped reporting was stopped: %v", err)
	}
}

// TestRunBounded_CeilingHoldsOverAChildThatNeverStops is the backstop: progress
// forever is still bounded, and it is reported as the ceiling rather than as a
// stall, because a reader acts on the two differently — one needs a bigger
// number, the other needs a diagnosis.
func TestRunBounded_CeilingHoldsOverAChildThatNeverStops(t *testing.T) {
	t.Parallel()
	b := Bounds{
		Stall:          10 * time.Second,
		Ceiling:        400 * time.Millisecond,
		ProgressPrefix: testPrefix,
	}
	_, err := RunBounded(t.Context(), b, "/bin/sh", "-c",
		`while true; do echo "`+testPrefix+`still here" >&2; sleep 0.05; done`)
	if !errors.Is(err, ErrCeiling) {
		t.Fatalf("err = %v, want ErrCeiling", err)
	}
	if errors.Is(err, ErrStalled) {
		t.Error("a child that kept reporting must not be reported as stalled")
	}
}

// TestRunBounded_CallersCancellationIsNotADeadline keeps the two apart: a run the
// operator interrupted is not a module that could not be analysed, and it must
// not be filed as either deadline.
func TestRunBounded_CallersCancellationIsNotADeadline(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithCancel(t.Context())
	go func() {
		time.Sleep(100 * time.Millisecond)
		cancel()
	}()
	b := Bounds{Stall: 10 * time.Second, Ceiling: 10 * time.Second, ProgressPrefix: testPrefix}
	_, err := RunBounded(ctx, b, "/bin/sleep", "30")
	if err == nil {
		t.Fatal("expected an error from the killed child")
	}
	if errors.Is(err, ErrStalled) || errors.Is(err, ErrCeiling) {
		t.Errorf("cancellation reported as a deadline: %v", err)
	}
}

// TestRunBounded_KeepsDiagnosticsAndDropsNarration pins the split. The child's
// account of what went wrong is what a failed stage carries; twenty progress
// lines in the same field would bury it.
func TestRunBounded_KeepsDiagnosticsAndDropsNarration(t *testing.T) {
	t.Parallel()
	var narration bytes.Buffer
	b := Bounds{Stall: 10 * time.Second, Ceiling: 10 * time.Second, ProgressPrefix: testPrefix, Progress: &narration}
	stderr, err := RunBounded(t.Context(), b, "/bin/sh", "-c",
		`echo "`+testPrefix+`loading" >&2; echo "panic: nil map" >&2; printf 'unterminated tail' >&2; exit 2`)
	if err == nil {
		t.Fatal("expected a non-zero exit")
	}
	got := string(stderr)
	if !strings.Contains(got, "panic: nil map") {
		t.Errorf("diagnostics lost: %q", got)
	}
	if !strings.Contains(got, "unterminated tail") {
		t.Errorf("a subprocess stopped mid-sentence still said something: %q", got)
	}
	if strings.Contains(got, "loading") {
		t.Errorf("narration kept as diagnostics: %q", got)
	}
	if !strings.Contains(narration.String(), "loading") {
		t.Errorf("narration lost: %q", narration.String())
	}
}

// TestRunBounded_NoStallWindowLeavesTheCeilingAlone covers the zero value: a
// caller that sets no stall window gets the ceiling and nothing else, rather
// than a detector that fires immediately.
func TestRunBounded_NoStallWindowLeavesTheCeilingAlone(t *testing.T) {
	t.Parallel()
	b := Bounds{Ceiling: 5 * time.Second}
	if _, err := RunBounded(t.Context(), b, "/bin/sh", "-c", "sleep 0.2"); err != nil {
		t.Fatalf("unbounded-by-stall child failed: %v", err)
	}
}
