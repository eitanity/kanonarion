package childproc

import (
	"errors"
	"fmt"
	"testing"
)

// fakeExit is what an *exec.ExitError looks like to ExitedPartial.
type fakeExit struct{ code int }

func (f fakeExit) Error() string { return fmt.Sprintf("exit status %d", f.code) }
func (f fakeExit) ExitCode() int { return f.code }

// A kanonarion child says "I finished, and my answer is incomplete" with exit 1.
// A parent that spawns one classifies the record the child wrote; reading the
// code as an execution fault discards a stored answer.
func TestExitedPartial_OnlyTheIncompleteExitCounts(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name string
		err  error
		want bool
	}{
		{"no error at all", nil, false},
		{"partial", fakeExit{1}, true},
		{"partial, wrapped", fmt.Errorf("spawning child: %w", fakeExit{1}), true},
		{"no graph produced", fakeExit{2}, false},
		{"cancelled", fakeExit{3}, false},
		{"killed by the kernel", fakeExit{137}, false},
		{"not an exit at all", errors.New("context deadline exceeded"), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := ExitedPartial(tc.err); got != tc.want {
				t.Errorf("ExitedPartial(%v) = %v, want %v", tc.err, got, tc.want)
			}
		})
	}
}

// A child too old to read the source exits 20 after writing its record; only
// that refusal, read off its stderr, is read as a record to classify.
func TestExitedAnalyserLimit_OnlyTheLimitRefusalCounts(t *testing.T) {
	t.Parallel()
	limit := []byte("error: example.com/m@v1.0.0: Partial — this kanonarion cannot read this code: " +
		"it was built with go1.26 and the code requires go1.27. It type-checks source with the Go compiled into the binary")
	for _, tc := range []struct {
		name   string
		err    error
		stderr []byte
		want   bool
	}{
		{"limit refusal", fakeExit{20}, limit, true},
		{"limit refusal, wrapped", fmt.Errorf("spawning child: %w", fakeExit{20}), limit, true},
		{"a malformed invocation", fakeExit{20}, []byte("error: unknown flag --nope"), false},
		{"the statement under another code", fakeExit{2}, limit, false},
		{"no error at all", nil, limit, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := ExitedAnalyserLimit(tc.err, tc.stderr); got != tc.want {
				t.Errorf("ExitedAnalyserLimit(%v) = %v, want %v", tc.err, got, tc.want)
			}
		})
	}
}
