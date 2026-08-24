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
