package cli

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
)

// A multi-phase command stops at the phase it was in once the run is
// interrupted, and carries on past a failed phase only while it is not.
func TestStopIfInterrupted(t *testing.T) {
	live := context.Background()
	if err := stopIfInterrupted(live, "extracting", errors.New("one module failed")); err != nil {
		t.Errorf("a live run must carry on past a failed phase; got %v", err)
	}
	stopped, cancel := context.WithCancel(context.Background())
	cancel()
	if err := stopIfInterrupted(stopped, "scanning", nil); !errors.Is(err, context.Canceled) || !strings.HasPrefix(err.Error(), "scanning: ") {
		t.Errorf("an interrupted run must stop even after a phase that returned no error; got %v", err)
	}
	phaseErr := fmt.Errorf("persisting run: %w", context.Canceled)
	if err := stopIfInterrupted(stopped, "extracting", phaseErr); !errors.Is(err, phaseErr) {
		t.Errorf("the phase's own error must be what the run reports; got %v", err)
	}
}

// A signal that lands after a command reached its answer stops nothing, so the
// answer's own exit code stands; an error the interruption caused does not.
func TestAnsweredDespite(t *testing.T) {
	for _, tc := range []struct {
		name string
		err  error
		want bool
	}{
		{"a partial answer", &exitError{code: ExitPartial, msg: "sbom generated with undetermined licences"}, true},
		{"a policy verdict", &exitError{code: ExitPolicy, msg: "blocked by policy"}, true},
		{"an absent record", &exitError{code: ExitNotFound, msg: "no walk"}, true},
		{"an integrity finding", &exitError{code: ExitIntegrity, msg: "hash mismatch"}, true},
		{"a write the cancellation stopped", fmt.Errorf("persisting record: %w", context.Canceled), false},
		{"a cancelled walk", &exitError{code: ExitCancelled, msg: "walk cancelled"}, false},
		{"work that could not complete", &exitError{code: ExitFailed, msg: "no graph"}, false},
		{"a plain consequence", errors.New("project walk produced no record"), false},
	} {
		if got := answeredDespite(tc.err); got != tc.want {
			t.Errorf("%s: answeredDespite = %v, want %v", tc.name, got, tc.want)
		}
	}
}
