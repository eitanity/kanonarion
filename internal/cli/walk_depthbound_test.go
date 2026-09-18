package cli

import (
	"context"
	"io"
	"strings"
	"testing"

	"github.com/eitanity/kanonarion/internal/cli/testfakes"
	"github.com/eitanity/kanonarion/internal/coordinate"
	"github.com/eitanity/kanonarion/internal/coordinate/coordinatetest"
	walkapp "github.com/eitanity/kanonarion/internal/walk/application"
	walkdomain "github.com/eitanity/kanonarion/internal/walk/domain"
)

// partialWalkRecord is a partial walk of one target with a stated reason and a
// given number of failed nodes.
func partialWalkRecord(t *testing.T, reason string, failures int) walkdomain.WalkRecord {
	t.Helper()
	target := coordinatetest.MustNew("example.com/m", "v1.0.0")
	results := map[coordinate.ModuleCoordinate]walkdomain.NodeResult{
		target: {Coordinate: target, Status: walkdomain.NodeSucceeded},
	}
	for i := range failures {
		c := coordinatetest.MustNew("example.com/dep"+string(rune('a'+i)), "v1.0.0")
		results[c] = walkdomain.NodeResult{Coordinate: c, Status: walkdomain.NodeFetchFailed}
	}
	return walkdomain.WalkRecord{
		ID:             "W-1",
		Target:         target,
		OverallStatus:  walkdomain.WalkPartial,
		PerNodeResults: results,
		Graph:          walkdomain.Graph{Target: target, Partial: true, PartialReason: reason},
	}
}

// walkOf runs the coordinate walk over a fake use case and returns the refusal.
func walkOf(t *testing.T, rec walkdomain.WalkRecord) error {
	t.Helper()
	uc := &testfakes.FakeExecuteWalk{Result: walkapp.ExecuteWalkResult{Record: rec}}
	_, err := runWalk(context.Background(), "example.com/m@v1.0.0", commonWalkFlags{},
		false, false, 0, "", "", false,
		walkdomain.WalkScopeCode, walkdomain.WalkDepthFull, "", nil, uc, nil, io.Discard, io.Discard)
	return err
}

// The coordinate walk refused with "some dependencies could not be fetched" for
// every partial walk, whatever the record said it was partial FOR. The project
// walk stopped doing that when walkPartialMessage was written; this path never
// called it, so a walk truncated by a max_depth policy — where nothing was
// fetched and nothing failed — refused with a sentence about fetching.
func TestRunWalk_PartialMessageSaysWhatTheWalkIsPartialFor(t *testing.T) {
	t.Run("a depth bound names the bound", func(t *testing.T) {
		err := walkOf(t, partialWalkRecord(t, walkdomain.DepthBoundedReason(1), 0))
		requireExit(t, err, ExitPartial)
		if strings.Contains(err.Error(), "could not be fetched") {
			t.Errorf("refusal blames fetching; nothing was fetched for the truncated nodes: %v", err)
		}
		if !strings.Contains(err.Error(), walkdomain.DepthBoundedReason(1)) {
			t.Errorf("refusal does not quote the reason the record carries: %v", err)
		}
	})

	// The control. A walk that really did fail to fetch still says so, on the
	// same path and in the same words it always used.
	t.Run("a fetch failure keeps the sentence it always had", func(t *testing.T) {
		err := walkOf(t, partialWalkRecord(t, walkdomain.FetchFailedReason, 2))
		requireExit(t, err, ExitPartial)
		if !strings.Contains(err.Error(), "some dependencies could not be fetched") {
			t.Errorf("a walk with two failed fetches must say so: %v", err)
		}
	})

	// A reason nobody has written yet is quoted rather than described, which is
	// what keeps this from having to be fixed again for the next one.
	t.Run("an unforeseen reason is quoted", func(t *testing.T) {
		err := walkOf(t, partialWalkRecord(t, "some_future_reason: whatever it says", 0))
		requireExit(t, err, ExitPartial)
		if !strings.Contains(err.Error(), "some_future_reason: whatever it says") {
			t.Errorf("refusal does not quote the record's own reason: %v", err)
		}
	})
}
