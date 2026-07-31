package cli

import (
	"context"
	"testing"
)

// TestGoToolchainVersionProbe_AnswersOnThisBox is the control for the seam: the
// real probe must succeed in an environment that can run the test suite at all,
// or every load failure would be classed as environmental and nothing would
// ever cache.
func TestGoToolchainVersionProbe_AnswersOnThisBox(t *testing.T) {
	if err := goToolchainVersionProbe(context.Background()); err != nil {
		t.Fatalf("the real toolchain probe failed in an environment running the test suite: %v", err)
	}
}
