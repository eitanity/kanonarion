package cli

import (
	"fmt"
	"io"
	"strings"
)

// writeDerivation states where a run's derived answers came from.
//
// It is one block, in one shape, across every command that has an answer it
// might not have measured itself. The distinction it carries is the same
// everywhere: a stored record and a fresh measurement look identical in the
// output above it, and which one a reader is holding decides what the answer is
// worth — for a release note, for an incident, for "is this about the code in
// front of me". Each caller writes its own lines, because what was reused is its
// own business; the shape is shared so a reader learns it once.
func writeDerivation(w io.Writer, lines ...string) error {
	if len(lines) == 0 {
		return nil
	}
	if _, err := fmt.Fprintf(w, "derivation:\n  %s\n", strings.Join(lines, "\n  ")); err != nil {
		return fmt.Errorf("writing output: %w", err)
	}
	return nil
}
