package cli

import (
	"strings"
	"testing"

	cgdomain "github.com/eitanity/kanonarion/internal/callgraph/domain"
	"github.com/eitanity/kanonarion/internal/coordinate"
)

// A composed call-graph read that refuses is refusing permanently: the ledger is
// append-only, so nothing the reader does to the stored rows makes the refusal go
// away, and a message with no exit leaves the caller to guess at --force. Guessing
// at --force is exactly what a caller should not do, so every conflict prints
// what to run instead — and every line it prints is parsed here, because advice
// the CLI itself rejects costs the caller the round trip the advice existed to
// save.
func TestCallGraphConflictRemedies_EveryLineIsAcceptedByTheParser(t *testing.T) {
	coord, err := coordinate.NewModuleCoordinate("github.com/Masterminds/sprig", "v2.22.0+incompatible")
	if err != nil {
		t.Fatalf("NewModuleCoordinate: %v", err)
	}
	fields := cgdomain.ConflictFields()
	if len(fields) == 0 {
		t.Fatal("no conflict fields enumerated")
	}
	for _, field := range fields {
		conflict := cgdomain.CallGraphConflict{Coordinate: coord, PipelineVersion: "0.3.0", Field: field}
		remedy := conflict.Remedy()
		if len(remedy.Lines) == 0 {
			t.Errorf("conflict field %q prints no invocation", field)
		}
		for _, line := range remedy.Lines {
			if err := parseInvocation(t, line); err != nil {
				t.Errorf("remedy line %q for %q is rejected by the CLI's own parser: %v", line, field, err)
			}
		}
		// The refusal a caller actually sees is the error string, so the check is on
		// that rather than on the remedy in isolation.
		for _, line := range remedy.Lines {
			if !strings.Contains(conflict.Error(), "\n  "+line) {
				t.Errorf("the refusal for %q does not print %q on its own line:\n%s", field, line, conflict.Error())
			}
		}
	}
}
