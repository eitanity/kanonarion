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

// TestHistoryFailure_KeepsTheSignalTheConflictCheckDropped.
//
// Composition no longer refuses when two generations of one artefact recorded
// different failures — their graphs agree, so no answer depends on the
// difference. That is the right call only if the difference stays visible: "two
// analyses of one module failed for different reasons" is worth knowing, and the
// history view is where the generations are read side by side. If this line goes
// away, dropping the refusal becomes dropping the signal.
func TestHistoryFailure_KeepsTheSignalTheConflictCheckDropped(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name   string
		record cgdomain.CallGraphRecord
		want   string
	}{
		{
			name:   "a clean generation says nothing about failing",
			record: cgdomain.CallGraphRecord{},
			want:   "",
		},
		{
			name: "cause and detail are both printed",
			record: cgdomain.CallGraphRecord{
				FailureCause:  cgdomain.FailureCauseEnvironment,
				FailureDetail: "go: module lookup disabled",
			},
			want: "    failure:  " + cgdomain.FailureCauseEnvironment.String() + ": go: module lookup disabled\n",
		},
		{
			name:   "a generation predating the cause axis still shows its detail",
			record: cgdomain.CallGraphRecord{FailureDetail: "no packages successfully loaded"},
			want:   "    failure:  no packages successfully loaded\n",
		},
		{
			name:   "a stated cause with no detail is not silent",
			record: cgdomain.CallGraphRecord{FailureCause: cgdomain.FailureCauseModule},
			want:   "    failure:  " + cgdomain.FailureCauseModule.String() + ": (no detail recorded)\n",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := historyFailure(tc.record); got != tc.want {
				t.Errorf("historyFailure = %q, want %q", got, tc.want)
			}
		})
	}
}
