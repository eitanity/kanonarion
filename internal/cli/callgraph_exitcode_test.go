package cli

import (
	"strings"
	"testing"

	cgdomain "github.com/eitanity/kanonarion/internal/callgraph/domain"
)

// TestCallGraphExtractionExit_FailedExtractionDoesNotReportSuccess is the
// regression for an extraction that printed LoadFailed and exited 0.
//
// Everything a script can branch on said the run had succeeded: a batch loop
// over a build list kept going, a make rule stayed green, and the only signal
// that nothing had been measured was prose on stdout. The record already carried
// the distinction; the exit code was not reading it.
func TestCallGraphExtractionExit_FailedExtractionDoesNotReportSuccess(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name      string
		status    cgdomain.CallGraphStatus
		zeroNodes bool
		want      int
	}{
		{"load failed", cgdomain.CallGraphStatusLoadFailed, false, ExitFailed},
		{"cancelled", cgdomain.CallGraphStatusCancelled, false, ExitCancelled},
		{"extracted", cgdomain.CallGraphStatusExtracted, false, ExitOK},
		// A Partial graph IS an answer, and 1 is the code for an answer that is
		// known-incomplete. It shared 0 with a complete graph, so nothing a script
		// reads distinguished a graph covering every package from one covering a
		// fraction of them.
		{"partial", cgdomain.CallGraphStatusPartial, false, ExitPartial},
		// Unless it carries nothing: the condition the code states is that a graph
		// exists, and a caller that keeps going has moved on from an extraction
		// which measured no function at all.
		{"partial with no nodes", cgdomain.CallGraphStatusPartial, true, ExitFailed},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			rec := makeCGRecord(t)
			rec.OverallStatus = tc.status
			rec.FailureDetail = "no package under example.com/cg"
			if tc.zeroNodes {
				rec.Nodes, rec.Edges, rec.NodeCount, rec.EdgeCount = nil, nil, 0, 0
			}

			err := callGraphExtractionExit(rec)
			if tc.want == ExitOK {
				if err != nil {
					t.Fatalf("status %s returned %v, want no error", tc.status, err)
				}
				return
			}
			if err == nil {
				t.Fatalf("status %s returned no error: a caller reading the exit code learns nothing went wrong", tc.status)
			}
			code, ok := ExitCodeFromError(err)
			if !ok {
				t.Fatalf("status %s returned an error carrying no exit code: %v", tc.status, err)
			}
			if code != tc.want {
				t.Errorf("exit code = %d, want %d", code, tc.want)
			}
			// The exit code says something went wrong; the message has to say what,
			// or the caller is back to reading stdout prose.
			if !strings.Contains(err.Error(), rec.FailureDetail) {
				t.Errorf("error does not carry the recorded failure detail: %v", err)
			}
		})
	}
}
