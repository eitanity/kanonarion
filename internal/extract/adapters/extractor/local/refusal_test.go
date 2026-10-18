package local

import (
	"errors"
	"strings"
	"testing"

	"github.com/eitanity/kanonarion/internal/coordinate/coordinatetest"
	fetchports "github.com/eitanity/kanonarion/internal/fetch/ports"
)

// A call-graph child that refused a stored artefact as altered exited with the
// integrity code and said so; the stage returns the refusal as an error, so the
// run stops on it, and only that exit with that line does so.
func TestExtractCallgraph_AChildsRefusalIsTheStagesError(t *testing.T) {
	coord := coordinatetest.MustNew("example.com/mod", "v1.0.0")
	line := "error: execute root command: stored artefact zip:h1:x= " + fetchports.BlobTamperedMarker + " (observed h1:y=): re-fetch"
	refusing := &fakeSubprocessExecutor{
		stderr: []byte("phase: materialising\n" + line + "\n"),
		err:    fakeExitStatus{code: 10},
	}
	_, err := newCallgraphAdapter(refusing, extractedOutcome()).Extract(t.Context(), coord, "callgraph", false, "")
	if !errors.Is(err, fetchports.ErrBlobTampered) || !strings.HasSuffix(err.Error(), line) {
		t.Fatalf("Extract err = %v, want the refusal carrying the child's line", err)
	}

	for name, exec := range map[string]*fakeSubprocessExecutor{
		"integrity exit without a refusal": {stderr: []byte("two analyses disagree\n"), err: fakeExitStatus{code: 10}},
		"refusal text on another exit":     {stderr: []byte(line + "\n"), err: fakeExitStatus{code: 2}},
	} {
		res, err := newCallgraphAdapter(exec, extractedOutcome()).Extract(t.Context(), coord, "callgraph", false, "")
		if err != nil || res.Error == "" {
			t.Errorf("%s: res %+v, err %v; want a failed stage as before", name, res, err)
		}
	}
}
