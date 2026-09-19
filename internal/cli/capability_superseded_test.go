package cli

import (
	"bytes"
	"context"
	"strings"
	"testing"

	cgapp "github.com/eitanity/kanonarion/internal/callgraph/application"
	cgdomain "github.com/eitanity/kanonarion/internal/callgraph/domain"
	cgports "github.com/eitanity/kanonarion/internal/callgraph/ports"
	capapp "github.com/eitanity/kanonarion/internal/capability/application"
	"github.com/eitanity/kanonarion/internal/cli/testfakes"
	"github.com/eitanity/kanonarion/internal/coordinate"
	"github.com/eitanity/kanonarion/internal/coordinate/coordinatetest"
)

// noGenerations is a store that holds nothing for any coordinate: the state an
// absence refusal may actually assert.
type noGenerations struct{}

func (noGenerations) ListCallGraphCoordinates(context.Context, cgports.CallGraphFilter) ([]cgports.CallGraphCoordinate, error) {
	return nil, nil
}

// generationsAt is a store holding one coordinate at the named pipeline
// versions — the state a bare "no record" refusal contradicts.
type generationsAt struct {
	coord    coordinate.ModuleCoordinate
	pipeline []string
}

func (g generationsAt) ListCallGraphCoordinates(context.Context, cgports.CallGraphFilter) ([]cgports.CallGraphCoordinate, error) {
	out := make([]cgports.CallGraphCoordinate, 0, len(g.pipeline))
	for _, p := range g.pipeline {
		out = append(out, cgports.CallGraphCoordinate{
			ModulePath:      g.coord.Path(),
			ModuleVersion:   g.coord.Version(),
			PipelineVersion: p,
		})
	}
	return out, nil
}

// capability said the record did not exist while the store held two generations
// of it under superseded pipeline versions — an absence its own store
// contradicts, and one that leaves a reader no reason to suspect the pipeline
// bump that is the real answer. callgraph-show, reading the same rows, already
// named them. The diagnosis now comes from the store for both.
func TestRunCapability_SupersededRecordIsDiagnosedNotDenied(t *testing.T) {
	coord := coordinatetest.MustNew("example.com/mod", "v1.2.0")
	held := generationsAt{coord: coord, pipeline: []string{"0.5.0", "0.6.0"}}
	uc := fakeCapAnalyser{err: &capapp.NoCallGraphError{Coord: coord}}

	var buf bytes.Buffer
	err := runCapability(context.Background(), "example.com/mod@v1.2.0", uc, held, cgdomain.RootScopeProduction, false, &buf)
	if err == nil {
		t.Fatal("a missing call graph returned no error")
	}
	if got := ExitCodeForError(err); got != ExitNotFound {
		t.Errorf("exit code = %d, want %d: the code does not move, only the diagnosis", got, ExitNotFound)
	}
	msg := err.Error()
	for _, want := range []string{
		"at pipeline " + cgapp.PipelineVersion,
		"superseded pipeline 0.5.0, 0.6.0",
		"kanonarion callgraph example.com/mod@v1.2.0",
	} {
		if !strings.Contains(msg, want) {
			t.Errorf("refusal does not state %q:\n%s", want, msg)
		}
	}

	// Word for word what callgraph-show says from the same rows: two spellings of
	// one refusal read as two conditions.
	showErr := missingCallGraphRefusal(context.Background(), coord, held)
	if showErr.Error() != msg {
		t.Errorf("capability and callgraph-show disagree about one store:\n capability:     %s\n callgraph-show: %s", msg, showErr.Error())
	}
}

// The other half of the rule, and the one that stops the fix from over-reaching:
// a coordinate the store has never held is genuinely absent, so the refusal says
// so and names no pipeline version at all.
func TestRunCapability_NeverHeldCoordinateNamesNoPipeline(t *testing.T) {
	coord := coordinatetest.MustNew("example.com/mod", "v1.2.0")
	uc := fakeCapAnalyser{err: &capapp.NoCallGraphError{Coord: coord}}

	var buf bytes.Buffer
	err := runCapability(context.Background(), "example.com/mod@v1.2.0", uc, noGenerations{}, cgdomain.RootScopeProduction, false, &buf)
	if err == nil {
		t.Fatal("a missing call graph returned no error")
	}
	if got := ExitCodeForError(err); got != ExitNotFound {
		t.Errorf("exit code = %d, want %d", got, ExitNotFound)
	}
	msg := err.Error()
	if strings.Contains(msg, "pipeline") || strings.Contains(msg, "superseded") {
		t.Errorf("a record nothing was ever stored for is described as superseded:\n%s", msg)
	}
	if !strings.Contains(msg, "kanonarion callgraph example.com/mod@v1.2.0") {
		t.Errorf("the remedy does not name the coordinate:\n%s", msg)
	}
}

// A diff reads two coordinates, and the side that missed is the one diagnosed.
func TestRunCapabilityDiff_SupersededSideIsTheOneDiagnosed(t *testing.T) {
	to := coordinatetest.MustNew("example.com/mod", "v2.0.0")
	held := generationsAt{coord: to, pipeline: []string{"0.6.0"}}
	uc := fakeCapAnalyser{err: &capapp.NoCallGraphError{Coord: to}}

	var buf bytes.Buffer
	err := runCapabilityDiff(context.Background(), "example.com/mod@v1.0.0", "example.com/mod@v2.0.0",
		uc, held, cgdomain.RootScopeProduction, false, &buf)
	if err == nil {
		t.Fatal("a missing call graph returned no error")
	}
	msg := err.Error()
	if !strings.Contains(msg, "superseded pipeline 0.6.0") {
		t.Errorf("the refusal does not name what the store holds:\n%s", msg)
	}
	if !strings.Contains(msg, "kanonarion callgraph example.com/mod@v2.0.0") {
		t.Errorf("the remedy names a side other than the one that missed:\n%s", msg)
	}
}

// diffWithNoHistory is a store that serves no generation at the pipeline version
// this build reads, and holds rows for the coordinate under an older one.
type diffWithNoHistory struct {
	*testfakes.FakeQueryCallGraph
	held generationsAt
}

func (d *diffWithNoHistory) ListCallGraphCoordinates(ctx context.Context, f cgports.CallGraphFilter) ([]cgports.CallGraphCoordinate, error) {
	return d.held.ListCallGraphCoordinates(ctx, f)
}

// callgraph-show --diff asks the same question of the same ledger, so it gets
// the same answer: a coordinate held only under a superseded pipeline version
// is diagnosed rather than reported as one the store has never analysed.
func TestCallGraphDiff_SupersededCoordinateIsDiagnosed(t *testing.T) {
	coord := coordinatetest.MustNew("example.com/mod", "v1.2.0")
	uc := &diffWithNoHistory{
		FakeQueryCallGraph: &testfakes.FakeQueryCallGraph{},
		held:               generationsAt{coord: coord, pipeline: []string{"0.6.0"}},
	}

	var buf bytes.Buffer
	err := runCallGraphDiff(context.Background(), coord, callGraphShowFlags{diff: true}, false, uc, &buf)
	if err == nil {
		t.Fatal("a coordinate with no servable generation returned no error")
	}
	if got := ExitCodeForError(err); got != ExitNotFound {
		t.Errorf("exit code = %d, want %d", got, ExitNotFound)
	}
	if !strings.Contains(err.Error(), "superseded pipeline 0.6.0") {
		t.Errorf("the refusal does not name what the store holds:\n%s", err.Error())
	}
}
