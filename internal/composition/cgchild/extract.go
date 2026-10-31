// Package cgchild runs the call-graph child: the process extraction and
// reachability start, from the running executable, to analyse one module's
// call graph and write it to the store. The kanonarion binary's callgraph
// command and an importing application's child both run Extract and exit by
// RecordExit; Serve is the whole child for an application.
package cgchild

import (
	"context"
	"errors"
	"fmt"
	"io"

	cgapp "code.eitanity.com/kanonarion/internal/callgraph/application"
	cgdomain "code.eitanity.com/kanonarion/internal/callgraph/domain"
	"code.eitanity.com/kanonarion/internal/coordinate"
	"code.eitanity.com/kanonarion/internal/exitcode"
)

// Extractor runs one call-graph extraction.
type Extractor func(context.Context, cgapp.ExtractRequest) (cgapp.ExtractResult, error)

// Deps is what an extraction runs against: the walks, the module and standard
// library extractions, the frame they analyse under, and where notices go.
type Deps struct {
	Walks  WalkReader
	Module Extractor
	Stdlib Extractor
	Frame  Frame
	Stderr io.Writer
}

// Request is one extraction: the coordinate, --force, --from-walk, and
// whether the invocation declared a frame of its own.
type Request struct {
	Coordinate coordinate.ModuleCoordinate
	Force      bool
	FromWalk   string
	Declared   bool
}

// Outcome is an extraction's result and, when no walk was named and several
// builds hold the module, the ambiguity that left it without a build list.
type Outcome struct {
	Result    cgapp.ExtractResult
	Ambiguity *Ambiguity
}

// Extract settles the frame from the walk --from-walk names, pins the analysis
// to that walk's build list or one discovered from the store, and runs the
// extraction.
func Extract(ctx context.Context, d Deps, req Request) (Outcome, error) {
	coord := req.Coordinate
	if err := adoptWalkFrame(ctx, d.Walks, d.Frame, coord, req.FromWalk, req.Declared, d.Stderr); err != nil {
		return Outcome{}, err
	}
	var out Outcome
	var inputs cgdomain.AnalysisInputs
	// The standard library resolves no build list and has none to be pinned
	// against: it vendors every dependency it has, and the toolchain the
	// coordinate names decides the rest. A --from-walk naming the frame that
	// recorded the coordinate is therefore accepted and used for nothing.
	if !coord.IsStdlib() {
		var err error
		if inputs, err = InputsForWalk(ctx, d.Walks, req.FromWalk); err != nil {
			return Outcome{}, err
		}
		if req.FromWalk == "" {
			inputs, out.Ambiguity = DiscoverBuildList(ctx, d.Walks, coord, d.Frame.Current(), d.Stderr)
		}
	}
	extract := d.Module
	if coord.IsStdlib() {
		extract = d.Stdlib
	}
	result, err := extract(ctx, cgapp.ExtractRequest{Coordinate: coord, Force: req.Force, Inputs: inputs})
	if err != nil {
		return Outcome{}, fmt.Errorf("extracting call graph: %w", err)
	}
	out.Result = result
	return out, nil
}

// InputsForWalk reads the resolved build list of a named walk so a pre-modules
// module can be analysed against the versions that walk selected. An empty
// walk ID returns the zero inputs; one that does not resolve is an error, since
// a caller who named a build is entitled to be told the answer did not come
// from it.
func InputsForWalk(ctx context.Context, walks WalkReader, walkID string) (cgdomain.AnalysisInputs, error) {
	if walkID == "" {
		return cgdomain.AnalysisInputs{}, nil
	}
	rec, err := walks.GetWalk(ctx, walkID)
	if err != nil {
		return cgdomain.AnalysisInputs{}, fmt.Errorf("--from-walk: loading walk %q: %w", walkID, err)
	}
	return cgdomain.AnalysisInputs{
		BuildList: rec.Graph.SelectedVersions(),
		Source:    rec.ID,
	}, nil
}

// DiscoverBuildList answers a module that needs a build list nobody named:
// the walk of frame that holds it, found before the extraction so the module
// is analysed once and one generation is written. A search that finds nothing
// says nothing; an ambiguous one is said on stderr and returned, because the
// store holds the build list in more than one build.
func DiscoverBuildList(ctx context.Context, walks WalkReader, coord coordinate.ModuleCoordinate, frame cgdomain.BuildFrame, stderr io.Writer) (cgdomain.AnalysisInputs, *Ambiguity) {
	found, err := FindWalkHolding(ctx, walks, coord,
		fmt.Sprintf("kanonarion callgraph %s --from-walk <walk of that build>", coord), &frame)
	if err != nil {
		if amb, ok := errors.AsType[*Ambiguity](err); ok {
			_, _ = fmt.Fprintf(stderr, "no build list was named; %s\n", amb)
			return cgdomain.AnalysisInputs{}, amb
		}
		return cgdomain.AnalysisInputs{}, nil //nolint:nilerr // a search that finds nothing says nothing
	}
	inputs, err := InputsForWalk(ctx, walks, found.WalkID)
	if err != nil || !inputs.HasBuildList() {
		return cgdomain.AnalysisInputs{}, nil //nolint:nilerr // a walk that offers no build list leaves the module unpinned
	}
	// The choice is announced, never enforced: an unwritable stderr does not make
	// a discovered build list the wrong input to analyse with.
	_, _ = fmt.Fprintf(stderr, "no build list was named; a pre-modules module will be pinned to walk %s, "+
		"which resolved %d version(s) and includes this module%s\n", found.WalkID, len(inputs.BuildList), framePassedOverClause(found.FramePassedOver, frame))
	return inputs, nil
}

// framePassedOverClause says how many walks of other frames the search left
// out, empty when none were.
func framePassedOverClause(n int, frame cgdomain.BuildFrame) string {
	if n == 0 {
		return ""
	}
	return fmt.Sprintf("; %d walk(s) resolved for a frame other than %s were passed over", n, frame)
}

// NoteReuse says, for an analysis that ran and matched the generation already
// recorded, that nothing new was written.
func NoteReuse(stderr io.Writer, result cgapp.ExtractResult) error {
	if !result.Reused {
		return nil
	}
	if _, err := fmt.Fprintln(stderr,
		"re-measured and found identical to the generation already recorded; no new generation was written"); err != nil {
		return fmt.Errorf("writing re-measurement note: %w", err)
	}
	return nil
}

// RecordExit maps an extraction outcome onto the process exit code.
//
// Three outcomes, three codes: a complete graph (0), one scoped by its
// FailedPackages line (1), and no graph at all (2). A Partial carrying no nodes
// stays at 2. An analyser limit is 20: the remedy is another build of this
// binary, so the invocation is what has to change.
func RecordExit(r cgdomain.CallGraphRecord) error {
	msg := fmt.Sprintf("%s: %s", r.Coordinate, r.OverallStatus.String())
	if r.FailureDetail != "" {
		msg += " — " + r.FailureDetail
	}
	if l, ok := cgdomain.AnalyserLimitOf(r.FailureDetail); ok && r.OverallStatus != cgdomain.CallGraphStatusCancelled {
		return &exitcode.Error{Code: exitcode.Config, Msg: fmt.Sprintf("%s: %s — %s", r.Coordinate, r.OverallStatus, l.Statement())}
	}
	switch r.OverallStatus {
	// ExcludedByConfig shares Extracted's 0 by decision: the operator listed
	// this module in callgraph.exclude, so the absent graph is what they asked for.
	case cgdomain.CallGraphStatusExtracted, cgdomain.CallGraphStatusExcludedByConfig:
		return nil
	case cgdomain.CallGraphStatusPartial:
		if r.NodeCount == 0 {
			return &exitcode.Error{Code: exitcode.Failed, Msg: msg}
		}
		return &exitcode.Error{Code: exitcode.Partial, Msg: msg}
	case cgdomain.CallGraphStatusCancelled:
		return &exitcode.Error{Code: exitcode.Cancelled, Msg: msg}
	default:
		// No graph exists, so nothing downstream can consume this coordinate.
		return &exitcode.Error{Code: exitcode.Failed, Msg: msg}
	}
}
