package cli

import (
	"context"
	"fmt"
	"io"
	"strings"

	"code.eitanity.com/kanonarion/internal/callgraph/domain"
	"code.eitanity.com/kanonarion/internal/callgraph/ports"
	"code.eitanity.com/kanonarion/internal/coordinate"
)

// loweringGap is a record an edge read draws on that carries the TinyGo lowering
// gap, with what its remedy needs.
type loweringGap struct {
	coord coordinate.ModuleCoordinate
	gap   domain.TinyGoLoweringGap
	rec   domain.CallGraphRecord
}

// loweringGapsOfRead lists the records in sc that carry the lowering gap. Only a
// TinyGo read can select one, and only a Partial generation can state it, so any
// other read decodes nothing.
func loweringGapsOfRead(ctx context.Context, uc QueryCallGraphUseCase, sc buildScope) ([]loweringGap, error) {
	if !declaredTinyGo.Declared() {
		return nil, nil
	}
	coords, err := listScopedCoordinates(ctx, uc, sc.modules)
	if err != nil {
		return nil, err
	}
	var out []loweringGap
	for _, s := range coords {
		if !s.AnyPartial {
			continue
		}
		coord, cErr := coordinate.NewModuleCoordinate(s.ModulePath, s.ModuleVersion)
		if cErr != nil {
			return nil, fmt.Errorf("call graph record %s@%s names no module: %w", s.ModulePath, s.ModuleVersion, cErr)
		}
		rec, found, gerr := uc.GetCallGraphRecordFrom(ctx, coord, s.PipelineVersion, domain.ComposeRequest{ToolchainPreference: sc.toolchain})
		if gerr != nil {
			return nil, fmt.Errorf("loading call graph for %s: %w", coord, gerr)
		}
		if g, ok := domain.ReadTinyGoLoweringGap(rec.FailureDetail); found && ok {
			out = append(out, loweringGap{coord: coord, gap: g, rec: rec})
		}
	}
	return out, nil
}

// loweringSinks are the gaps as the sinks of an answer.
func loweringSinks(gaps []loweringGap) []domain.SoundnessSink {
	out := make([]domain.SoundnessSink, 0, len(gaps))
	for _, g := range gaps {
		out = append(out, g.gap.Sink(g.coord.String()))
	}
	return out
}

// loweringClause qualifies a non-empty answer line: the list may be short.
func loweringClause(gaps []loweringGap) string {
	if len(gaps) == 0 {
		return ""
	}
	parts := make([]string, 0, len(gaps))
	for _, s := range loweringSinks(gaps) {
		parts = append(parts, s.Describe())
	}
	return "; the calls TinyGo's compiler inserts are not recorded, so the list may be short — " + strings.Join(parts, "; ")
}

// reportLoweringNotice holds the gap for stderr under a single-hop --json
// answer, whose bare array has nowhere to carry it.
func reportLoweringNotice(kind, symbolID string, gaps []loweringGap) {
	if len(gaps) == 0 {
		return
	}
	parts := make([]string, 0, len(gaps))
	for _, s := range loweringSinks(gaps) {
		parts = append(parts, s.Describe())
	}
	storeDispatchNotice.note("notice: the " + kind + " of " + symbolID +
		" do not include the calls TinyGo's compiler inserts: " + strings.Join(parts, "; ") + "\n")
}

// writeLoweringRemedies prints, under an UNRESOLVED answer, what closes each gap.
func writeLoweringRemedies(ctx context.Context, stdout io.Writer, gaps []loweringGap) error {
	for _, g := range gaps {
		r := g.rec
		if _, err := fmt.Fprintln(stdout, incompleteGraphRemedy(ctx, g.coord, r.FailureCause, r.FailureDetail, r.AnalysisRoot, r.Frame)); err != nil {
			return fmt.Errorf("writing lowering remedy: %w", err)
		}
	}
	return nil
}

// classifyEmptyEdges returns the read's lowering gaps, after refusing an empty
// answer classifyEmptyEdgeResult explains: one with no dropped package and no gap.
func classifyEmptyEdges(ctx context.Context, symbolID string, uc QueryCallGraphUseCase, sc buildScope, pr partialRoot, found int) ([]loweringGap, error) {
	gaps, err := loweringGapsOfRead(ctx, uc, sc)
	if err != nil || found > 0 || pr.failedPkg != "" || len(gaps) > 0 {
		return gaps, err
	}
	return nil, classifyEmptyEdgeResult(ctx, symbolID, uc, sc)
}

// writeEmptyEdgeAnswer writes an empty answer: its verdict, UNRESOLVED naming
// any lowering gap, then each gap's remedy.
func writeEmptyEdgeAnswer(ctx context.Context, stdout io.Writer, kind, symbolID string, scanDispatch bool, uc QueryCallGraphUseCase,
	sc buildScope, opts ports.EdgeQueryOptions, pr partialRoot, gaps []loweringGap) error {
	v, err := negativeCallAnswer(ctx, symbolID, scanDispatch, uc, sc, opts, pr.failedPkg, pr.detail)
	if err != nil {
		return err
	}
	if err := writeCallAnswer(stdout, kind, symbolID, v.WithSinks(loweringSinks(gaps)...), opts); err != nil {
		return err
	}
	return writeLoweringRemedies(ctx, stdout, gaps)
}
