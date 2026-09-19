package application

import (
	"context"
	"errors"
	"fmt"

	"github.com/eitanity/kanonarion/internal/coordinate"

	cgdomain "github.com/eitanity/kanonarion/internal/callgraph/domain"
	capdomain "github.com/eitanity/kanonarion/internal/capability/domain"
)

// ErrNoCallGraph is returned when no call graph record exists for the requested
// module. Capability analysis needs the graph, so this is actionable, not a
// silent empty result.
//
// It names no remedy. Which invocation re-derives a graph is decided by the
// coordinate — a published module is analysed, a working tree is ingested — and
// a use case that guessed printed a placeholder no parser accepts. The
// coordinate travels on NoCallGraphError so the caller can name the real one.
var ErrNoCallGraph = errors.New("no call graph record")

// NoCallGraphError is the missing-record refusal, carrying the coordinate it is
// about. A diff reads two coordinates and either may be the absent one, so the
// remedy has to be built from the side that actually missed.
type NoCallGraphError struct {
	Coord coordinate.ModuleCoordinate
}

func (e *NoCallGraphError) Error() string {
	return fmt.Sprintf("%s: %s", e.Coord, ErrNoCallGraph)
}

// Unwrap keeps errors.Is(err, ErrNoCallGraph) answering for callers that only
// need the class.
func (e *NoCallGraphError) Unwrap() error { return ErrNoCallGraph }

// CallGraphSource reads stored call graph records. QueryCallGraphUseCase
// satisfies it; the capability context depends only on this narrow method.
type CallGraphSource interface {
	GetCallGraphRecord(ctx context.Context, coord coordinate.ModuleCoordinate, pipelineVersion string) (cgdomain.CallGraphRecord, bool, error)
}

// AnalyseCapabilitiesUseCase produces capability reports from stored call graphs.
type AnalyseCapabilitiesUseCase struct {
	source CallGraphSource
}

// NewAnalyseCapabilitiesUseCase constructs the use case.
func NewAnalyseCapabilitiesUseCase(source CallGraphSource) *AnalyseCapabilitiesUseCase {
	return &AnalyseCapabilitiesUseCase{source: source}
}

// Analyse reads the call graph for coord and returns its capability report,
// rooted at the scope the caller asked for.
func (uc *AnalyseCapabilitiesUseCase) Analyse(
	ctx context.Context,
	coord coordinate.ModuleCoordinate,
	pipelineVersion string,
	scope cgdomain.RootScope,
) (capdomain.CapabilityReport, error) {
	rec, err := uc.load(ctx, coord, pipelineVersion)
	if err != nil {
		return capdomain.CapabilityReport{}, err
	}
	return capdomain.Analyse(rec, capdomain.SelectRoots(rec, scope)), nil
}

// Diff reads the call graphs for two coordinates and returns their per-side
// reports plus the capability diff between them.
func (uc *AnalyseCapabilitiesUseCase) Diff(
	ctx context.Context,
	from, to coordinate.ModuleCoordinate,
	pipelineVersion string,
	scope cgdomain.RootScope,
) (fromReport, toReport capdomain.CapabilityReport, diff capdomain.CapabilityDiff, err error) {
	fromReport, err = uc.Analyse(ctx, from, pipelineVersion, scope)
	if err != nil {
		return capdomain.CapabilityReport{}, capdomain.CapabilityReport{}, capdomain.CapabilityDiff{}, fmt.Errorf("analysing %s: %w", from, err)
	}
	toReport, err = uc.Analyse(ctx, to, pipelineVersion, scope)
	if err != nil {
		return capdomain.CapabilityReport{}, capdomain.CapabilityReport{}, capdomain.CapabilityDiff{}, fmt.Errorf("analysing %s: %w", to, err)
	}
	return fromReport, toReport, capdomain.DiffCapabilities(fromReport, toReport), nil
}

func (uc *AnalyseCapabilitiesUseCase) load(ctx context.Context, coord coordinate.ModuleCoordinate, pipelineVersion string) (cgdomain.CallGraphRecord, error) {
	rec, found, err := uc.source.GetCallGraphRecord(ctx, coord, pipelineVersion)
	if err != nil {
		return cgdomain.CallGraphRecord{}, fmt.Errorf("getting call graph record for %s: %w", coord, err)
	}
	if !found {
		return cgdomain.CallGraphRecord{}, &NoCallGraphError{Coord: coord}
	}
	return rec, nil
}
