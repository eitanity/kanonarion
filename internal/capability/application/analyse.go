package application

import (
	"context"
	"errors"
	"fmt"

	cgdomain "github.com/eitanity/kanonarion/internal/callgraph/domain"
	capdomain "github.com/eitanity/kanonarion/internal/capability/domain"
	fetchdomain "github.com/eitanity/kanonarion/internal/fetch/domain"
)

// ErrNoCallGraph is returned when no call graph record exists for the requested
// module. Capability analysis needs the graph, so this is actionable, not a
// silent empty result.
var ErrNoCallGraph = errors.New("no call graph record: run 'kanonarion callgraph <module>@<version>' first")

// CallGraphSource reads stored call graph records. QueryCallGraphUseCase
// satisfies it; the capability context depends only on this narrow method.
type CallGraphSource interface {
	GetCallGraphRecord(ctx context.Context, coord fetchdomain.ModuleCoordinate, pipelineVersion string) (cgdomain.CallGraphRecord, bool, error)
}

// AnalyseCapabilitiesUseCase produces capability reports from stored call graphs.
type AnalyseCapabilitiesUseCase struct {
	source CallGraphSource
}

// NewAnalyseCapabilitiesUseCase constructs the use case.
func NewAnalyseCapabilitiesUseCase(source CallGraphSource) *AnalyseCapabilitiesUseCase {
	return &AnalyseCapabilitiesUseCase{source: source}
}

// Analyse reads the call graph for coord and returns its capability report.
func (uc *AnalyseCapabilitiesUseCase) Analyse(ctx context.Context, coord fetchdomain.ModuleCoordinate, pipelineVersion string) (capdomain.CapabilityReport, error) {
	rec, err := uc.load(ctx, coord, pipelineVersion)
	if err != nil {
		return capdomain.CapabilityReport{}, err
	}
	return capdomain.Analyse(rec, capdomain.SelectRoots(rec)), nil
}

// Diff reads the call graphs for two coordinates and returns their per-side
// reports plus the capability diff between them.
func (uc *AnalyseCapabilitiesUseCase) Diff(ctx context.Context, from, to fetchdomain.ModuleCoordinate, pipelineVersion string) (fromReport, toReport capdomain.CapabilityReport, diff capdomain.CapabilityDiff, err error) {
	fromReport, err = uc.Analyse(ctx, from, pipelineVersion)
	if err != nil {
		return capdomain.CapabilityReport{}, capdomain.CapabilityReport{}, capdomain.CapabilityDiff{}, fmt.Errorf("analysing %s: %w", from, err)
	}
	toReport, err = uc.Analyse(ctx, to, pipelineVersion)
	if err != nil {
		return capdomain.CapabilityReport{}, capdomain.CapabilityReport{}, capdomain.CapabilityDiff{}, fmt.Errorf("analysing %s: %w", to, err)
	}
	return fromReport, toReport, capdomain.DiffCapabilities(fromReport, toReport), nil
}

func (uc *AnalyseCapabilitiesUseCase) load(ctx context.Context, coord fetchdomain.ModuleCoordinate, pipelineVersion string) (cgdomain.CallGraphRecord, error) {
	rec, found, err := uc.source.GetCallGraphRecord(ctx, coord, pipelineVersion)
	if err != nil {
		return cgdomain.CallGraphRecord{}, fmt.Errorf("getting call graph record for %s: %w", coord, err)
	}
	if !found {
		return cgdomain.CallGraphRecord{}, fmt.Errorf("%s: %w", coord, ErrNoCallGraph)
	}
	return rec, nil
}
