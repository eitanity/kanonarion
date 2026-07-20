package application

import (
	"context"
	"fmt"

	"github.com/eitanity/kanonarion/internal/coordinate"

	"github.com/eitanity/kanonarion/internal/local/domain"
	"github.com/eitanity/kanonarion/internal/local/ports"
)

// LoadDependenciesUseCase loads callgraph records for a set of module
// coordinates from the global store and constructs an in-memory AnalysisSession
// for cross-module edge resolution. No facts are written to any store.
type LoadDependenciesUseCase struct {
	loader          ports.DependencyLoader
	pipelineVersion string
}

// NewLoadDependenciesUseCase constructs a LoadDependenciesUseCase.
func NewLoadDependenciesUseCase(loader ports.DependencyLoader, pipelineVersion string) *LoadDependenciesUseCase {
	return &LoadDependenciesUseCase{loader: loader, pipelineVersion: pipelineVersion}
}

// Execute loads callgraph records for the given module coordinates and returns
// an AnalysisSession ready for cross-module edge resolution. Coordinates that
// have no stored record are silently omitted — gaps in coverage are visible
// via session.ModuleCount vs. len(coords).
func (uc *LoadDependenciesUseCase) Execute(ctx context.Context, coords []coordinate.ModuleCoordinate) (domain.AnalysisSession, error) {
	records, err := uc.loader.LoadCallGraphRecords(ctx, coords, uc.pipelineVersion)
	if err != nil {
		return domain.AnalysisSession{}, fmt.Errorf("loading dependency callgraph records: %w", err)
	}
	return domain.NewAnalysisSession(records), nil
}
