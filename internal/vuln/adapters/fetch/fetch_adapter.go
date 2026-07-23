package fetch

import (
	"context"
	"fmt"

	"github.com/eitanity/kanonarion/internal/coordinate"

	fetchapp "github.com/eitanity/kanonarion/internal/fetch/application"
)

// FetchModuleAdapter wraps a fetch.FetchModuleUseCase to satisfy ports.ModuleFetcher.
type FetchModuleAdapter struct {
	uc *fetchapp.FetchModuleUseCase
}

// NewFetchModuleAdapter returns a ModuleFetcher backed by the given use case.
func NewFetchModuleAdapter(uc *fetchapp.FetchModuleUseCase) *FetchModuleAdapter {
	return &FetchModuleAdapter{uc: uc}
}

// FetchModule fetches a single module, ignoring the result beyond success/failure.
func (a *FetchModuleAdapter) FetchModule(ctx context.Context, coord coordinate.ModuleCoordinate) error {
	_, err := a.uc.Execute(ctx, fetchapp.FetchRequest{Coordinate: coord})
	if err != nil {
		return fmt.Errorf("fetching %s: %w", coord, err)
	}
	return nil
}

// FetchModuleGoMod acquires only the module's go.mod, ignoring the result beyond
// success/failure. It persists a go.mod-only record for module-graph resolution.
func (a *FetchModuleAdapter) FetchModuleGoMod(ctx context.Context, coord coordinate.ModuleCoordinate) error {
	_, err := a.uc.Execute(ctx, fetchapp.FetchRequest{Coordinate: coord, GoModOnly: true})
	if err != nil {
		return fmt.Errorf("fetching go.mod for %s: %w", coord, err)
	}
	return nil
}
