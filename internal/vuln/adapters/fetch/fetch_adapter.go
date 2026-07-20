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
