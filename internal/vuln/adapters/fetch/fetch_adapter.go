package fetch

import (
	"context"
	"fmt"

	fetchapp "github.com/eitanity/kanonarion/internal/fetch/application"
	fetchdomain "github.com/eitanity/kanonarion/internal/fetch/domain"
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
func (a *FetchModuleAdapter) FetchModule(ctx context.Context, coord fetchdomain.ModuleCoordinate) error {
	_, err := a.uc.Execute(ctx, fetchapp.FetchRequest{Coordinate: coord})
	if err != nil {
		return fmt.Errorf("fetching %s: %w", coord, err)
	}
	return nil
}
