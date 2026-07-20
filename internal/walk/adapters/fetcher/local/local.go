// Package local provides a ModuleFetcher adapter backed by the local
// FetchModuleUseCase. A future gRPC implementation can live alongside this
// package (e.g. adapters/fetcher/grpc) and implement the same port.
package local

import (
	"context"
	"fmt"

	"github.com/eitanity/kanonarion/internal/coordinate"

	fetchapplication "github.com/eitanity/kanonarion/internal/fetch/application"

	walkports "github.com/eitanity/kanonarion/internal/walk/ports"
)

// Fetcher adapts FetchModuleUseCase to walkports.ModuleFetcher.
type Fetcher struct {
	uc            *fetchapplication.FetchModuleUseCase
	skipVCSVerify bool
	force         bool
}

// New constructs a Fetcher. When skipVCSVerify is true the underlying fetch
// skips the git-tag verification step.
func New(uc *fetchapplication.FetchModuleUseCase, skipVCSVerify bool) *Fetcher {
	return &Fetcher{uc: uc, skipVCSVerify: skipVCSVerify}
}

// WithForce returns a shallow copy of the fetcher configured to bypass the
// fact-store cache on every EnsureFetched call. The original fetcher is
// unchanged. The walker uses this per-walk when WalkRequest.Force is set,
// so a forced walk genuinely re-downloads every module instead of returning
// cached fact records. The return type is walkports.ModuleFetcher
// so the walker's forceCapable interface can declare it without importing
// this adapter package.
func (f *Fetcher) WithForce(force bool) walkports.ModuleFetcher {
	clone := *f
	clone.force = force
	return &clone
}

func (f *Fetcher) EnsureFetched(ctx context.Context, coord coordinate.ModuleCoordinate) (walkports.ModuleFetchResult, error) {
	result, err := f.uc.Execute(ctx, fetchapplication.FetchRequest{
		Coordinate:    coord,
		SkipVCSVerify: f.skipVCSVerify,
		Force:         f.force,
	})
	if err != nil {
		return walkports.ModuleFetchResult{}, fmt.Errorf("fetching module: %w", err)
	}
	return walkports.ModuleFetchResult{Record: result.Record, FromCache: result.FromCache}, nil
}
