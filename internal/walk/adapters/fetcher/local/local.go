// Package local provides a ModuleFetcher adapter backed by the local
// FetchModuleUseCase. A future gRPC implementation can live alongside this
// package (e.g. adapters/fetcher/grpc) and implement the same port.
package local

import (
	"context"
	"fmt"

	"github.com/eitanity/kanonarion/internal/coordinate"

	fetchapplication "github.com/eitanity/kanonarion/internal/fetch/application"
	fetchdomain "github.com/eitanity/kanonarion/internal/fetch/domain"

	walkports "github.com/eitanity/kanonarion/internal/walk/ports"
)

// Fetcher adapts FetchModuleUseCase to walkports.ModuleFetcher.
type Fetcher struct {
	uc            *fetchapplication.FetchModuleUseCase
	skipVCSVerify bool
	force         bool
	vcsHosts      fetchdomain.VCSHostAllowlist
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

// WithVCSHosts returns a shallow copy of the fetcher that hands the given VCS
// forge allowlist to every fetch. The original fetcher is unchanged. The walker
// uses this per-walk with the allowlist resolved from the walk's fetch-stage
// policy, so an operator's allowed_vcs_hosts governs which forges the run is
// willing to clone from. The return type is walkports.ModuleFetcher so the
// walker's capability interface can declare it without importing this package.
func (f *Fetcher) WithVCSHosts(hosts fetchdomain.VCSHostAllowlist) walkports.ModuleFetcher {
	clone := *f
	clone.vcsHosts = hosts
	return &clone
}

func (f *Fetcher) EnsureFetched(ctx context.Context, coord coordinate.ModuleCoordinate) (walkports.ModuleFetchResult, error) {
	return f.EnsureFetchedReplacing(ctx, coord, coordinate.ModuleCoordinate{})
}

// EnsureFetchedReplacing fetches coord as the replacement for original, so the
// fetch can anchor the module under the coordinate go.sum actually records —
// the replacement — while still being able to name the coordinate the project
// requires it under.
func (f *Fetcher) EnsureFetchedReplacing(ctx context.Context, coord, original coordinate.ModuleCoordinate) (walkports.ModuleFetchResult, error) {
	result, err := f.uc.Execute(ctx, fetchapplication.FetchRequest{
		Coordinate:         coord,
		OriginalCoordinate: original,
		SkipVCSVerify:      f.skipVCSVerify,
		Force:              f.force,
		VCSHosts:           f.vcsHosts,
	})
	if err != nil {
		return walkports.ModuleFetchResult{}, fmt.Errorf("fetching module: %w", err)
	}
	return walkports.ModuleFetchResult{Record: result.Record, FromCache: result.FromCache}, nil
}
