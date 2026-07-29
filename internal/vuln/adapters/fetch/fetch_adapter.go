package fetch

import (
	"context"
	"fmt"

	"github.com/eitanity/kanonarion/internal/coordinate"

	fetchapp "github.com/eitanity/kanonarion/internal/fetch/application"
	fetchdomain "github.com/eitanity/kanonarion/internal/fetch/domain"
	vulnports "github.com/eitanity/kanonarion/internal/vuln/ports"
)

// FetchModuleAdapter wraps a fetch.FetchModuleUseCase to satisfy ports.ModuleFetcher.
type FetchModuleAdapter struct {
	uc *fetchapp.FetchModuleUseCase
	// vcsHosts is the effective VCS forge allowlist for this run. The zero
	// value is the built-in advisory set, which is what an invocation with no
	// policy should get.
	vcsHosts fetchdomain.VCSHostAllowlist
}

// NewFetchModuleAdapter returns a ModuleFetcher backed by the given use case.
func NewFetchModuleAdapter(uc *fetchapp.FetchModuleUseCase) *FetchModuleAdapter {
	return &FetchModuleAdapter{uc: uc}
}

// WithVCSHosts returns a shallow copy of the adapter that hands the given VCS
// forge allowlist to every full-module fetch it performs.
//
// A clone rather than a mutation: the container builds one adapter and hands it
// to both the scan and rescan use cases, and a per-run policy must not leak
// sideways into whatever else holds a reference.
func (a *FetchModuleAdapter) WithVCSHosts(hosts fetchdomain.VCSHostAllowlist) vulnports.ModuleFetcher {
	clone := *a
	clone.vcsHosts = hosts
	return &clone
}

// FetchModule fetches a single module, ignoring the result beyond success/failure.
func (a *FetchModuleAdapter) FetchModule(ctx context.Context, coord coordinate.ModuleCoordinate) error {
	_, err := a.uc.Execute(ctx, fetchapp.FetchRequest{Coordinate: coord, VCSHosts: a.vcsHosts})
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
