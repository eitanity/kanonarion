// Package store provides a VulnFindingLoader adapter backed by the global
// vulnerability store. All access is read-only; no records are written.
package store

import (
	"context"
	"fmt"

	fetchdomain "github.com/eitanity/kanonarion/internal/fetch/domain"
	"github.com/eitanity/kanonarion/internal/local/ports"
	vulnports "github.com/eitanity/kanonarion/internal/vuln/ports"
)

// VulnStoreAdapter adapts a vuln ports.VulnerabilityStore to the local
// ports.VulnFindingLoader interface.
type VulnStoreAdapter struct {
	store           vulnports.VulnerabilityStore
	pipelineVersion string
}

// New constructs a VulnStoreAdapter.
func New(store vulnports.VulnerabilityStore, pipelineVersion string) *VulnStoreAdapter {
	return &VulnStoreAdapter{store: store, pipelineVersion: pipelineVersion}
}

// LoadFindings queries the latest stored vulnerability record for each
// coordinate and returns only coordinates that have at least one finding.
func (a *VulnStoreAdapter) LoadFindings(ctx context.Context, coords []fetchdomain.ModuleCoordinate) (map[fetchdomain.ModuleCoordinate][]ports.VulnFinding, error) {
	result := make(map[fetchdomain.ModuleCoordinate][]ports.VulnFinding)
	for _, coord := range coords {
		rec, found, err := a.store.GetLatestVulnerabilityRecord(ctx, coord, a.pipelineVersion)
		if err != nil {
			return nil, fmt.Errorf("loading vuln record for %s: %w", coord, err)
		}
		if !found || len(rec.Findings) == 0 {
			continue
		}
		findings := make([]ports.VulnFinding, 0, len(rec.Findings))
		for _, f := range rec.Findings {
			vf := ports.VulnFinding{
				ID:              f.ID,
				Aliases:         f.Aliases,
				Summary:         f.Summary,
				AffectedSymbols: f.AffectedSymbols,
			}
			if f.Reachable != nil {
				r := f.Reachable.IsReachable
				vf.Reachable = &r
			}
			findings = append(findings, vf)
		}
		result[coord] = findings
	}
	return result, nil
}

// Ensure VulnStoreAdapter implements ports.VulnFindingLoader at compile time.
var _ ports.VulnFindingLoader = (*VulnStoreAdapter)(nil)
