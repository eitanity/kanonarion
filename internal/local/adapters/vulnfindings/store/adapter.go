// Package store provides a VulnFindingLoader adapter backed by the global
// vulnerability store. All access is read-only; no records are written.
package store

import (
	"context"
	"fmt"

	"github.com/eitanity/kanonarion/internal/coordinate"

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
// coordinate. Coordinates with at least one finding land in Findings; every
// coordinate a record was held for at all — findings or not — lands in Scanned,
// so a caller can tell "clean" from "never scanned".
func (a *VulnStoreAdapter) LoadFindings(ctx context.Context, coords []coordinate.ModuleCoordinate) (ports.FindingSet, error) {
	result := ports.FindingSet{
		Findings: make(map[coordinate.ModuleCoordinate][]ports.VulnFinding),
		Scanned:  make(map[coordinate.ModuleCoordinate]struct{}),
	}
	for _, coord := range coords {
		rec, found, err := a.store.GetLatestVulnerabilityRecord(ctx, coord, a.pipelineVersion)
		if err != nil {
			return ports.FindingSet{}, fmt.Errorf("loading vuln record for %s: %w", coord, err)
		}
		if !found {
			continue
		}
		result.Scanned[coord] = struct{}{}
		if len(rec.Findings) == 0 {
			continue
		}
		findings := make([]ports.VulnFinding, 0, len(rec.Findings))
		for _, f := range rec.Findings {
			vf := ports.VulnFinding{
				ID:              f.ID,
				Aliases:         f.Aliases,
				Summary:         f.Summary,
				AffectedSymbols: f.AffectedSymbols,
				// Carried so an empty symbol list is read as "the advisory named
				// none" rather than as a probe that found nothing.
				AdvisoryNamesNoSymbols: f.AdvisoryNamesNoSymbols,
			}
			if f.Reachable != nil {
				r := f.Reachable.IsReachable
				vf.Reachable = &r
			}
			findings = append(findings, vf)
		}
		result.Findings[coord] = findings
	}
	return result, nil
}

// Ensure VulnStoreAdapter implements ports.VulnFindingLoader at compile time.
var _ ports.VulnFindingLoader = (*VulnStoreAdapter)(nil)
