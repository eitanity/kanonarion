// Package store provides a VulnFindingLoader adapter backed by the global
// vulnerability store. All access is read-only; no records are written.
package store

import (
	"context"
	"fmt"

	"github.com/eitanity/kanonarion/internal/coordinate"

	"github.com/eitanity/kanonarion/internal/local/ports"
	vulndomain "github.com/eitanity/kanonarion/internal/vuln/domain"
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

// LoadFindings queries the stored vulnerability records for each coordinate and
// seeds the probe from the ones measured in the probed tree's own frame, or in
// the isolated frame. Coordinates with at least one finding land in Findings;
// every coordinate an acceptable record was held for at all — findings or not —
// lands in Scanned, so a caller can tell "clean" from "never scanned".
//
// The frame filter is the whole point of reading the candidates rather than the
// store-wide composed record. A shared store holds one answer per project per
// coordinate, and the store-wide read served whichever of them the ladder ranked
// first — so a probe of this tree could be seeded with another project's build's
// reachability judgments, at full confidence and with nothing said.
//
// A coordinate whose records all belong to other consumers is left out of
// Scanned as well as Findings. It was not measured for this tree, and reporting
// it as covered would claim a scan of this build that never ran; the coverage
// block then names it as uncovered, which is the true statement.
func (a *VulnStoreAdapter) LoadFindings(
	ctx context.Context,
	coords []coordinate.ModuleCoordinate,
	consumerModulePath string,
) (ports.FindingSet, error) {
	result := ports.FindingSet{
		Findings:       make(map[coordinate.ModuleCoordinate][]ports.VulnFinding),
		Scanned:        make(map[coordinate.ModuleCoordinate]struct{}),
		OtherFrameOnly: make(map[coordinate.ModuleCoordinate]struct{}),
		Restriction:    seedRestriction(consumerModulePath),
	}
	for _, coord := range coords {
		candidates, err := a.store.ListVulnerabilityRecordsForModule(ctx, coord, a.pipelineVersion)
		if err != nil {
			return ports.FindingSet{}, fmt.Errorf("loading vuln records for %s: %w", coord, err)
		}
		if len(candidates) == 0 {
			continue
		}
		rec, found, err := vulndomain.ComposeForTree(candidates, consumerModulePath)
		if err != nil {
			return ports.FindingSet{}, fmt.Errorf("selecting vuln record for %s: %w", coord, err)
		}
		if !found {
			// The store holds this coordinate, in a frame that says nothing about
			// this tree. Recording which absence it is keeps the coverage block from
			// reporting a scanned module as never scanned.
			result.OtherFrameOnly[coord] = struct{}{}
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
				// The basis rides along with the verdict rather than being looked up
				// later: it is what says the verdict came from a stored scan, and which
				// build that scan was rooted at.
				vf.ReachableBasis = f.Reachable.DerivedBy.String()
				// The rung behind a negative is derived here, where the whole finding is
				// in hand. Below this seam the analyser and its fidelity are gone, so a
				// probe that carried the verdict on and derived the rung later would be
				// deriving it from nothing.
				soundness, reason := vulndomain.NegativeSoundness(f)
				vf.ReachableSoundness, vf.ReachableSoundnessReason = string(soundness), reason
			}
			findings = append(findings, vf)
		}
		result.Findings[coord] = findings
	}
	return result, nil
}

// seedRestriction is the one-line statement of what the seed was drawn from,
// for the probe to report beside its answer.
func seedRestriction(consumerModulePath string) string {
	if consumerModulePath == "" {
		// No go.mod path to anchor to, so nothing but the frame that belongs to no
		// project may seed. Saying so is the point: a silent narrowing here reads
		// as a store that holds less than it does.
		return "seed restricted to stored records measured in the isolated frame; " +
			"this tree declares no module path to anchor its own frame to"
	}
	return fmt.Sprintf(
		"seed restricted to stored records measured in this tree's own frame (rooted at %s) "+
			"or in the isolated frame; records measured in another consumer's build were not read",
		consumerModulePath)
}

// Ensure VulnStoreAdapter implements ports.VulnFindingLoader at compile time.
var _ ports.VulnFindingLoader = (*VulnStoreAdapter)(nil)
