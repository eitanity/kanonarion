// Package store provides a VulnFindingLoader adapter backed by the global
// vulnerability store. All access is read-only; no records are written.
package store

import (
	"context"
	"errors"
	"fmt"

	"github.com/eitanity/kanonarion/internal/adapters/recordseal"
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
	searcher        NegativeSearcher
	anchor          *WalkAnchor
}

// WalkAnchor is the walk a probe is seeded from: the newest project walk for the
// tree's go.mod, which the caller resolves. Rooting is empty when the walk record
// is no longer in the store, and the seed then falls back to the tree's frame
// within the walk's records.
type WalkAnchor struct {
	WalkID  string
	Rooting vulndomain.Rooting
	// Source names the walk for the seed line, e.g.
	// `walk "01K…" (code scope, frame target-rooted:example.com/app@local)`.
	Source string
	// PassedOver names a newer project walk whose vuln-scan did not complete,
	// with the remedy that completes it; the seed came from an older walk whose
	// scan did. Empty when the newest walk's scan completed.
	PassedOver string
	// ScanIncomplete says no walk of the tree has a completed vuln-scan, so the
	// anchor is the newest walk and it answers for no coordinate.
	ScanIncomplete bool
}

// NegativeSearcher is the read-time call-graph search a record's negatives are
// put through before their soundness is derived. It is declared here, as the
// one method this adapter needs, so the local context does not depend on the
// vuln reachability adapter.
type NegativeSearcher interface {
	Search(ctx context.Context, rec *vulndomain.VulnerabilityRecord)
}

// New constructs a VulnStoreAdapter.
func New(store vulnports.VulnerabilityStore, pipelineVersion string) *VulnStoreAdapter {
	return &VulnStoreAdapter{store: store, pipelineVersion: pipelineVersion}
}

// WithNegativeSearcher seeds the probe from records that have been through the
// call-graph search, so a negative reads at the same rung here as it does on
// every other surface. Without one the seed carries the stored derivation's own
// rung, which is what it carried before the search existed.
func (a *VulnStoreAdapter) WithNegativeSearcher(s NegativeSearcher) *VulnStoreAdapter {
	a.searcher = s
	return a
}

// WithWalkAnchor seeds the probe from one walk's records instead of every record
// in the tree's frame. Older walks of the same tree can carry another toolchain's
// verdict, and composing across them refused a probe no re-scan could unblock.
func (a *VulnStoreAdapter) WithWalkAnchor(anchor WalkAnchor) *VulnStoreAdapter {
	a.anchor = &anchor
	return a
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
		SupersededOnly: make(map[coordinate.ModuleCoordinate]struct{}),
		SetAsideOnly:   make(map[coordinate.ModuleCoordinate]struct{}),
		NotInSeedWalk:  make(map[coordinate.ModuleCoordinate]struct{}),
		ScanIncomplete: make(map[coordinate.ModuleCoordinate]struct{}),
		NotAnalysed:    make(map[coordinate.ModuleCoordinate]struct{}),
		Restriction:    a.seedRestriction(consumerModulePath),
	}
	for _, coord := range coords {
		candidates, err := a.candidates(ctx, coord)
		// Generations this build cannot reproduce are left out of the seed and
		// named beside it; an altered row still fails the load.
		var aside *recordseal.SetAside
		if errors.As(err, &aside) {
			for _, r := range aside.Rows {
				result.SetAside = append(result.SetAside, r.Label()+": "+recordseal.SetAsideRemedy)
			}
			if len(candidates) == 0 {
				result.SetAsideOnly[coord] = struct{}{}
				continue
			}
		} else if err != nil {
			return ports.FindingSet{}, fmt.Errorf("loading vuln records for %s: %w", coord, err)
		}
		if len(candidates) == 0 {
			// The read above keys on the pipeline version. An empty answer is
			// therefore silent about every other generation, and a coordinate the
			// store holds only at one of those is not an unscanned dependency —
			// which is what the coverage block would otherwise call it.
			a.classifyEmpty(ctx, coord, &result)
			continue
		}
		rec, found, err := a.selectSeed(candidates, consumerModulePath)
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
		if len(rec.Findings) == 0 && notAnalysed(rec) {
			// A failed or unscannable scan with nothing found is not a clean answer;
			// counting it covered turned a failed walk scan into "no findings".
			result.NotAnalysed[coord] = struct{}{}
			continue
		}
		result.Scanned[coord] = struct{}{}
		if len(rec.Findings) == 0 {
			continue
		}
		if a.searcher != nil {
			a.searcher.Search(ctx, &rec)
		}
		result.Findings[coord] = seedFindings(rec.Findings)
	}
	return result, nil
}

// seedFindings maps a seeding record's findings onto the probe's shape.
func seedFindings(recFindings []vulndomain.VulnerabilityFinding) []ports.VulnFinding {
	findings := make([]ports.VulnFinding, 0, len(recFindings))
	for _, f := range recFindings {
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
	return findings
}

// candidates reads the records a coordinate's seed is chosen from: the anchored
// walk's, or every record at this pipeline version when no walk anchors it.
func (a *VulnStoreAdapter) candidates(ctx context.Context, coord coordinate.ModuleCoordinate) ([]vulndomain.VulnerabilityRecord, error) {
	if a.anchor == nil {
		return a.store.ListVulnerabilityRecordsForModule(ctx, coord, a.pipelineVersion) //nolint:wrapcheck // wrapped by the caller, which also inspects it for set-aside rows
	}
	return a.store.ListVulnerabilityRecordsForModuleInWalk(ctx, coord, a.pipelineVersion, a.anchor.WalkID) //nolint:wrapcheck // as above
}

// selectSeed picks the record that seeds one coordinate. Anchored, it is the
// selection vuln-show --gomod makes in the same walk, so the two answer alike.
func (a *VulnStoreAdapter) selectSeed(candidates []vulndomain.VulnerabilityRecord, consumerModulePath string) (vulndomain.VulnerabilityRecord, bool, error) {
	if a.anchor != nil && a.anchor.Rooting.IsRecorded() {
		rec, _, _, found, err := vulndomain.ComposeInFrame(candidates, a.anchor.Rooting)
		return rec, found, err //nolint:wrapcheck // wrapped by the caller with the coordinate
	}
	return vulndomain.ComposeForTree(candidates, consumerModulePath) //nolint:wrapcheck // as above
}

// seedRestriction is the one-line statement of what the seed was drawn from,
// for the probe to report beside its answer.
func (a *VulnStoreAdapter) seedRestriction(consumerModulePath string) string {
	switch {
	case a.anchor == nil:
		return treeSeedRestriction(consumerModulePath)
	case a.anchor.ScanIncomplete:
		return fmt.Sprintf(
			"seed restricted to stored records scanned by %s, the newest project walk for this tree's go.mod, "+
				"whose vuln-scan did not complete; no walk of this tree has a completed scan, so nothing seeded this build",
			a.anchor.Source)
	case a.anchor.PassedOver != "":
		return fmt.Sprintf(
			"%s; seeded from %s, the newest project walk for this tree's go.mod whose scan completed, "+
				"in its own frame or in the isolated frame; records of other walks and of another consumer's build were not read",
			a.anchor.PassedOver, a.anchor.Source)
	}
	return fmt.Sprintf(
		"seed restricted to stored records scanned by %s, the newest project walk for this tree's go.mod, "+
			"in its own frame or in the isolated frame; records of older walks and of another consumer's build were not read",
		a.anchor.Source)
}

// treeSeedRestriction states the seed boundary when no walk anchors it.
func treeSeedRestriction(consumerModulePath string) string {
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

// supersededOnly reports whether the store holds this coordinate only at
// pipeline versions this loader does not read.
//
// It runs on the empty path only, and it is advisory: a census that fails to
// read leaves the coordinate in the plain uncovered bucket, which is less
// precise and never wrong. A coverage note may not become a load failure.
func (a *VulnStoreAdapter) supersededOnly(ctx context.Context, coord coordinate.ModuleCoordinate) bool {
	gens, err := a.store.ListVulnerabilityRecordGenerationsForModule(ctx, coord)
	if err != nil || len(gens) == 0 {
		return false
	}
	for _, g := range gens {
		if g.PipelineVersion == a.pipelineVersion {
			return false
		}
	}
	return true
}

// classifyEmpty records which absence an empty read is: no completed scan to
// read, superseded only, held only by walks other than the seed walk, or never
// scanned (no set). A walk whose scan did not complete reads empty for every
// coordinate, so that reason comes first.
func (a *VulnStoreAdapter) classifyEmpty(ctx context.Context, coord coordinate.ModuleCoordinate, result *ports.FindingSet) {
	switch {
	case a.anchor != nil && a.anchor.ScanIncomplete:
		result.ScanIncomplete[coord] = struct{}{}
	case a.supersededOnly(ctx, coord):
		result.SupersededOnly[coord] = struct{}{}
	case a.heldOutsideAnchor(ctx, coord):
		result.NotInSeedWalk[coord] = struct{}{}
	}
}

// heldOutsideAnchor reports whether an anchored load found nothing in the seed
// walk for a coordinate the store does hold at this pipeline version — another
// walk scanned it, so "never vuln-scanned" would be false. Advisory, on the
// terms supersededOnly states.
func (a *VulnStoreAdapter) heldOutsideAnchor(ctx context.Context, coord coordinate.ModuleCoordinate) bool {
	if a.anchor == nil {
		return false
	}
	recs, err := a.store.ListVulnerabilityRecordsForModule(ctx, coord, a.pipelineVersion)
	return err == nil && len(recs) > 0
}

// notAnalysed reports whether a record says its module was not analysed. A
// record stating nothing about coverage is not read as a failure.
func notAnalysed(r vulndomain.VulnerabilityRecord) bool {
	if r.OverallStatus == "" && r.UnscanReason == "" && r.UnscannableReason == "" && r.ErrorDetail == "" {
		return false
	}
	return vulndomain.DetermineRecordCoverage(r) != vulndomain.CoverageAnalysed
}
