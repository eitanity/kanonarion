package cli

import (
	"context"
	"fmt"

	cgdomain "github.com/eitanity/kanonarion/internal/callgraph/domain"
)

// analysisInputsForWalk reads the resolved build list of a named walk so a
// pre-modules module can be analysed against the versions that walk selected.
//
// A module published before Go modules ships no go.mod, so nothing in the
// artefact says which versions of its imports to load. The walk does: it already
// resolved one version per module for the build that wants the answer, and
// pinning to those is what keeps the resulting graph joined to the rest of the
// ledger instead of naming coordinates nobody chose.
//
// An empty walk ID returns the zero inputs, which offer nothing. That is the
// honest answer for a coordinate asked about on its own, and synthesis refuses a
// module needing requires exactly as it did before this existed. A walk ID that
// does not resolve is an error rather than a silent fallback: a caller who named
// a build is entitled to be told the answer did not come from it.
func analysisInputsForWalk(ctx context.Context, walks QueryWalksUseCase, walkID string) (cgdomain.AnalysisInputs, error) {
	if walkID == "" {
		return cgdomain.AnalysisInputs{}, nil
	}
	rec, err := walks.GetWalk(ctx, walkID)
	if err != nil {
		return cgdomain.AnalysisInputs{}, fmt.Errorf("--from-walk: loading walk %q: %w", walkID, err)
	}
	return cgdomain.AnalysisInputs{
		BuildList: rec.Graph.SelectedVersions(),
		Source:    rec.ID,
	}, nil
}
