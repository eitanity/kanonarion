package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"github.com/eitanity/kanonarion/internal/walk/application"
	walkports "github.com/eitanity/kanonarion/internal/walk/ports"
	"github.com/spf13/cobra"
)

func newWalkDiffCmd(stdout, stderr io.Writer) *cobra.Command {

	cmd := &cobra.Command{
		Use: "walk-diff <id-a> <id-b>",
		Annotations: map[string]string{
			annotationStoreIntent: StoreIntentRead,
			annotationNetworkUse:  NetworkNever,
		},
		Short: "Print the diff between two walk records",
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) != 2 {
				return usageErr(cmd)
			}
			logger := buildLogger(logLevel, stderr)
			ctr, cleanup, err := NewContainer(storeRoot, "", "", false, activeConfig, logger)
			if err != nil {
				return fmt.Errorf("initialising store: %w", err)
			}
			defer func() { _ = cleanup() }()
			return runWalkDiff(cmd.Context(), args[0], args[1], ctr.DiffWalks, ctr.QueryWalks, stdout, stderr)
		},
	}
	return cmd
}
func runWalkDiff(ctx context.Context, idA, idB string, uc DiffWalksUseCase, walks QueryWalksUseCase,
	stdout, stderr io.Writer,
) error {
	diff, err := uc.Diff(ctx, idA, idB)
	if err != nil {
		if isWalkNotFound(err) {
			return walkDiffMiss(ctx, walks, idA, idB, stderr)
		}
		if isWalkIntegrity(err) {
			return &exitError{code: ExitIntegrity, msg: "walk record integrity check failed"}
		}
		return fmt.Errorf("computing diff: %w", err)
	}

	if jsonOut {
		// The statement is a field of the document, not a second object on
		// stderr. An empty diff is the reading of this command a caller acts on
		// directly, and a consumer reading the data channel could not tell it
		// from a comparison that ran over nothing.
		doc := toWalkDiffJSON(diff)
		if walkDiffIsEmpty(diff) {
			statement := walkDiffEmptyStatement(idA, idB, diff)
			doc.NoDifference = &statement
		}
		enc := json.NewEncoder(stdout)
		enc.SetIndent("", "  ")
		if encErr := enc.Encode(doc); encErr != nil {
			return fmt.Errorf("encoding JSON: %w", encErr)
		}
		return nil
	}

	if _, pErr := fmt.Fprintf(stdout, "diff %s..%s\n", idA, idB); pErr != nil {
		return fmt.Errorf("writing output: %w", pErr)
	}
	if diff.CompletenessMismatch != "" {
		if _, pErr := fmt.Fprintf(stdout, "UNRESOLVED: %s — added/removed below is an asymmetric comparison, not a confident resolution\n", diff.CompletenessMismatch); pErr != nil {
			return fmt.Errorf("writing output: %w", pErr)
		}
	}
	for _, c := range diff.Added {
		if _, pErr := fmt.Fprintf(stdout, "+ %s\n", c.String()); pErr != nil {
			return fmt.Errorf("writing output: %w", pErr)
		}
	}
	for _, c := range diff.Removed {
		if _, pErr := fmt.Fprintf(stdout, "- %s\n", c.String()); pErr != nil {
			return fmt.Errorf("writing output: %w", pErr)
		}
	}
	for _, vc := range diff.VersionChanged {
		if _, pErr := fmt.Fprintf(stdout, "~ %s: %s -> %s\n", vc.Path, vc.VersionA, vc.VersionB); pErr != nil {
			return fmt.Errorf("writing output: %w", pErr)
		}
	}
	for _, sc := range diff.StatusChanged {
		if _, pErr := fmt.Fprintf(stdout, "! %s: %s -> %s\n", sc.Coordinate.String(), sc.StatusA.String(), sc.StatusB.String()); pErr != nil {
			return fmt.Errorf("writing output: %w", pErr)
		}
	}
	if walkDiffIsEmpty(diff) {
		return writeWalkDiffEmpty(stdout, idA, idB, diff)
	}
	return nil
}

// walkDiffIsEmpty reports the diff with nothing to print under its header: no
// module added, none removed, no version moved and no per-node status changed.
func walkDiffIsEmpty(d application.WalkDiff) bool {
	return len(d.Added) == 0 && len(d.Removed) == 0 &&
		len(d.VersionChanged) == 0 && len(d.StatusChanged) == 0
}

// writeWalkDiffEmpty states an empty diff.
//
// The header alone was the whole output for two walks that agree, which is the
// one reading of this command a caller acts on directly: an empty diff is the
// evidence for "the dependency set did not move between these two builds", and
// a bare header is indistinguishable from a command that compared nothing. The
// statement therefore names both sides, the frame each was resolved in, and how
// many nodes were on each — the population the zero was measured over.
func writeWalkDiffEmpty(stdout io.Writer, idA, idB string, d application.WalkDiff) error {
	if idA == idB {
		if _, err := fmt.Fprintf(stdout,
			"no difference: both arguments name the same walk (%s, frame %s, %d node(s)), so this compared it with itself\n",
			idA, d.FrameA, d.NodesA); err != nil {
			return fmt.Errorf("writing output: %w", err)
		}
		return nil
	}
	if _, err := fmt.Fprintf(stdout,
		"no difference: %s (frame %s, %d node(s)) and %s (frame %s, %d node(s)) name the same modules at the same versions, and no node status changed\n",
		idA, d.FrameA, d.NodesA, idB, d.FrameB, d.NodesB); err != nil {
		return fmt.Errorf("writing output: %w", err)
	}
	if d.CompletenessMismatch != "" {
		// The UNRESOLVED line above already named the axis; what it cannot say on
		// its own is that a zero delta under an asymmetric comparison is not the
		// same claim as two walks agreeing.
		if _, err := fmt.Fprintf(stdout,
			"  the two walks were resolved at unequal completeness, so this is not a confident \"identical\"\n"); err != nil {
			return fmt.Errorf("writing output: %w", err)
		}
	}
	return nil
}

// walkDiffEmptyJSON is the machine-readable form of that statement. It is a
// field of the diff document, present only when the diff is empty, and it keeps
// the field names it had when it was written on its own.
type walkDiffEmptyJSON struct {
	Statement string `json:"statement"`
	WalkA     string `json:"walk_a"`
	WalkB     string `json:"walk_b"`
	// FrameA and FrameB are the frames the two sides answer in, each with the
	// basis that says whether a platform applies at all. Two walks that resolve
	// no platform share a token because neither has a frame, not because their
	// frames matched — the basis is what a consumer keys on.
	FrameA      string `json:"frame_a"`
	FrameABasis string `json:"frame_a_basis"`
	FrameB      string `json:"frame_b"`
	FrameBBasis string `json:"frame_b_basis"`
	NodesA      int    `json:"nodes_a"`
	NodesB      int    `json:"nodes_b"`
	SameWalk    bool   `json:"same_walk"`
	Unresolved  string `json:"unresolved,omitempty"`
}

func walkDiffEmptyStatement(idA, idB string, d application.WalkDiff) walkDiffEmptyJSON {
	statement := "no difference: the two walks name the same modules at the same versions, and no node status changed"
	if idA == idB {
		statement = "no difference: both arguments name the same walk, so this compared it with itself"
	}
	return walkDiffEmptyJSON{
		Statement:   statement,
		WalkA:       idA,
		WalkB:       idB,
		FrameA:      d.FrameA.Text,
		FrameABasis: string(d.FrameA.Basis),
		FrameB:      d.FrameB.Text,
		FrameBBasis: string(d.FrameB.Basis),
		NodesA:      d.NodesA,
		NodesB:      d.NodesB,
		SameWalk:    idA == idB,
		Unresolved:  d.CompletenessMismatch,
	}
}

// walkDiffMiss answers a diff whose operands the store does not both hold.
//
// `one or both walk IDs not found` is the worst answer of the class it belongs
// to: a caller with one good id and one typo is told nothing about either, so
// the cheapest way to find out which is to run walk-show twice. The two ids are
// therefore looked up individually and the missing side is named — the whole
// point of the command is that it took two operands.
//
// The corpus comes from the walk query use case rather than from the diff use
// case, which has no listing method. Routing the count through the use case that
// already lists is what keeps the port unchanged; sizing the corpus from the two
// ids in hand would have reported a corpus of two, which is a measurement of the
// argument list and not of the store.
//
// Everything here is on the miss branch: a diff whose two walks were both found
// never looks anything up a second time.
func walkDiffMiss(ctx context.Context, walks QueryWalksUseCase, idA, idB string, stderr io.Writer) error {
	missing := make([]string, 0, 2)
	for _, id := range []string{idA, idB} {
		if _, err := walks.GetWalk(ctx, id); err != nil {
			if !isWalkNotFound(err) {
				return fmt.Errorf("checking walk %s for the not-found notice: %w", id, err)
			}
			missing = append(missing, id)
		}
	}
	if len(missing) == 0 {
		// The diff reported a missing walk and both ids read back. Nothing here
		// can name a side, and inventing one would be worse than the sentence
		// this function replaced.
		return fmt.Errorf("diffing walks %s and %s: %w", idA, idB, walkports.ErrWalkNotFound)
	}
	scope, serr := walkIDZeroScope(ctx, strings.Join(missing, ", "), walks)
	if serr != nil {
		return serr
	}
	// Which operand slot the missing id came from, so a caller reading the
	// message does not have to compare strings to find out which of the two they
	// have to correct.
	side := "the <id-a> argument"
	switch {
	case len(missing) == 2:
		side = "both arguments"
	case missing[0] == idB:
		side = "the <id-b> argument"
	}
	if jsonOut {
		if werr := writeListZeroNoticeJSON(stderr, scope); werr != nil {
			return werr
		}
	}
	return &exitError{code: ExitNotFound, msg: fmt.Sprintf("%s named a walk the store does not hold; %s",
		side, listZeroLine(scope))}
}

// walkDiffJSON is the compact, AI-friendly JSON representation of a walk diff.
// All slice fields are non-nil so they always appear as [] in output, never null.
type walkDiffJSON struct {
	WalkA              string         `json:"walk_a"`
	WalkB              string         `json:"walk_b"`
	Added              []string       `json:"added"`
	Removed            []string       `json:"removed"`
	Upgraded           []upgradeEntry `json:"upgraded"`
	LicenseRegressions []string       `json:"license_regressions"`
	NewReachableCVEs   []string       `json:"new_reachable_cves"`
	// Unresolved names a completeness mismatch (differing scope/depth) that makes
	// the added/removed sets an asymmetric comparison; empty when the walks are
	// completeness-comparable.
	Unresolved string `json:"unresolved,omitempty"`
	// NoDifference is present only when the four delta sets are all empty. Four
	// empty arrays are the same bytes whether the walks agree or the comparison
	// was asymmetric, and this is what separates them.
	NoDifference *walkDiffEmptyJSON `json:"no_difference,omitempty"`
}
type upgradeEntry struct {
	Module    string   `json:"module"`
	From      string   `json:"from"`
	To        string   `json:"to"`
	FixedCVEs []string `json:"fixed_cves"`
}

func toWalkDiffJSON(d application.WalkDiff) walkDiffJSON {
	added := make([]string, len(d.Added))
	for i, c := range d.Added {
		added[i] = c.String()
	}
	removed := make([]string, len(d.Removed))
	for i, c := range d.Removed {
		removed[i] = c.String()
	}
	upgraded := make([]upgradeEntry, len(d.VersionChanged))
	for i, vc := range d.VersionChanged {
		upgraded[i] = upgradeEntry{
			Module:    vc.Path,
			From:      vc.VersionA,
			To:        vc.VersionB,
			FixedCVEs: []string{},
		}
	}
	return walkDiffJSON{
		WalkA:              d.WalkA,
		WalkB:              d.WalkB,
		Added:              added,
		Removed:            removed,
		Upgraded:           upgraded,
		LicenseRegressions: []string{},
		NewReachableCVEs:   []string{},
		Unresolved:         d.CompletenessMismatch,
	}
}
