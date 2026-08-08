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
		Use:   "walk-diff <id-a> <id-b>",
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
		enc := json.NewEncoder(stdout)
		enc.SetIndent("", "  ")
		if encErr := enc.Encode(toWalkDiffJSON(diff)); encErr != nil {
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
	return nil
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
