package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"io"

	"github.com/eitanity/kanonarion/internal/walk/application"
	"github.com/spf13/cobra"
)

func newWalkDiffCmd(stdout, _ io.Writer) *cobra.Command {
	var f commonWalkFlags

	cmd := &cobra.Command{
		Use:   "walk-diff <id-a> <id-b>",
		Short: "Print the diff between two walk records",
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) != 2 {
				return usageErr(cmd)
			}
			logger := buildLogger(logLevel, stdout)
			ctr, cleanup, err := NewContainer(storeRoot, "", "", false, activeConfig, logger)
			if err != nil {
				return fmt.Errorf("initialising store: %w", err)
			}
			defer func() { _ = cleanup() }()
			return runWalkDiff(cmd.Context(), f, args[0], args[1], ctr.DiffWalks, stdout)
		},
	}
	return cmd
}
func runWalkDiff(ctx context.Context, f commonWalkFlags, idA, idB string, uc DiffWalksUseCase, stdout io.Writer) error {
	diff, err := uc.Diff(ctx, idA, idB)
	if err != nil {
		if isWalkNotFound(err) {
			return &exitError{code: ExitConfig, msg: "one or both walk IDs not found"}
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
