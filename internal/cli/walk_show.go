package cli

import (
	"context"
	"fmt"
	"io"

	"github.com/eitanity/kanonarion/internal/walk/domain"
	"github.com/spf13/cobra"
)

func newWalkShowCmd(stdout, stderr io.Writer) *cobra.Command {

	cmd := &cobra.Command{
		Use:   "walk-show <id>",
		Short: "Print a stored walk record",
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) != 1 {
				return usageErr(cmd)
			}
			logger := buildLogger(logLevel, stderr)
			ctr, cleanup, err := NewContainer(storeRoot, "", "", false, activeConfig, logger)
			if err != nil {
				return fmt.Errorf("initialising store: %w", err)
			}
			defer func() { _ = cleanup() }()
			return runWalkShow(cmd.Context(), args[0], ctr.QueryWalks, stdout, stderr)
		},
	}
	return cmd
}
func runWalkShow(ctx context.Context, id string, uc QueryWalksUseCase, stdout, stderr io.Writer) error {
	rec, err := uc.GetWalk(ctx, id)
	if err != nil {
		if isWalkNotFound(err) {
			return &exitError{code: ExitNotFound, msg: fmt.Sprintf("walk record %q not found", id)}
		}
		if isWalkIntegrity(err) {
			return &exitError{code: ExitIntegrity, msg: fmt.Sprintf("walk record %q failed integrity check", id)}
		}
		return fmt.Errorf("getting walk: %w", err)
	}

	if jsonOut {
		if encErr := writeWalkRecordJSON(stdout, rec); encErr != nil {
			return fmt.Errorf("encoding JSON: %w", encErr)
		}
		// stdout is the record's own sealed bytes and nothing else — a caveat
		// added there would change what the record hashes over. It goes to stderr,
		// where it reaches the reader without touching the artefact.
		return writeWalkPreModulesCaveat(stderr, rec.Graph)
	}

	if _, pErr := fmt.Fprintf(stdout, "Walk %s\n", rec.ID); pErr != nil {
		return fmt.Errorf("writing output: %w", pErr)
	}
	if _, pErr := fmt.Fprintf(stdout, "Target: %s\n", rec.Target.String()); pErr != nil {
		return fmt.Errorf("writing output: %w", pErr)
	}
	if _, pErr := fmt.Fprintf(stdout, "Status: %s\n", rec.OverallStatus.String()); pErr != nil {
		return fmt.Errorf("writing output: %w", pErr)
	}
	// A walk of a +incompatible module is one node and no edges, and the three
	// lines above give a reader no way to tell that from a module that genuinely
	// requires nothing. The target gets its own line only when the graph statement
	// would not already name it, so the ordinary case — a walk rooted AT the
	// pre-modules module — says it once.
	if !containsCoordinate(preModulesNodesIn(rec.Graph), rec.Target) {
		if err := writePreModulesCaveat(stdout, rec.Target); err != nil {
			return err
		}
	}
	return writeWalkPreModulesCaveat(stdout, rec.Graph)
}
func writeWalkRecordJSON(w io.Writer, r domain.WalkRecord) error {
	var h domain.WalkRecordHasher
	b, err := h.Marshal(r)
	if err != nil {
		return fmt.Errorf("marshalling walk record: %w", err)
	}
	if _, err := fmt.Fprintf(w, "%s\n", b); err != nil {
		return fmt.Errorf("writing walk record: %w", err)
	}
	return nil
}
