package cli

import (
	"context"
	"fmt"
	"io"

	"github.com/eitanity/kanonarion/internal/walk/domain"
	"github.com/spf13/cobra"
)

func newWalkShowCmd(stdout, _ io.Writer) *cobra.Command {
	var f commonWalkFlags

	cmd := &cobra.Command{
		Use:   "walk-show <id>",
		Short: "Print a stored walk record",
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) != 1 {
				return usageErr(cmd)
			}
			logger := buildLogger(logLevel, stdout)
			ctr, cleanup, err := NewContainer(storeRoot, "", "", false, activeConfig, logger)
			if err != nil {
				return fmt.Errorf("initialising store: %w", err)
			}
			defer func() { _ = cleanup() }()
			return runWalkShow(cmd.Context(), f, args[0], ctr.QueryWalks, stdout)
		},
	}
	return cmd
}
func runWalkShow(ctx context.Context, f commonWalkFlags, id string, uc QueryWalksUseCase, stdout io.Writer) error {
	rec, err := uc.GetWalk(ctx, id)
	if err != nil {
		if isWalkNotFound(err) {
			return &exitError{code: ExitConfig, msg: fmt.Sprintf("walk record %q not found", id)}
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
		return nil
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
	return nil
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
