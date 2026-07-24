package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"time"

	vuldomain "github.com/eitanity/kanonarion/internal/vuln/domain"

	"github.com/spf13/cobra"
)

func newVulnSnapshotListCmd(stdout, stderr io.Writer) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "vuln-snapshot-list",
		Short: "List stored vulnerability database snapshots",
		RunE: func(cmd *cobra.Command, _ []string) error {
			logger := buildLogger(logLevel, stderr)
			ctr, cleanup, err := NewContainer(storeRoot, "", "", false, activeConfig, logger)
			if err != nil {
				return fmt.Errorf("initialising store: %w", err)
			}
			defer func() { _ = cleanup() }()
			return runSnapshotList(cmd.Context(), jsonOut, ctr.QueryScanRuns, stdout)
		},
	}

	return cmd
}

func runSnapshotList(ctx context.Context, jsonOut bool, uc QueryScanRunsUseCase, stdout io.Writer) error {
	snapshots, err := uc.ListSnapshots(ctx)
	if err != nil {
		return fmt.Errorf("listing snapshots: %w", err)
	}
	// The empty case is answered on the caller's own channel: under --json an
	// empty array, never a human sentence that fails to parse. Only the text
	// path gets the prose.
	if jsonOut {
		enc := json.NewEncoder(stdout)
		enc.SetIndent("", "  ")
		if snapshots == nil {
			snapshots = []vuldomain.DatabaseSnapshot{}
		}
		if err := enc.Encode(snapshots); err != nil {
			return fmt.Errorf("encoding snapshots: %w", err)
		}
		return nil
	}

	if len(snapshots) == 0 {
		_, _ = fmt.Fprintln(stdout, "no snapshots found")
		return nil
	}

	for _, s := range snapshots {
		_, _ = fmt.Fprintf(stdout, "%-30s %-20s %s\n",
			s.Source, s.Version, s.RetrievedAt.UTC().Format("2006-01-02T15:04:05Z"))
	}
	return nil
}

func newVulnSnapshotShowCmd(stdout, stderr io.Writer) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "vuln-snapshot-show <source> <version>",
		Short: "Show metadata for a specific vulnerability database snapshot",
		Example: `  kanonarion vuln-snapshot-show govulndb v2024-01-01T00-00-00
  kanonarion vuln-snapshot-show govulndb v2024-01-01T00-00-00 --json`,
		Args: cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			logger := buildLogger(logLevel, stderr)
			ctr, cleanup, err := NewContainer(storeRoot, "", "", false, activeConfig, logger)
			if err != nil {
				return fmt.Errorf("initialising store: %w", err)
			}
			defer func() { _ = cleanup() }()
			return runSnapshotShow(cmd.Context(), args[0], args[1], jsonOut, ctr.QueryScanRuns, stdout)
		},
	}

	return cmd
}

func runSnapshotShow(ctx context.Context, source, version string, jsonOut bool, uc QueryScanRunsUseCase, stdout io.Writer) error {
	snapshots, err := uc.ListSnapshots(ctx)
	if err != nil {
		return fmt.Errorf("listing snapshots: %w", err)
	}

	for _, s := range snapshots {
		if s.Source == source && s.Version == version {
			if jsonOut {
				enc := json.NewEncoder(stdout)
				enc.SetIndent("", "  ")
				if err := enc.Encode(s); err != nil {
					return fmt.Errorf("encoding snapshot: %w", err)
				}
				return nil
			}
			_, _ = fmt.Fprintf(stdout, "Source:       %s\n", s.Source)
			_, _ = fmt.Fprintf(stdout, "Version:      %s\n", s.Version)
			_, _ = fmt.Fprintf(stdout, "Retrieved at: %s\n", s.RetrievedAt.UTC().Format(time.RFC3339))
			_, _ = fmt.Fprintf(stdout, "Content hash: %s\n", s.ContentHash)
			return nil
		}
	}
	return fmt.Errorf("snapshot not found: %s@%s", source, version)
}
