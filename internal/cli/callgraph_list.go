package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"io"

	"github.com/eitanity/kanonarion/internal/callgraph/ports"
	"github.com/spf13/cobra"
)

func newCallGraphListCmd(stdout, stderr io.Writer) *cobra.Command {
	var moduleFilter string
	var limit, offset int

	cmd := &cobra.Command{
		Use:   "callgraph-list [<module>]",
		Short: "List extracted call graph records",
		Example: `  kanonarion callgraph-list
  kanonarion callgraph-list github.com/spf13/cobra`,
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) > 1 {
				return fmt.Errorf("accepts at most 1 arg, received %d", len(args))
			}
			if len(args) == 1 {
				moduleFilter = args[0]
			}
			logger := buildLogger(logLevel, stderr)
			ctr, cleanup, err := NewContainer(storeRoot, "", "", false, activeConfig, logger)
			if err != nil {
				return fmt.Errorf("initialising store: %w", err)
			}
			defer func() { _ = cleanup() }()
			return runCallGraphList(cmd.Context(), moduleFilter, limit, offset, ctr.QueryCallGraph, stdout)
		},
	}

	cmd.Flags().IntVar(&limit, "limit", 20, "maximum number of records to return (0 = unlimited)")
	cmd.Flags().IntVar(&offset, "offset", 0, "skip this many records")

	return cmd
}

func runCallGraphList(ctx context.Context, moduleFilter string, limit, offset int, uc QueryCallGraphUseCase, stdout io.Writer) error {
	summaries, err := uc.ListCallGraphRecords(ctx, ports.CallGraphFilter{
		ModulePath: moduleFilter,
		Limit:      limit,
		Offset:     offset,
	})
	if err != nil {
		return fmt.Errorf("listing callgraph records: %w", err)
	}

	if jsonOut {
		type entry struct {
			Module          string `json:"module"`
			Version         string `json:"version"`
			PipelineVersion string `json:"pipeline_version"`
			Status          string `json:"status"`
			NodeCount       int    `json:"node_count"`
			EdgeCount       int    `json:"edge_count"`
		}
		out := make([]entry, 0, len(summaries))
		for _, s := range summaries {
			out = append(out, entry{s.ModulePath, s.ModuleVersion, s.PipelineVersion, s.OverallStatus.String(), s.NodeCount, s.EdgeCount})
		}
		enc := json.NewEncoder(stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(out); err != nil {
			return fmt.Errorf("encoding JSON: %w", err)
		}
		return nil
	}

	if len(summaries) == 0 {
		if _, err := fmt.Fprintln(stdout, "No call graph records found."); err != nil {
			return fmt.Errorf("writing output: %w", err)
		}
		return nil
	}

	for _, s := range summaries {
		if _, err := fmt.Fprintf(stdout, "%-60s %-12s %s %5d nodes %5d edges\n",
			s.ModulePath+"@"+s.ModuleVersion, s.PipelineVersion,
			s.OverallStatus.String(), s.NodeCount, s.EdgeCount,
		); err != nil {
			return fmt.Errorf("writing summary: %w", err)
		}
	}
	return nil
}
