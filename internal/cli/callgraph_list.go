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
			return runCallGraphList(cmd.Context(), moduleFilter, limit, offset, ctr.QueryCallGraph, stdout, stderr)
		},
	}

	cmd.Flags().IntVar(&limit, "limit", 20, "maximum number of records to return (0 = unlimited)")
	cmd.Flags().IntVar(&offset, "offset", 0, "skip this many records")

	return cmd
}

func runCallGraphList(ctx context.Context, moduleFilter string, limit, offset int, uc QueryCallGraphUseCase, stdout, stderr io.Writer) error {
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
		if len(summaries) == 0 {
			scope, serr := callGraphListZeroScope(ctx, moduleFilter, offset, uc)
			if serr != nil {
				return serr
			}
			return writeListZeroNoticeJSON(stderr, scope)
		}
		return nil
	}

	if len(summaries) == 0 {
		scope, serr := callGraphListZeroScope(ctx, moduleFilter, offset, uc)
		if serr != nil {
			return serr
		}
		return writeListZeroNotice(stdout, scope)
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

// callGraphListZeroScope lifts the filter and paging and re-asks the store, so a
// zero can say whether the module path matched nothing or there was nothing to
// match. Reached only when the listing came back empty.
func callGraphListZeroScope(ctx context.Context, moduleFilter string, offset int, uc QueryCallGraphUseCase) (listZeroScope, error) {
	all, err := uc.ListCallGraphRecords(ctx, ports.CallGraphFilter{})
	if err != nil {
		return listZeroScope{}, fmt.Errorf("counting callgraph records for the zero-result notice: %w", err)
	}
	scope := listZeroScope{
		subject:     "call graph record",
		filterName:  "module path",
		filterValue: moduleFilter,
		field:       "module path",
		matchKind:   matchExact,
		considered:  len(all),
		produce:     "kanonarion callgraph <module>@<version>",
		listAll:     "kanonarion callgraph-list",
	}
	if len(all) > 0 {
		scope.example = all[0].ModulePath
	}
	// An offset past the end empties the page without the filter having anything
	// to do with it, and the two look identical from the rows alone.
	if moduleFilter == "" && offset > 0 && offset >= len(all) {
		scope.pagedPast = fmt.Sprintf("--offset %d starts past the last one", offset)
	}
	return scope, nil
}
