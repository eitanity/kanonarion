package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"time"

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

// runCallGraphList prints what the ledger HOLDS, read from the record table's
// columns and nothing else.
//
// COORDINATES, NOT SUMMARIES. Every field this listing prints — the coordinate,
// the pipeline version, the status, the node and edge counts — is a column on
// callgraph_records. The summary listing answers the different question "what
// does the served generation say", and for every coordinate holding more than
// one generation that means composing them: a blob decode plus a full
// reconstruction of each generation's edge set, to read eight scalars off the
// winner. On this ledger's scale that was the whole cost of the command, and
// none of it reached the output.
//
// So a re-analysed coordinate is not collapsed into one composed row here. The
// row says how many generations it holds and names the one its counts came
// from, and where those generations do not agree with one another it states
// that instead of putting one generation's numbers forward as the coordinate's.
// Composition remains exactly as it was for the reads that serve ONE coordinate
// — callgraph-show, callers, callees — where picking a winner is the question
// being asked.
func runCallGraphList(ctx context.Context, moduleFilter string, limit, offset int, uc QueryCallGraphUseCase, stdout, stderr io.Writer) error {
	// One row more than will be printed: the extra row's presence is what tells
	// this listing whether it withheld anything, and it costs one row rather
	// than a second read.
	coords, err := uc.ListCallGraphCoordinates(ctx, ports.CallGraphFilter{
		ModulePath: moduleFilter,
		Limit:      truncationFetchLimit(limit),
		Offset:     offset,
	})
	if err != nil {
		return fmt.Errorf("listing callgraph records: %w", err)
	}
	coords, truncated := truncateList(coords, limit)
	trunc := listTruncation{limit: limit, subject: "call graph records", truncated: truncated, offset: offset}

	if jsonOut {
		out := make([]callGraphListEntry, 0, len(coords))
		for _, c := range coords {
			out = append(out, callGraphListJSON(c))
		}
		enc := json.NewEncoder(stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(out); err != nil {
			return fmt.Errorf("encoding JSON: %w", err)
		}
		if len(coords) == 0 {
			scope, serr := callGraphListZeroScope(ctx, moduleFilter, offset, uc)
			if serr != nil {
				return serr
			}
			return writeListZeroNoticeJSON(stderr, scope)
		}
		return writeListTruncationJSON(stderr, trunc)
	}

	if len(coords) == 0 {
		scope, serr := callGraphListZeroScope(ctx, moduleFilter, offset, uc)
		if serr != nil {
			return serr
		}
		return writeListZeroNotice(stdout, scope)
	}

	for _, c := range coords {
		if err := writeCallGraphListRow(stdout, c); err != nil {
			return err
		}
	}
	return writeListTruncationNotice(stdout, trunc)
}

// writeCallGraphListRow prints ONE line per coordinate, whatever its history.
//
// A coordinate with one generation prints exactly the line it always has: the
// only generation is the served one, so naming it would state something the
// reader can already see. A coordinate whose generations all say the same thing
// prints those numbers too, and names the generation they were read off, since
// every other generation states them as well.
//
// Where the generations do NOT agree, no count is printed at all. Putting one
// generation's numbers on the row would make it the coordinate's answer, and
// which generation a read serves is decided by composition — work this listing
// does not do. The row says the generations differ and names the command that
// shows them, which is the whole of what the columns can prove.
//
// The per-generation lines this used to print are gone: a store holding 65
// analyses of one module turned a 20-row page into 93 lines of history nobody
// asked a listing for. callgraph-show --history is where a coordinate's
// generations belong, and it prints what a listing structurally cannot — the
// toolchain, the origin, and which generation is served.
func writeCallGraphListRow(stdout io.Writer, c ports.CallGraphCoordinate) error {
	coord := c.ModulePath + "@" + c.ModuleVersion
	head, ok := headlineGeneration(c)
	if !ok {
		// A store that lists coordinates without enumerating their generations has
		// no counts to print, and inventing zeroes would read as a measured empty
		// graph.
		_, err := fmt.Fprintf(stdout, "%-60s %-12s (this store reports no per-generation counts)\n",
			coord, c.PipelineVersion)
		if err != nil {
			return fmt.Errorf("writing summary: %w", err)
		}
		return nil
	}

	if c.GenerationsDiffer {
		_, err := fmt.Fprintf(stdout, "%-60s %-12s %d generations state different counts, status or completeness; run: kanonarion callgraph-show %s --history\n",
			coord, c.PipelineVersion, len(c.Generations), coord)
		if err != nil {
			return fmt.Errorf("writing summary: %w", err)
		}
		return nil
	}

	line := fmt.Sprintf("%-60s %-12s %s %5d nodes %5d edges",
		coord, c.PipelineVersion,
		head.OverallStatus.String(), head.NodeCount, head.EdgeCount)
	if len(c.Generations) > 1 {
		line += fmt.Sprintf("  [%d generations; counts from %s]",
			len(c.Generations), head.ExtractedAt.Format(time.RFC3339))
	}
	if _, err := fmt.Fprintln(stdout, line); err != nil {
		return fmt.Errorf("writing summary: %w", err)
	}
	return nil
}

// headlineGeneration is the generation whose counts head the row: the most
// recently extracted one, which is the order the listing returns them in.
//
// It is NOT the generation composition serves — that one is chosen by the
// completeness ladder and can be an older row, and deciding it is the read the
// listing exists not to perform. The row names this generation whenever there
// is more than one, so nothing is presented as the coordinate's settled answer.
func headlineGeneration(c ports.CallGraphCoordinate) (ports.CallGraphGeneration, bool) {
	if len(c.Generations) == 0 {
		return ports.CallGraphGeneration{}, false
	}
	return c.Generations[0], true
}

// callGraphListEntry is the JSON shape of one row. The headline fields carry
// the same values they always have for a coordinate with one generation, and
// counts_from plus generations appear only where there is more than one — so a
// count is never printed without the reader being able to see whose it is.
//
// The headline fields are pointers, and they are emitted whether or not they
// carry a value: null and 0 are different answers, and a coordinate whose
// generations disagree states no headline count at all, for the reason
// writeCallGraphListRow gives. Omitting them instead would make "no count is
// stated" indistinguishable from a build that does not derive one, which is
// what the package-wide scalar-omitempty guard exists to prevent.
//
// The generations array stays, unlike in the text rows. Its cost there was a
// terminal page and JSON has no page, while an agent without it pays one extra
// invocation per coordinate to rebuild what this call already read. The two
// surfaces carry different amounts of detail; they state no different facts.
type callGraphListEntry struct {
	Module            string                    `json:"module"`
	Version           string                    `json:"version"`
	PipelineVersion   string                    `json:"pipeline_version"`
	Status            *string                   `json:"status"`
	NodeCount         *int                      `json:"node_count"`
	EdgeCount         *int                      `json:"edge_count"`
	GenerationsDiffer bool                      `json:"generations_differ"`
	CountsFrom        string                    `json:"counts_from,omitempty"`
	Generations       []callGraphGenerationJSON `json:"generations,omitempty"`
}

type callGraphGenerationJSON struct {
	ExtractedAt string `json:"extracted_at"`
	Status      string `json:"status"`
	NodeCount   int    `json:"node_count"`
	EdgeCount   int    `json:"edge_count"`
	ContentHash string `json:"content_hash"`
}

func callGraphListJSON(c ports.CallGraphCoordinate) callGraphListEntry {
	e := callGraphListEntry{
		Module:          c.ModulePath,
		Version:         c.ModuleVersion,
		PipelineVersion: c.PipelineVersion,
	}
	head, ok := headlineGeneration(c)
	if !ok {
		return e
	}
	e.GenerationsDiffer = c.GenerationsDiffer
	if !c.GenerationsDiffer {
		status, nodes, edges := head.OverallStatus.String(), head.NodeCount, head.EdgeCount
		e.Status = &status
		e.NodeCount = &nodes
		e.EdgeCount = &edges
	}
	if len(c.Generations) == 1 {
		return e
	}
	if !c.GenerationsDiffer {
		e.CountsFrom = head.ExtractedAt.Format(time.RFC3339)
	}
	for _, g := range c.Generations {
		e.Generations = append(e.Generations, callGraphGenerationJSON{
			ExtractedAt: g.ExtractedAt.Format(time.RFC3339),
			Status:      g.OverallStatus.String(),
			NodeCount:   g.NodeCount,
			EdgeCount:   g.EdgeCount,
			ContentHash: g.ContentHash,
		})
	}
	return e
}

// callGraphListZeroScope lifts the filter and paging and re-asks the store, so a
// zero can say whether the module path matched nothing or there was nothing to
// match. Reached only when the listing came back empty.
//
// It counts coordinates for the same reason the listing prints them: "how many
// are there" is a question about the ledger's keys, and asking it of the
// composing listing made the cheapest possible answer — an empty one — the most
// expensive command in the store.
func callGraphListZeroScope(ctx context.Context, moduleFilter string, offset int, uc QueryCallGraphUseCase) (listZeroScope, error) {
	all, err := uc.ListCallGraphCoordinates(ctx, ports.CallGraphFilter{})
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
	// An empty corpus is not something a page can start past, so a zero over it
	// keeps the store-empty statement and its produce-a-record remedy.
	if moduleFilter == "" && len(all) > 0 && offset > 0 && offset >= len(all) {
		scope.pagedPast = fmt.Sprintf("--offset %d starts past the last one", offset)
	}
	return scope, nil
}
