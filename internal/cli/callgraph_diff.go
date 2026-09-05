package cli

import (
	"context"
	"fmt"
	"io"
	"time"

	cgapp "github.com/eitanity/kanonarion/internal/callgraph/application"
	"github.com/eitanity/kanonarion/internal/callgraph/domain"
	"github.com/eitanity/kanonarion/internal/coordinate"
)

// runCallGraphDiff compares the distinct graphs the ledger holds for one
// coordinate and reports what they differ about.
//
// It is the instrument the composed read's refusal names. --history lists the
// generations and their digests, which tells a reader THAT two measurements
// disagree; nothing until now told them what about, and adjudicating a graph of
// seventeen thousand edges by eye is not a thing an operator can do.
func runCallGraphDiff(ctx context.Context, coord coordinate.ModuleCoordinate, f callGraphShowFlags, jsonOut bool, uc QueryCallGraphUseCase, stdout io.Writer) error {
	recs, err := uc.CallGraphHistory(ctx, coord, cgapp.PipelineVersion)
	if err != nil {
		return fmt.Errorf("reading callgraph history: %w", err)
	}
	if len(recs) == 0 {
		return &exitError{code: ExitNotFound, msg: fmt.Sprintf(
			"no callgraph records for %s at pipeline %s — analyse it first:\n  %s",
			coord, cgapp.PipelineVersion, domain.ReanalysisInstruction(coord, ""))}
	}

	measurements := groupBy(recs, domain.MeasurementDigest)
	// The graph count is taken over one generation per measurement, not over every
	// generation. Two generations of one measurement state the same record apart
	// from when it was taken, so they state the same graph — and a digest of a
	// four-million-edge record is not something to compute more often than the
	// answer needs.
	graphs := len(groupBy(representatives(measurements), domain.GraphDigest))
	if len(measurements) < 2 {
		if jsonOut {
			return encodeJSON(stdout, callGraphDiffJSON{
				Coordinate:       coordinateJSON{Path: coord.Path(), Version: coord.Version()},
				PipelineVersion:  cgapp.PipelineVersion,
				Generations:      len(recs),
				DistinctMeasures: len(measurements),
				DistinctGraphs:   graphs,
			})
		}
		_, werr := fmt.Fprintf(stdout,
			"%d generation(s) for %s at pipeline %s, all stating the same measurement — nothing to compare\n",
			len(recs), coord, cgapp.PipelineVersion)
		if werr != nil {
			return fmt.Errorf("writing output: %w", werr)
		}
		return nil
	}

	left, right := measurements[0][0], measurements[1][0]
	diff, err := domain.DiffGenerations(left, right)
	if err != nil {
		return fmt.Errorf("comparing generations of %s: %w", coord, err)
	}
	counts := diffCounts{generations: len(recs), measurements: len(measurements), graphs: graphs}

	if jsonOut {
		return encodeJSON(stdout, toCallGraphDiffJSON(coord, counts, left, right, diff))
	}
	return printGenerationDiff(stdout, coord, counts, left, right, diff, f)
}

// diffCounts is how many generations the ledger holds and how many distinct
// things they say. The two counts are separate answers: generations that state
// two measurements and one graph agree about the module and differ about what
// they were asked, which is the whole distinction a reader is here for.
type diffCounts struct{ generations, measurements, graphs int }

// representatives is the first generation of each group.
func representatives(groups [][]domain.CallGraphRecord) []domain.CallGraphRecord {
	out := make([]domain.CallGraphRecord, 0, len(groups))
	for _, g := range groups {
		out = append(out, g[0])
	}
	return out
}

// groupBy groups generations by a digest of them, keeping both the groups and
// the generations within them in append order.
//
// It never groups by content hash: that is sealed over the time of measurement,
// so two runs a second apart that produced the identical record carry different
// content hashes and every re-analysis would read as a distinct answer.
func groupBy(recs []domain.CallGraphRecord, digest func(domain.CallGraphRecord) string) [][]domain.CallGraphRecord {
	var order []string
	byDigest := map[string][]domain.CallGraphRecord{}
	for _, r := range recs {
		d := digest(r)
		if _, seen := byDigest[d]; !seen {
			order = append(order, d)
		}
		byDigest[d] = append(byDigest[d], r)
	}
	out := make([][]domain.CallGraphRecord, 0, len(order))
	for _, d := range order {
		out = append(out, byDigest[d])
	}
	return out
}

func printGenerationDiff(stdout io.Writer, coord coordinate.ModuleCoordinate, counts diffCounts,
	left, right domain.CallGraphRecord, diff domain.GenerationDiff, f callGraphShowFlags,
) error {
	var b []byte
	line := func(format string, args ...any) {
		b = append(b, fmt.Sprintf(format, args...)...)
	}
	line("%d generation(s) for %s at pipeline %s, stating %d distinct measurement(s) and %d distinct graph(s)\n",
		counts.generations, coord, cgapp.PipelineVersion, counts.measurements, counts.graphs)
	if counts.graphs == 1 {
		line("the graphs agree; the generations differ in what they were asked\n")
	}
	line("\ncomparing the first generation of the first two measurements:\n")
	line("  left   %s  %s  %d node(s) / %d edge(s)\n",
		left.ContentHash, left.ExtractedAt.UTC().Format(time.RFC3339), left.NodeCount, left.EdgeCount)
	line("  right  %s  %s  %d node(s) / %d edge(s)\n\n",
		right.ContentHash, right.ExtractedAt.UTC().Format(time.RFC3339), right.NodeCount, right.EdgeCount)

	if diff.Empty() {
		line("the two generations state the same record\n")
	}
	if len(diff.Fields) > 0 {
		line("fields:\n")
		for _, fd := range diff.Fields {
			line("  %-24s %s\n%-26s %s\n", fd.Field, orNone(fd.Left), "", orNone(fd.Right))
		}
	}
	for _, c := range diff.Collections() {
		if c.Empty() {
			continue
		}
		limit := f.limitEdges
		if c.Kind != "edge" {
			limit = f.limitNodes
		}
		line("%ss:\n", c.Kind)
		for _, id := range capped(c.OnlyLeft, limit) {
			line("  - %s\n", id)
		}
		for _, id := range capped(c.OnlyRight, limit) {
			line("  + %s\n", id)
		}
		for _, ch := range c.Changed[:min(len(c.Changed), cap0(limit, len(c.Changed)))] {
			line("  ~ %s  %s: %s -> %s\n", ch.ID, ch.Field, orNone(ch.Left), orNone(ch.Right))
		}
		line("  %d only in left, %d only in right, %d described differently\n",
			len(c.OnlyLeft), len(c.OnlyRight), len(c.Changed))
	}
	line("\n- only in left   + only in right   ~ present in both, described differently\n")
	if _, err := stdout.Write(b); err != nil {
		return fmt.Errorf("writing output: %w", err)
	}
	return nil
}

func orNone(v string) string {
	if v == "" {
		return "(not stated)"
	}
	return v
}

// capped truncates a listing to limit entries; a limit of zero is unlimited,
// matching --limit-nodes and --limit-edges everywhere else on this command.
func capped(ids []string, limit int) []string {
	return ids[:cap0(limit, len(ids))]
}

func cap0(limit, have int) int {
	if limit <= 0 || limit > have {
		return have
	}
	return limit
}

// -- JSON --

type callGraphDiffJSON struct {
	Coordinate       coordinateJSON       `json:"coordinate"`
	PipelineVersion  string               `json:"pipeline_version"`
	Generations      int                  `json:"generations"`
	DistinctMeasures int                  `json:"distinct_measurements"`
	DistinctGraphs   int                  `json:"distinct_graphs"`
	Left             *diffSideJSON        `json:"left,omitempty"`
	Right            *diffSideJSON        `json:"right,omitempty"`
	Fields           []diffFieldJSON      `json:"fields,omitempty"`
	Collections      []diffCollectionJSON `json:"collections,omitempty"`
	Summary          string               `json:"summary,omitempty"`
}

type diffSideJSON struct {
	ContentHash string `json:"content_hash"`
	ExtractedAt string `json:"extracted_at"`
	NodeCount   int    `json:"node_count"`
	EdgeCount   int    `json:"edge_count"`
}

type diffFieldJSON struct {
	Field string `json:"field"`
	Left  string `json:"left"`
	Right string `json:"right"`
}

type diffCollectionJSON struct {
	Kind      string           `json:"kind"`
	OnlyLeft  []string         `json:"only_left,omitempty"`
	OnlyRight []string         `json:"only_right,omitempty"`
	Changed   []diffMemberJSON `json:"changed,omitempty"`
}

type diffMemberJSON struct {
	ID    string `json:"id"`
	Field string `json:"field"`
	Left  string `json:"left"`
	Right string `json:"right"`
}

func toCallGraphDiffJSON(coord coordinate.ModuleCoordinate, counts diffCounts,
	left, right domain.CallGraphRecord, diff domain.GenerationDiff,
) callGraphDiffJSON {
	out := callGraphDiffJSON{
		Coordinate:       coordinateJSON{Path: coord.Path(), Version: coord.Version()},
		PipelineVersion:  cgapp.PipelineVersion,
		Generations:      counts.generations,
		DistinctMeasures: counts.measurements,
		DistinctGraphs:   counts.graphs,
		Left:             &diffSideJSON{ContentHash: left.ContentHash, ExtractedAt: isoTime(left.ExtractedAt), NodeCount: left.NodeCount, EdgeCount: left.EdgeCount},
		Right:            &diffSideJSON{ContentHash: right.ContentHash, ExtractedAt: isoTime(right.ExtractedAt), NodeCount: right.NodeCount, EdgeCount: right.EdgeCount},
		Summary:          diff.Summary(),
	}
	for _, f := range diff.Fields {
		out.Fields = append(out.Fields, diffFieldJSON{Field: f.Field, Left: f.Left, Right: f.Right})
	}
	for _, c := range diff.Collections() {
		if c.Empty() {
			continue
		}
		cj := diffCollectionJSON{Kind: c.Kind, OnlyLeft: c.OnlyLeft, OnlyRight: c.OnlyRight}
		for _, ch := range c.Changed {
			cj.Changed = append(cj.Changed, diffMemberJSON{ID: ch.ID, Field: ch.Field, Left: ch.Left, Right: ch.Right})
		}
		out.Collections = append(out.Collections, cj)
	}
	return out
}
