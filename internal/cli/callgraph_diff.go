package cli

import (
	"context"
	"fmt"
	"io"
	"strings"

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
	// The pair is settled before the ledger's count is judged, so that a hash
	// naming nothing is refused as the broken invocation it is. Answering "one
	// measurement, nothing to compare" to a typed hash would report the
	// coordinate when the thing that was wrong is the argument.
	pair, err := selectDiffPair(coord, measurements, f.diffFrom, f.diffTo)
	if err != nil {
		return err
	}
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

	diff, err := domain.DiffGenerations(pair.left.rec, pair.right.rec)
	if err != nil {
		return fmt.Errorf("comparing generations of %s: %w", coord, err)
	}
	counts := diffCounts{generations: len(recs), measurements: len(measurements), graphs: graphs}

	if jsonOut {
		return encodeJSON(stdout, toCallGraphDiffJSON(coord, counts, pair, diff))
	}
	return printGenerationDiff(stdout, coord, counts, pair, diff, f)
}

// -- which two generations get compared --------------------------------------

// diffSideBasis says how one side of the comparison was chosen. It is the value
// the JSON surface carries and the fact the text statement puts in words, so a
// consumer can tell a default comparison from one the caller asked for without
// diffing the command line.
type diffSideBasis string

const (
	// diffSideUnstated is a coordinate holding exactly two measurements, where
	// the ladder offers one pair and there was no choice to state.
	diffSideUnstated       diffSideBasis = ""
	diffSideMostRecent     diffSideBasis = "most_recent"
	diffSideNamed          diffSideBasis = "named"
	diffSideNeighbourOlder diffSideBasis = "neighbour_older"
	diffSideNeighbourNewer diffSideBasis = "neighbour_newer"
)

// diffSide is one generation of the comparison and how it came to be there.
type diffSide struct {
	rec   domain.CallGraphRecord
	basis diffSideBasis
}

// diffPair is the two generations compared, with the one line that says which
// two and why. left is rendered as the "-" side and right as the "+" side; a
// caller naming both may put the newer one on the left, and the rendering
// follows the flags rather than the clock.
type diffPair struct {
	left, right diffSide
	statement   string
}

// selectDiffPair settles which two generations are compared.
//
// The default is the two most recent distinct measurements. Taking the first
// two was an artefact of append order rather than a choice, and on a coordinate
// re-ingested many times — every working tree, since local pins the tree on
// each run — it answered "what changed" about two states the reader had left
// weeks behind, with the served generation not in the comparison at all.
//
// WITHIN a measurement it takes the FIRST generation, which is when the ledger
// first saw that measurement. Every generation of one measurement states the
// same record apart from when it was taken, so the choice decides only the
// timestamp printed, and the earliest is the one that answers "since when has
// it said this". Taking the last would also move the output of every coordinate
// holding two measurements across three or more generations — a forced
// re-analysis of an unchanged tree makes one — and that common case is what a
// reader who wants a particular generation names with --diff-from/--diff-to.
func selectDiffPair(coord coordinate.ModuleCoordinate, measurements [][]domain.CallGraphRecord,
	fromArg, toArg string,
) (diffPair, error) {
	var left, right diffSide
	var fromGroup, toGroup int
	if fromArg != "" {
		rec, group, err := resolveGeneration(coord, measurements, "--diff-from", fromArg)
		if err != nil {
			return diffPair{}, err
		}
		left, fromGroup = diffSide{rec: rec, basis: diffSideNamed}, group
	}
	if toArg != "" {
		rec, group, err := resolveGeneration(coord, measurements, "--diff-to", toArg)
		if err != nil {
			return diffPair{}, err
		}
		right, toGroup = diffSide{rec: rec, basis: diffSideNamed}, group
	}
	if len(measurements) < 2 {
		// Nothing to pair. The named hashes were still resolved above, so a typo
		// is refused rather than answered; the caller prints the count.
		return diffPair{}, nil
	}

	switch {
	case fromArg != "" && toArg != "":
		return diffPair{left: left, right: right, statement: "comparing the two generations you named"}, nil
	case fromArg != "":
		right = neighbourOf(measurements, fromGroup, true)
		return diffPair{left: left, right: right, statement: neighbourStatement(right.basis, false)}, nil
	case toArg != "":
		left = neighbourOf(measurements, toGroup, false)
		return diffPair{left: left, right: right, statement: neighbourStatement(left.basis, true)}, nil
	}
	return defaultDiffPair(measurements), nil
}

// defaultDiffPair is the two most recent distinct measurements, older on the
// left, which is the direction the rendering has always had.
func defaultDiffPair(measurements [][]domain.CallGraphRecord) diffPair {
	n := len(measurements)
	pair := diffPair{
		left:      diffSide{rec: measurements[n-2][0], basis: diffSideMostRecent},
		right:     diffSide{rec: measurements[n-1][0], basis: diffSideMostRecent},
		statement: "comparing the first generation of the two most recent measurements",
	}
	if n == 2 {
		// Two measurements offer one pair, so there is no choice to report: this
		// is the line the command has always printed and the document carries no
		// selection basis. The common case does not move.
		pair.statement = "comparing the first generation of the first two measurements"
		pair.left.basis, pair.right.basis = diffSideUnstated, diffSideUnstated
	}
	return pair
}

// neighbourOf is the generation the unnamed side takes: the first generation of
// the adjacent measurement, on the side the named flag implies — older than a
// --diff-to, newer than a --diff-from. Where the named generation already sits
// at that end of the ladder the only neighbour is on the other side, and the
// basis says which it took rather than leaving the reader to compare two
// timestamps to find out.
func neighbourOf(measurements [][]domain.CallGraphRecord, named int, newer bool) diffSide {
	step, basis, reversed := -1, diffSideNeighbourOlder, diffSideNeighbourNewer
	if newer {
		step, basis, reversed = 1, diffSideNeighbourNewer, diffSideNeighbourOlder
	}
	i := named + step
	if i < 0 || i >= len(measurements) {
		i, basis = named-step, reversed
	}
	return diffSide{rec: measurements[i][0], basis: basis}
}

// neighbourStatement puts the chosen neighbour into words. onLeft says which
// side of the rendering the neighbour occupies.
func neighbourStatement(basis diffSideBasis, onLeft bool) string {
	adjacent := "the first generation of the measurement after it"
	if basis == diffSideNeighbourOlder {
		adjacent = "the first generation of the measurement before it"
	}
	if onLeft {
		return "comparing " + adjacent + " against the generation you named"
	}
	return "comparing the generation you named against " + adjacent
}

// resolveGeneration finds the one generation a side names.
//
// The handle is the record hash --history prints, which is 71 characters, so a
// unique prefix of one names the same generation. An ambiguous prefix is refused
// naming what it matched rather than resolved by position: two generations whose
// hashes share a prefix are two different records and the caller has not said
// which.
//
// Only this coordinate's generations are searched, so a hash naming a generation
// of another module is not a match and is refused exactly as an unknown one is.
// The comparison is between two measurements of ONE coordinate; there is no
// answer to give about a hash belonging to another.
//
// A refusal is ExitConfig, not ExitNotFound: what it prints is --history, which
// lists the hashes so the caller can correct the argument. Nothing can be run to
// make the store hold the hash that was typed, and conventions.md draws the 4/20
// line at exactly that — a remedy that produces the missing record against a
// diagnostic that helps fix the invocation.
func resolveGeneration(coord coordinate.ModuleCoordinate, measurements [][]domain.CallGraphRecord,
	flagName, value string,
) (domain.CallGraphRecord, int, error) {
	var (
		matched []domain.CallGraphRecord
		groups  []int
		seen    = map[string]bool{}
	)
	for gi, group := range measurements {
		for _, r := range group {
			if r.ContentHash == value {
				// A whole hash names one record and cannot be ambiguous.
				return r, gi, nil
			}
			if strings.HasPrefix(r.ContentHash, value) && !seen[r.ContentHash] {
				seen[r.ContentHash] = true
				matched = append(matched, r)
				groups = append(groups, gi)
			}
		}
	}
	switch len(matched) {
	case 1:
		return matched[0], groups[0], nil
	case 0:
		return domain.CallGraphRecord{}, 0, &exitError{code: ExitConfig, msg: fmt.Sprintf(
			"%s %s names no generation of %s at pipeline %s — every generation and its record hash:\n  kanonarion callgraph-show %s --history",
			flagName, value, coord, cgapp.PipelineVersion, coord)}
	default:
		candidates := make([]string, 0, len(matched))
		for _, r := range matched {
			candidates = append(candidates, fmt.Sprintf("  %s  %s  %d node(s) / %d edge(s)",
				r.ContentHash, ledgerStamp(r.ExtractedAt), r.NodeCount, r.EdgeCount))
		}
		return domain.CallGraphRecord{}, 0, &exitError{code: ExitConfig, msg: fmt.Sprintf(
			"%s %s matches %d generations of %s — name more of the hash:\n%s",
			flagName, value, len(matched), coord, strings.Join(candidates, "\n"))}
	}
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
	pair diffPair, diff domain.GenerationDiff, f callGraphShowFlags,
) error {
	left, right := pair.left.rec, pair.right.rec
	var b []byte
	line := func(format string, args ...any) {
		b = append(b, fmt.Sprintf(format, args...)...)
	}
	line("%d generation(s) for %s at pipeline %s, stating %d distinct measurement(s) and %d distinct graph(s)\n",
		counts.generations, coord, cgapp.PipelineVersion, counts.measurements, counts.graphs)
	if counts.graphs == 1 {
		line("the graphs agree; the generations differ in what they were asked\n")
	}
	line("\n%s:\n", pair.statement)
	line("  left   %s  %s  %d node(s) / %d edge(s)\n",
		left.ContentHash, ledgerStamp(left.ExtractedAt), left.NodeCount, left.EdgeCount)
	line("  right  %s  %s  %d node(s) / %d edge(s)\n\n",
		right.ContentHash, ledgerStamp(right.ExtractedAt), right.NodeCount, right.EdgeCount)

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

// diffSideJSON is one side of the comparison. SelectedBy is why this record is
// on this side — the machine form of the statement the text surface prints, so
// a consumer can tell a default pairing from one the caller named without
// diffing the command line. It is absent on a coordinate holding exactly two
// measurements, where the ladder offers one pair and nothing was chosen.
type diffSideJSON struct {
	ContentHash string `json:"content_hash"`
	ExtractedAt string `json:"extracted_at"`
	NodeCount   int    `json:"node_count"`
	EdgeCount   int    `json:"edge_count"`
	SelectedBy  string `json:"selected_by,omitempty"`
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
	pair diffPair, diff domain.GenerationDiff,
) callGraphDiffJSON {
	out := callGraphDiffJSON{
		Coordinate:       coordinateJSON{Path: coord.Path(), Version: coord.Version()},
		PipelineVersion:  cgapp.PipelineVersion,
		Generations:      counts.generations,
		DistinctMeasures: counts.measurements,
		DistinctGraphs:   counts.graphs,
		Left:             toDiffSideJSON(pair.left),
		Right:            toDiffSideJSON(pair.right),
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

func toDiffSideJSON(side diffSide) *diffSideJSON {
	return &diffSideJSON{
		ContentHash: side.rec.ContentHash,
		ExtractedAt: ledgerStamp(side.rec.ExtractedAt),
		NodeCount:   side.rec.NodeCount,
		EdgeCount:   side.rec.EdgeCount,
		SelectedBy:  string(side.basis),
	}
}
