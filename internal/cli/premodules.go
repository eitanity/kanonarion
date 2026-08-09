package cli

import (
	"context"
	"fmt"
	"io"
	"slices"
	"sort"
	"strings"

	"github.com/eitanity/kanonarion/internal/coordinate"
	walkdomain "github.com/eitanity/kanonarion/internal/walk/domain"
)

// preModulesLimitation is what every answer under a +incompatible coordinate is
// bounded by, in one sentence a reader can act on.
//
// The go command ignores the go.mod of a module that reached major version 2 or
// above without adopting modules. Resolution therefore yields no requirements for
// it, and a walk of one records its own node and nothing else. The record is
// honest about the build; an answer that reads dependency structure out of it and
// says nothing is not, because an empty requirement set reads as "depends on
// nothing" when the truth is "its dependencies were never resolvable here".
const preModulesLimitation = "the Go module system ignores a +incompatible module's own go.mod, " +
	"so no requirement edges are resolved under it: its dependencies are ABSENT from this answer, " +
	"not measured to be none"

// preModulesRemedy names the way out where the module took it. It is phrased
// conditionally and costs nothing to state: checking whether the successor major
// exists would be a network call on an answer path that makes none, and a reader
// who has the path can check it in one command.
const preModulesRemedy = "If the project later published a /vN major, that version is a proper module and resolves normally"

// preModulesCaveat renders the caveat for one coordinate, or the empty string
// when the coordinate is not resolved under pre-modules semantics — so a caller
// can append it unconditionally.
func preModulesCaveat(c coordinate.ModuleCoordinate) string {
	if !c.IsPreModulesIncompatible() {
		return ""
	}
	return fmt.Sprintf("caveat: %s@%s is a pre-modules module — %s. %s.",
		c.Path(), c.Version(), preModulesLimitation, preModulesRemedy)
}

// writePreModulesCaveat prints the caveat for coord when one applies, and
// nothing at all otherwise.
func writePreModulesCaveat(w io.Writer, coord coordinate.ModuleCoordinate) error {
	line := preModulesCaveat(coord)
	if line == "" {
		return nil
	}
	if _, err := fmt.Fprintln(w, line); err != nil {
		return fmt.Errorf("writing pre-modules caveat: %w", err)
	}
	return nil
}

// writePreModulesCaveatForSet prints one caveat naming every pre-modules
// coordinate an answer spans, and nothing when it spans none.
//
// A per-coordinate line would be repeated once per row on a listing that holds
// dozens; one line naming them all keeps the statement present without burying
// the answer. Coordinates are sorted so the same set always renders identically.
func writePreModulesCaveatForSet(w io.Writer, coords []coordinate.ModuleCoordinate) error {
	seen := map[string]struct{}{}
	var named []string
	for _, c := range coords {
		if !c.IsPreModulesIncompatible() {
			continue
		}
		k := c.Path() + "@" + c.Version()
		if _, dup := seen[k]; dup {
			continue
		}
		seen[k] = struct{}{}
		named = append(named, k)
	}
	if len(named) == 0 {
		return nil
	}
	sort.Strings(named)
	if _, err := fmt.Fprintf(w, "caveat: %d module(s) in this answer resolved under pre-modules semantics — %s. %s.\n%s",
		len(named), preModulesLimitation, preModulesRemedy, indentedList(named)); err != nil {
		return fmt.Errorf("writing pre-modules caveat: %w", err)
	}
	return nil
}

// preModulesNodesIn lists, sorted and deduplicated, every coordinate in a walk
// graph that resolved under pre-modules semantics.
//
// It is the set an answer about the walk's dependency STRUCTURE is bounded by,
// whichever direction the question runs: no requirement edge was resolved under
// any of them, so their own dependencies are missing from the graph and they can
// never appear as the dependent of anything.
func preModulesNodesIn(g walkdomain.Graph) []coordinate.ModuleCoordinate {
	seen := map[coordinate.ModuleCoordinate]struct{}{}
	var out []coordinate.ModuleCoordinate
	for _, n := range g.Nodes {
		if !n.Coordinate.IsPreModulesIncompatible() {
			continue
		}
		if _, dup := seen[n.Coordinate]; dup {
			continue
		}
		seen[n.Coordinate] = struct{}{}
		out = append(out, n.Coordinate)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Path() != out[j].Path() {
			return out[i].Path() < out[j].Path()
		}
		return out[i].Version() < out[j].Version()
	})
	return out
}

// writeWalkPreModulesCaveat states what a walk's dependency structure cannot
// show, naming the coordinates responsible, and prints nothing when the walk
// contains none.
//
// It is deliberately stated as an absence of MEASUREMENT rather than a defect in
// the walk. The walk recorded exactly what the module system resolved; it is the
// reader who would otherwise take an empty requirement set for a measured one.
func writeWalkPreModulesCaveat(w io.Writer, g walkdomain.Graph) error {
	pre := preModulesNodesIn(g)
	if len(pre) == 0 {
		return nil
	}
	named := make([]string, 0, len(pre))
	for _, c := range pre {
		named = append(named, c.Path()+"@"+c.Version())
	}
	if _, err := fmt.Fprintf(w,
		"caveat: %d module(s) in this walk resolved under pre-modules semantics — %s. "+
			"They can therefore neither show their own dependencies nor appear as the dependent of anything. %s.\n%s",
		len(pre), preModulesLimitation, preModulesRemedy, indentedList(named)); err != nil {
		return fmt.Errorf("writing pre-modules caveat: %w", err)
	}
	return nil
}

// indentedList renders the named coordinates one per line.
//
// A real project reaches double figures — the reference corteza walk holds
// sixteen — and a comma-joined run of them on one line is where a reader stops
// reading. They are listed rather than counted because which modules are
// affected is the actionable half of the statement.
func indentedList(named []string) string {
	var b strings.Builder
	for _, n := range named {
		b.WriteString("  ")
		b.WriteString(n)
		b.WriteString("\n")
	}
	return b.String()
}

// preModulesCaveatJSON is the machine-readable form of the same statement. It is
// a pointer field on each surface's output so an answer that carries no
// pre-modules coordinate marshals exactly as it did before.
type preModulesCaveatJSON struct {
	// Coordinates are the pre-modules coordinates this answer spans.
	Coordinates []string `json:"coordinates"`
	// Limitation states what is structurally unavailable under them.
	Limitation string `json:"limitation"`
	// Remedy names the way out where the project took it.
	Remedy string `json:"remedy"`
}

// preModulesCaveatFor builds the JSON caveat for the coordinates an answer
// spans, returning nil when none of them is a pre-modules module.
func preModulesCaveatFor(coords ...coordinate.ModuleCoordinate) *preModulesCaveatJSON {
	seen := map[string]struct{}{}
	var named []string
	for _, c := range coords {
		if !c.IsPreModulesIncompatible() {
			continue
		}
		k := c.Path() + "@" + c.Version()
		if _, dup := seen[k]; dup {
			continue
		}
		seen[k] = struct{}{}
		named = append(named, k)
	}
	if len(named) == 0 {
		return nil
	}
	sort.Strings(named)
	return &preModulesCaveatJSON{
		Coordinates: named,
		Limitation:  preModulesLimitation,
		Remedy:      preModulesRemedy,
	}
}

// printPreModulesCaveat writes the caveat into a context section, and nothing
// when the section is not bounded by one. It takes the JSON form so the text and
// the document state the same thing from the same value rather than deriving it
// twice.
func printPreModulesCaveat(w *errWriter, c *preModulesCaveatJSON) {
	if c == nil {
		return
	}
	w.printf("  caveat: %s resolved under pre-modules semantics — %s. %s.\n",
		strings.Join(c.Coordinates, ", "), c.Limitation, c.Remedy)
}

// auditPreModulesCoords parses the coordinates off audit rows so the pre-modules
// ones among them can be named.
//
// The row carries its coordinate already joined into "path@version". A string
// that does not parse back is dropped rather than guessed at: naming a
// coordinate the row does not actually hold would be the fabrication this caveat
// exists to prevent.
func auditPreModulesCoords(results []auditModuleResult) []coordinate.ModuleCoordinate {
	coords := make([]coordinate.ModuleCoordinate, 0, len(results))
	for _, r := range results {
		coord, err := parseCoordinate(r.Coordinate)
		if err != nil {
			continue
		}
		coords = append(coords, coord)
	}
	return coords
}

// sbomPreModulesCoords reads the walk an SBOM was generated from and returns the
// pre-modules coordinates it contains.
//
// It reads the walk rather than the document because the fact is a property of
// how the build resolved, and the document has no field that records it. A walk
// that cannot be read yields nothing: the caveat is stated from measurement or
// not at all, and an SBOM must never carry a claim about a walk nobody opened.
func sbomPreModulesCoords(ctx context.Context, ctr *Container, walkID string) []coordinate.ModuleCoordinate {
	if walkID == "" {
		return nil
	}
	rec, err := ctr.QueryWalks.GetWalk(ctx, walkID)
	if err != nil {
		return nil
	}
	return preModulesNodesIn(rec.Graph)
}

// containsCoordinate reports whether coords already names c, so a surface does
// not state the same limitation twice about the same module.
func containsCoordinate(coords []coordinate.ModuleCoordinate, c coordinate.ModuleCoordinate) bool {
	return slices.Contains(coords, c)
}
