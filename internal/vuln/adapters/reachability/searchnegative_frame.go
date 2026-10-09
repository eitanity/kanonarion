package reachability

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/eitanity/kanonarion/internal/coordinate"

	callgraphdomain "github.com/eitanity/kanonarion/internal/callgraph/domain"

	"github.com/eitanity/kanonarion/internal/vuln/ports"
)

// testOnly is the package a dependency's test node is placed in for a join: no
// build links it, so inBuild drops the node and every edge touching it.
const testOnly = "\x00test"

// loadResult is one memoised graph read.
type loadResult struct {
	proj ports.CallGraphProjection
	err  error
}

// load reads coord's graph once for the life of the searcher. The caller holds
// s.mu.
func (s *NegativeSearcher) load(ctx context.Context, coord coordinate.ModuleCoordinate) (ports.CallGraphProjection, error) {
	if r, ok := s.loads[coord]; ok {
		return r.proj, r.err
	}
	proj, err := s.loader.Load(ctx, coord)
	if err != nil {
		// Wrapped bare: refusals quote the loader's own text.
		err = fmt.Errorf("%w", err)
	}
	s.loads[coord] = loadResult{proj: proj, err: err}
	return proj, err
}

// heldGraph is one dependency graph the store holds for a frame's build.
type heldGraph struct {
	coord coordinate.ModuleCoordinate
	proj  ports.CallGraphProjection
}

// frameBuild is a frame's own graph with every dependency graph the store
// holds for its build joined at its external leaves, built once per (frame,
// walk) and shared by every subject searched in that frame.
type frameBuild struct {
	base    ports.CallGraphProjection
	held    []heldGraph
	modules []ports.BuildModule
	// faults is why a module's graph would not read, by module path.
	faults map[string]string
	// notWidened says why no dependency graph could be joined at all, "" when
	// the build list and the closure were both known.
	notWidened string
}

// frameFor returns the frame's widened graph. The caller holds s.mu.
func (s *NegativeSearcher) frameFor(
	ctx context.Context,
	frame coordinate.ModuleCoordinate,
	walkID string,
	consumer ports.CallGraphProjection,
	frameDir string,
) *frameBuild {
	key := graphKey{coord: frame, walk: walkID}
	if b, ok := s.frames[key]; ok {
		return b
	}
	b := &frameBuild{base: consumer, faults: map[string]string{}}
	s.frames[key] = b
	b.modules, b.notWidened = s.buildList(ctx, walkID)
	if b.notWidened == "" && len(consumer.DependencyPackages) == 0 {
		b.notWidened = "the stored call graph of " + frame.String() +
			" does not record which packages of other modules its build links, so no dependency graph was joined" +
			remedyClause("re-analyse it with", frame, frameDir, true)
	}
	if b.notWidened != "" {
		return b
	}
	// Graphs are loaded only for modules the frame's code reaches, round by
	// round, because reading a graph is most of a joined search's cost. Every
	// owned node roots the frontier, so the whole-graph claim is followed too.
	closure := dependencyClosure(consumer)
	roots := collectEntryPoints(consumer)
	linked := linkedModules(b.modules, consumer.DependencyPackages)
	tried := map[string]bool{}
	for {
		next := reachedModules(b.base, roots, linked, tried)
		if len(next) == 0 {
			break
		}
		for _, m := range next {
			tried[m.Coordinate.Path()] = true
			if m.LocalReplace {
				continue
			}
			proj, err := s.load(ctx, m.Coordinate)
			if err != nil {
				if !errors.Is(err, ports.ErrCallGraphNotFound) {
					b.faults[m.Coordinate.Path()] = err.Error()
				}
				continue
			}
			b.held = append(b.held, heldGraph{coord: m.Coordinate, proj: proj})
			b.base = joinProjections(b.base, proj, closure, false)
		}
	}
	// The base keeps the frame's own completeness: a dependency graph weighs on
	// a rung only where the entry points reach into it, see reachedCompleteness.
	b.base.Completeness = consumer.Completeness
	return b
}

// buildList is the walk's selected modules, or why none can be named.
func (s *NegativeSearcher) buildList(ctx context.Context, walkID string) ([]ports.BuildModule, string) {
	const lead = "no dependency graph was joined, because "
	if s.modules == nil || walkID == "" {
		return nil, lead + "no walk is named that lists the modules this build selected"
	}
	mods, ok, err := s.modules.WalkModules(ctx, walkID)
	if err != nil {
		return nil, lead + "the build list of walk " + walkID + " could not be read: " + err.Error()
	}
	if !ok {
		return nil, lead + "the store holds no walk " + walkID + " to list the modules this build selected"
	}
	return mods, ""
}

// dependencyClosure is what a dependency graph is kept to in a join: the
// packages of other modules the build links, the standard library it links,
// and the frame's own packages, so calls between them stay in the graph.
func dependencyClosure(consumer ports.CallGraphProjection) []string {
	out := append(append([]string(nil), consumer.DependencyPackages...), consumer.StdlibPackages...)
	for _, n := range consumer.Nodes {
		if !n.IsExternal && n.Package != "" {
			out = append(out, n.Package)
		}
	}
	return out
}

// moduleOf is the build module that provides pkg, by longest path prefix.
func moduleOf(modules []ports.BuildModule, pkg string) (ports.BuildModule, bool) {
	var best ports.BuildModule
	found := false
	for _, m := range modules {
		p := m.Coordinate.Path()
		if (pkg == p || strings.HasPrefix(pkg, p+"/")) && (!found || len(p) > len(best.Coordinate.Path())) {
			best, found = m, true
		}
	}
	return best, found
}

// linkedModules is every build module that provides at least one linked
// package, sorted by path so the join is built in one order every time.
func linkedModules(modules []ports.BuildModule, packages []string) []ports.BuildModule {
	seen := map[string]ports.BuildModule{}
	for _, pkg := range packages {
		if m, ok := moduleOf(modules, pkg); ok {
			seen[m.Coordinate.Path()] = m
		}
	}
	out := make([]ports.BuildModule, 0, len(seen))
	for _, m := range seen {
		out = append(out, m)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Coordinate.Path() < out[j].Coordinate.Path() })
	return out
}

// reachedModules is every linked module not yet tried that provides an
// external node roots reach in joined, sorted by path.
func reachedModules(joined ports.CallGraphProjection, roots []string, linked []ports.BuildModule, tried map[string]bool) []ports.BuildModule {
	reached := reachableFrom(joined, roots)
	seen := map[string]bool{}
	var out []ports.BuildModule
	for _, n := range joined.Nodes {
		if !n.IsExternal || !reached[n.ID] {
			continue
		}
		m, ok := moduleOf(linked, n.Package)
		if !ok || tried[m.Coordinate.Path()] || seen[m.Coordinate.Path()] {
			continue
		}
		seen[m.Coordinate.Path()] = true
		out = append(out, m)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Coordinate.Path() < out[j].Coordinate.Path() })
	return out
}

// holds returns coord's graph where it is already joined into the base.
func (b *frameBuild) holds(coord coordinate.ModuleCoordinate) (heldGraph, bool) {
	for _, h := range b.held {
		if h.coord == coord {
			return h, true
		}
	}
	return heldGraph{}, false
}

// label names the dependency graphs joined beside the subject's, so an answer
// says what the traversal ran over. Nil where there are none.
func (b *frameBuild) label(subject coordinate.ModuleCoordinate) []string {
	var names []string
	for _, h := range b.held {
		if h.coord != subject {
			names = append(names, h.coord.String())
		}
	}
	if len(names) == 0 {
		return nil
	}
	return []string{fmt.Sprintf("%s held for this build (%s), kept only within the packages this build links",
		plural(len(names), "further dependency graph"), strings.Join(firstN(names, 3), ", "))}
}

// reachedCompleteness is the weakest completeness of the frame's graph, the
// subject's, and every joined dependency graph the entry points reach into. A
// graph nothing enters cannot hide a route, so its fidelity does not weigh.
func (b *frameBuild) reachedCompleteness(joined ports.CallGraphProjection, roots []string, consumer, subject ports.CallGraphProjection) string {
	level := callgraphdomain.WeakerCompleteness(
		callgraphdomain.CompletenessLevel(consumer.Completeness),
		callgraphdomain.CompletenessLevel(subject.Completeness))
	if len(b.held) == 0 {
		return string(level)
	}
	reached := reachableFrom(joined, roots)
	for _, h := range b.held {
		for _, n := range h.proj.Nodes {
			if !n.IsExternal && reached[n.ID] {
				level = callgraphdomain.WeakerCompleteness(level, callgraphdomain.CompletenessLevel(h.proj.Completeness))
				break
			}
		}
	}
	return string(level)
}

// unjoinedWhy says, per module, why the reached calls were not joined, with
// the command that joins each where one exists.
func (b *frameBuild) unjoinedWhy(joined ports.CallGraphProjection, calls []string) string {
	if len(calls) == 0 {
		return ""
	}
	if b.notWidened != "" {
		return b.notWidened
	}
	want := make(map[string]bool, len(calls))
	for _, id := range calls {
		want[id] = true
	}
	var commands, local, empty, faulty, unknown []string
	seen := map[string]bool{}
	for _, n := range joined.Nodes {
		if !want[n.ID] {
			continue
		}
		m, ok := moduleOf(b.modules, n.Package)
		if !ok {
			if !seen[n.Package] {
				seen[n.Package] = true
				unknown = append(unknown, n.Package)
			}
			continue
		}
		coord := m.Coordinate.String()
		if seen[coord] {
			continue
		}
		seen[coord] = true
		switch {
		case m.LocalReplace:
			local = append(local, coord)
		case b.faults[m.Coordinate.Path()] != "":
			faulty = append(faulty, "the stored call graph of "+coord+" could not be read: "+b.faults[m.Coordinate.Path()])
		default:
			if h, ok := b.holds(m.Coordinate); ok {
				empty = append(empty, fmt.Sprintf("%s (%s, %d nodes)", coord, h.proj.Completeness, len(h.proj.Nodes)))
				continue
			}
			line, _ := callgraphdomain.ReanalysisCommand(m.Coordinate, "", false)
			commands = append(commands, line)
		}
	}
	var parts []string
	if len(commands) > 0 {
		sort.Strings(commands)
		which := "the module that provides them"
		if len(commands) > 1 {
			which = "the " + plural(len(commands), "module") + " that provide them"
		}
		parts = append(parts, "the store holds no call graph for "+which+"; extract "+
			itOrThem(len(commands))+" with: "+strings.Join(commands, "; "))
	}
	if len(local) > 0 {
		sort.Strings(local)
		parts = append(parts, strings.Join(local, ", ")+" is replaced by a local directory, which no stored call graph is taken of")
	}
	if len(empty) > 0 {
		sort.Strings(empty)
		parts = append(parts, "the stored call graphs of "+strings.Join(empty, ", ")+
			" hold no node for those calls; kanonarion callgraph-show <module>@<version> says how each was built")
	}
	parts = append(parts, faulty...)
	if len(unknown) > 0 {
		sort.Strings(unknown)
		parts = append(parts, "no module of this build's walk provides "+strings.Join(firstN(unknown, 3), ", "))
	}
	return strings.Join(parts, "; ")
}
