package domain

import "github.com/eitanity/kanonarion/internal/coordinate"

// FilterGraph selects the nodes of g for which inScope accepts either the node's
// replacement coordinate (Coordinate) or its original require coordinate
// (OriginalCoordinate), and the edges both of whose endpoints belong to a
// retained node. A module-replace node is keyed by its replacement coordinate in
// Coordinate, with the original require coordinate in OriginalCoordinate, but a
// require/import-derived scope only ever names the original (`go list` never
// surfaces the replacement); testing both identities is what keeps a
// replace-to-fork dependency (e.g. mattn/go-sqlite3 => rqlite/go-sqlite3) whose
// replacement is not independently required. Matching only one identity silently
// drops it, losing its whole capability, licence, and vulnerability surface.
//
// Endpoint membership for edges is tested against the id projection of both
// identities of every retained node, plus any seed identities, so an edge keyed
// by either a replaced node's original or replacement coordinate survives. id
// lets a caller match at its own granularity — a bare module path for a
// path-keyed scope, the full coordinate for a version-sensitive allow-list.
//
// Node order is preserved and g is not mutated; the caller owns copying,
// carrying graph metadata, and sorting.
func FilterGraph[K comparable](
	g Graph,
	inScope func(coordinate.ModuleCoordinate) bool,
	id func(coordinate.ModuleCoordinate) K,
	seed ...K,
) (nodes []GraphNode, edges []GraphEdge) {
	effectiveKeep := make(map[K]bool, len(g.Nodes)+len(seed))
	for _, k := range seed {
		effectiveKeep[k] = true
	}
	for _, n := range g.Nodes {
		orig := n.OriginalCoordinate
		if !inScope(n.Coordinate) && (orig.Path == "" || !inScope(orig)) {
			continue
		}
		nodes = append(nodes, n)
		effectiveKeep[id(n.Coordinate)] = true
		if orig.Path != "" {
			effectiveKeep[id(orig)] = true
		}
	}
	for _, e := range g.Edges {
		if effectiveKeep[id(e.From)] && effectiveKeep[id(e.To)] {
			edges = append(edges, e)
		}
	}
	return nodes, edges
}

// FilterGraphToScope restricts g to a dependency scope: the main module anchor
// (mainPath) plus every node in scope. The build list combines code, test, and
// tool inputs; keep is the build-list subset for the requested scope (computed by
// the caller via the Go toolchain — e.g. the import closure of the project's own
// packages, or of the tool directives), so filtering to it isolates that scope
// without re-deriving membership here.
//
// keep is built from require/import paths, so scope membership is matched on the
// module path (see [FilterGraph] for how a module-replaced dependency, absent
// from keep under its replacement path, is retained via OriginalCoordinate). The
// main anchor is always kept so the record stays rooted at the project even when
// keep is empty. g is not mutated; a sorted copy is returned.
func FilterGraphToScope(g Graph, mainPath string, keep []string) Graph {
	inScope := map[string]bool{mainPath: true}
	for _, p := range keep {
		inScope[p] = true
	}

	out := Graph{
		Target:          g.Target,
		ResolvedAt:      g.ResolvedAt,
		PipelineVersion: g.PipelineVersion,
		Partial:         g.Partial,
		PartialReason:   g.PartialReason,
		HasLocalReplace: g.HasLocalReplace,
		// The build environment is a property of the whole resolution, not of any
		// node, so it survives scope filtering — a code- or tool-scoped SBOM states
		// the same platform as the complete-scope one.
		BuildEnv: g.BuildEnv,
	}
	out.Nodes, out.Edges = FilterGraph(
		g,
		func(c coordinate.ModuleCoordinate) bool { return inScope[c.Path] },
		func(c coordinate.ModuleCoordinate) string { return c.Path },
		mainPath,
	)
	out.Sort()
	return out
}
