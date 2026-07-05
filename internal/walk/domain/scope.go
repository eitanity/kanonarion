package domain

// FilterGraphToScope restricts g to a dependency scope: the main module anchor
// (mainPath) plus every node whose module path is in keep. The build list
// combines code, test, and tool inputs; keep is the build-list subset for the
// requested scope (computed by the caller via the Go toolchain — e.g. the import
// closure of the project's own packages, or of the tool directives), so filtering
// to it isolates that scope without re-deriving membership here.
//
// Edges are retained only when both endpoints survive. The main anchor is always
// kept so the record stays rooted at the project even when keep is empty. g is
// not mutated; a sorted copy is returned.
func FilterGraphToScope(g Graph, mainPath string, keep []string) Graph {
	keepSet := map[string]bool{mainPath: true}
	for _, p := range keep {
		keepSet[p] = true
	}

	out := Graph{
		Target:          g.Target,
		ResolvedAt:      g.ResolvedAt,
		PipelineVersion: g.PipelineVersion,
		Partial:         g.Partial,
		PartialReason:   g.PartialReason,
		HasLocalReplace: g.HasLocalReplace,
	}
	for _, n := range g.Nodes {
		if keepSet[n.Coordinate.Path] {
			out.Nodes = append(out.Nodes, n)
		}
	}
	for _, e := range g.Edges {
		if keepSet[e.From.Path] && keepSet[e.To.Path] {
			out.Edges = append(out.Edges, e)
		}
	}
	out.Sort()
	return out
}
