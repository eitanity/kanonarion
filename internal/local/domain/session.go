package domain

import (
	callgraphdomain "github.com/eitanity/kanonarion/internal/callgraph/domain"
)

// AnalysisSession is the in-memory, ephemeral state for a local workspace
// analysis run. It indexes callgraph records loaded from the global store for
// the modules actually imported by the local workspace, enabling O(1)
// cross-module symbol and edge resolution without SQL joins.
//
// A session is never persisted — it is built fresh for each analysis run and
// discarded when the run completes.
type AnalysisSession struct {
	// byModule maps module path to its loaded CallGraphRecord.
	byModule map[string]callgraphdomain.CallGraphRecord
	// nodeIndex maps symbolID to the CallNode across all loaded records.
	nodeIndex map[string]callgraphdomain.CallNode
	// outEdges maps symbolID to all outgoing call edges across all loaded records.
	outEdges map[string][]callgraphdomain.CallEdge
}

// NewAnalysisSession builds an AnalysisSession from a slice of CallGraphRecords.
// Lookup indices are built eagerly so FindNode and OutEdges are O(1) after
// construction.
func NewAnalysisSession(records []callgraphdomain.CallGraphRecord) AnalysisSession {
	byModule := make(map[string]callgraphdomain.CallGraphRecord, len(records))
	nodeIndex := make(map[string]callgraphdomain.CallNode)
	outEdges := make(map[string][]callgraphdomain.CallEdge)

	for _, r := range records {
		byModule[r.Coordinate.Path] = r
		for _, n := range r.Nodes {
			nodeIndex[n.ID] = n
		}
		for _, e := range r.Edges {
			outEdges[e.FromID] = append(outEdges[e.FromID], e)
		}
	}
	return AnalysisSession{
		byModule:  byModule,
		nodeIndex: nodeIndex,
		outEdges:  outEdges,
	}
}

// ModuleRecord returns the loaded CallGraphRecord for the given module path.
// Returns (zero, false) if no record was loaded for that module.
func (s *AnalysisSession) ModuleRecord(modulePath string) (callgraphdomain.CallGraphRecord, bool) {
	r, ok := s.byModule[modulePath]
	return r, ok
}

// FindNode returns the CallNode for the given symbolID, searching across all
// loaded dependency records. Returns (zero, false) if the symbol is unknown.
func (s *AnalysisSession) FindNode(symbolID string) (callgraphdomain.CallNode, bool) {
	n, ok := s.nodeIndex[symbolID]
	return n, ok
}

// OutEdges returns all outgoing call edges whose caller is symbolID, across
// all loaded dependency records. The slice is nil if the symbol has no
// recorded outgoing edges.
func (s *AnalysisSession) OutEdges(symbolID string) []callgraphdomain.CallEdge {
	return s.outEdges[symbolID]
}

// ModuleCount returns the number of dependency modules loaded into the session.
func (s *AnalysisSession) ModuleCount() int {
	return len(s.byModule)
}
