package reachability

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/eitanity/kanonarion/internal/coordinate"

	callgraphdomain "github.com/eitanity/kanonarion/internal/callgraph/domain"
	cgports "github.com/eitanity/kanonarion/internal/callgraph/ports"

	"github.com/eitanity/kanonarion/internal/vuln/ports"
)

// CallSiteStoreReader answers ports.CallSiteReader from the call-graph ledger.
//
// It serves the composed generation through GetCallGraphRecord rather than
// reading the edge tables by coordinate. The ledger is append-only and a
// coordinate names every generation it holds at once, so an edge picked by
// coordinate can come from a superseded analysis while the reachability answer
// beside it was computed against the served one — a disagreement nothing in the
// record would show.
//
// It keeps no cache. The annotator above it memoises per run, which is where the
// knowledge of how many records share a module lives; caching here would hold a
// decoded graph for the life of the process for the benefit of whoever asked
// first.
type CallSiteStoreReader struct {
	store           cgports.CallGraphStore
	pipelineVersion string
}

// NewCallSiteStoreReader returns a reader over the call-graph ledger.
func NewCallSiteStoreReader(store cgports.CallGraphStore, pipelineVersion string) *CallSiteStoreReader {
	return &CallSiteStoreReader{store: store, pipelineVersion: pipelineVersion}
}

// ReadCallSites returns what the served graph for coord records about the call
// sites out of fromIDs.
//
// A coordinate the ledger holds nothing for is not an error: it is the answer
// Served=false, which the annotation states as the reason a hop is unannotated.
// A store failure IS an error — a graph that could not be read is not a graph
// that is absent, and reporting the two the same way would turn a broken store
// into a walk-wide "no call graph held".
func (r *CallSiteStoreReader) ReadCallSites(
	ctx context.Context,
	coord coordinate.ModuleCoordinate,
	fromIDs []string,
) (ports.CallSiteAnswer, error) {
	if coord.IsZero() || len(fromIDs) == 0 {
		return ports.CallSiteAnswer{}, nil
	}
	rec, ok, err := r.store.GetCallGraphRecord(ctx, coord, r.pipelineVersion)
	if err != nil {
		if errors.Is(err, coordinate.ErrZeroCoordinate) {
			return ports.CallSiteAnswer{}, nil
		}
		return ports.CallSiteAnswer{}, fmt.Errorf("reading call sites in %s: %w", coord, err)
	}
	if !ok {
		return ports.CallSiteAnswer{}, nil
	}

	wanted := make(map[string]bool, len(fromIDs))
	for _, id := range fromIDs {
		if id != "" {
			wanted[id] = true
		}
	}

	answer := ports.CallSiteAnswer{
		Served:       true,
		Completeness: string(rec.Completeness),
		KnownCallers: make(map[string]bool, len(wanted)),
		Edges:        make(map[ports.CallSiteKey]ports.CallSiteFact),
	}
	moduleOf := make(map[string]string, len(rec.Nodes))
	for _, n := range rec.Nodes {
		moduleOf[n.ID] = n.Module
		if wanted[n.ID] {
			answer.KnownCallers[n.ID] = true
		}
	}
	ifaceOf, ifaceSize := implementationIndex(rec)

	for _, e := range rec.Edges {
		if !wanted[e.FromID] {
			continue
		}
		// A caller the node list did not name but an edge does is still named by
		// the graph; recording it here keeps "the graph does not know this
		// function" a statement about the graph rather than about its node table.
		answer.KnownCallers[e.FromID] = true
		key := ports.CallSiteKey{FromID: e.FromID, ToID: e.ToID}
		if _, seen := answer.Edges[key]; seen {
			// The ledger records one edge per call SITE, so a caller that invokes the
			// same callee twice produces two rows. The first is kept: they agree on
			// everything the annotation reads except the position, and picking a
			// later one by arrival order would make the annotation depend on edge
			// order.
			continue
		}
		fact := ports.CallSiteFact{
			Confidence:           string(e.Confidence),
			ReflectDispatch:      e.ReflectDispatch,
			Reference:            e.Kind.IsReference(),
			CallSiteFile:         e.CallSite.File,
			CallSiteLine:         e.CallSite.Line,
			ImplementationModule: moduleOf[e.ToID],
		}
		if ids := ifaceOf[e.ToID]; len(ids) == 1 {
			fact.InterfaceID = ids[0]
			fact.Implementers = ifaceSize[ids[0]]
		}
		answer.Edges[key] = fact
	}
	return answer, nil
}

// implementationIndex maps each concrete method node the record attributes to an
// interface onto the interfaces it satisfies there, and counts the implementers
// of each interface.
//
// Both are derived from the record's own implementation relation, which the
// analysed module computes over its OWN declarations on both sides. A type in
// another module satisfying the same interface is not in it, and neither is an
// interface another module declares — so an interface hop whose two halves
// straddle a module boundary yields no attribution here, and is left saying the
// dispatch happened without naming what it crossed. That is the honest answer:
// the edge does not carry the interface it dispatched through, and inventing one
// from the callee's method name would be the guess the whole annotation refuses.
func implementationIndex(rec callgraphdomain.CallGraphRecord) (map[string][]string, map[string]int) {
	ifaceOf := make(map[string][]string)
	ifaceSize := make(map[string]int, len(rec.Interfaces))
	for _, impl := range rec.Implementations {
		ifaceSize[impl.InterfaceID]++
		for _, m := range impl.Methods {
			if m.NodeID == "" {
				continue
			}
			if !slicesContains(ifaceOf[m.NodeID], impl.InterfaceID) {
				ifaceOf[m.NodeID] = append(ifaceOf[m.NodeID], impl.InterfaceID)
			}
		}
	}
	return ifaceOf, ifaceSize
}

// slicesContains is a local membership test over the small per-node interface
// lists, kept here so the index stays free of a generic import for two lines.
func slicesContains(list []string, want string) bool {
	for _, s := range list {
		if s == want {
			return true
		}
	}
	return false
}

// ImplementersQuery renders the command that lists the concrete types satisfying
// an interface, so a hop that reports a count points at the answer the count
// replaced.
//
// It is here rather than in the vuln domain because the command it names belongs
// to the call-graph side, and a domain that hard-codes another context's CLI
// grammar is a domain that goes stale silently.
func ImplementersQuery(interfaceID string) string {
	if interfaceID == "" {
		return ""
	}
	return "kanonarion implementers '" + strings.ReplaceAll(interfaceID, "'", "") + "'"
}

// Ensure CallSiteStoreReader implements ports.CallSiteReader.
var _ ports.CallSiteReader = (*CallSiteStoreReader)(nil)
