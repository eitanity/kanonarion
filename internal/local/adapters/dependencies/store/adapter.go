// Package store provides a DependencyLoader adapter backed by the global
// callgraph store. All access is read-only: no records are written.
package store

import (
	"context"
	"fmt"

	"github.com/eitanity/kanonarion/internal/coordinate"

	callgraphdomain "github.com/eitanity/kanonarion/internal/callgraph/domain"
	cgports "github.com/eitanity/kanonarion/internal/callgraph/ports"
)

// CallGraphStoreAdapter adapts a cgports.CallGraphStore to the
// local ports.DependencyLoader interface.
type CallGraphStoreAdapter struct {
	store cgports.CallGraphStore
}

// New constructs a CallGraphStoreAdapter wrapping the given store.
func New(store cgports.CallGraphStore) *CallGraphStoreAdapter {
	return &CallGraphStoreAdapter{store: store}
}

// LoadCallGraphRecords fetches the callgraph record for each coordinate from
// the global store at the given pipeline version. Coordinates that have no
// stored record are silently omitted from the result.
func (a *CallGraphStoreAdapter) LoadCallGraphRecords(ctx context.Context, coords []coordinate.ModuleCoordinate, pipelineVersion string) ([]callgraphdomain.CallGraphRecord, error) {
	records := make([]callgraphdomain.CallGraphRecord, 0, len(coords))
	for _, coord := range coords {
		rec, found, err := a.store.GetCallGraphRecord(ctx, coord, pipelineVersion)
		if err != nil {
			return nil, fmt.Errorf("loading callgraph for %s: %w", coord, err)
		}
		if !found {
			continue
		}
		records = append(records, rec)
	}
	return records, nil
}
