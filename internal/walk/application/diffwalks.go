package application

import (
	"context"
	"fmt"
	"sort"

	fetchdomain "github.com/eitanity/kanonarion/internal/fetch/domain"
	"github.com/eitanity/kanonarion/internal/walk/domain"
	walkports "github.com/eitanity/kanonarion/internal/walk/ports"
)

// DiffWalksUseCase produces a structured diff between two walk records.
type DiffWalksUseCase struct {
	store walkports.WalkStore
}

// NewDiffWalksUseCase constructs a DiffWalksUseCase.
func NewDiffWalksUseCase(store walkports.WalkStore) *DiffWalksUseCase {
	return &DiffWalksUseCase{store: store}
}

// WalkDiff is the result of comparing two walk records.
type WalkDiff struct {
	WalkA          string                         // ID of the base walk
	WalkB          string                         // ID of the comparison walk
	Added          []fetchdomain.ModuleCoordinate // modules present in B but not A (by path)
	Removed        []fetchdomain.ModuleCoordinate // modules present in A but not B (by path)
	VersionChanged []VersionChange
	StatusChanged  []StatusChange
}

// VersionChange records a module whose MVS-selected version changed.
type VersionChange struct {
	Path     string
	VersionA string
	VersionB string
}

// StatusChange records a module whose node status changed.
type StatusChange struct {
	Coordinate fetchdomain.ModuleCoordinate
	StatusA    domain.NodeStatus
	StatusB    domain.NodeStatus
}

// Diff retrieves walks idA and idB and returns the structured diff.
func (uc *DiffWalksUseCase) Diff(ctx context.Context, idA, idB string) (WalkDiff, error) {
	recA, err := uc.store.GetWalk(ctx, idA)
	if err != nil {
		return WalkDiff{}, fmt.Errorf("loading walk A (%s): %w", idA, err)
	}
	recB, err := uc.store.GetWalk(ctx, idB)
	if err != nil {
		return WalkDiff{}, fmt.Errorf("loading walk B (%s): %w", idB, err)
	}

	return diffRecords(recA, recB), nil
}

func diffRecords(a, b domain.WalkRecord) WalkDiff {
	// Index nodes by module path for both walks.
	nodesA := nodesByPath(a.Graph.Nodes)
	nodesB := nodesByPath(b.Graph.Nodes)

	var added, removed []fetchdomain.ModuleCoordinate
	var versionChanged []VersionChange
	var statusChanged []StatusChange

	for path, nodeB := range nodesB {
		if nodeA, ok := nodesA[path]; !ok {
			added = append(added, nodeB.Coordinate)
		} else if nodeA.Coordinate.Version != nodeB.Coordinate.Version {
			versionChanged = append(versionChanged, VersionChange{
				Path:     path,
				VersionA: nodeA.Coordinate.Version,
				VersionB: nodeB.Coordinate.Version,
			})
		}
	}
	for path, nodeA := range nodesA {
		if _, ok := nodesB[path]; !ok {
			removed = append(removed, nodeA.Coordinate)
		}
	}

	// Status changes use the per-node results, keyed by full coordinate.
	for coord, resultB := range b.PerNodeResults {
		if resultA, ok := a.PerNodeResults[coord]; ok {
			if resultA.Status != resultB.Status {
				statusChanged = append(statusChanged, StatusChange{
					Coordinate: coord,
					StatusA:    resultA.Status,
					StatusB:    resultB.Status,
				})
			}
		}
	}

	// Sort all slices for deterministic output.
	sort.Slice(added, func(i, j int) bool { return added[i].String() < added[j].String() })
	sort.Slice(removed, func(i, j int) bool { return removed[i].String() < removed[j].String() })
	sort.Slice(versionChanged, func(i, j int) bool { return versionChanged[i].Path < versionChanged[j].Path })
	sort.Slice(statusChanged, func(i, j int) bool {
		return statusChanged[i].Coordinate.String() < statusChanged[j].Coordinate.String()
	})

	return WalkDiff{
		WalkA:          a.ID,
		WalkB:          b.ID,
		Added:          added,
		Removed:        removed,
		VersionChanged: versionChanged,
		StatusChanged:  statusChanged,
	}
}

func nodesByPath(nodes []domain.GraphNode) map[string]domain.GraphNode {
	m := make(map[string]domain.GraphNode, len(nodes))
	for _, n := range nodes {
		m[n.Coordinate.Path] = n
	}
	return m
}
