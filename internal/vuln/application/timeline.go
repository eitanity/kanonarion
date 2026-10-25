package application

import (
	"context"
	"errors"
	"fmt"
	"io"

	"github.com/eitanity/kanonarion/internal/adapters/recordseal"
	"github.com/eitanity/kanonarion/internal/adapters/vulndbindex"

	"github.com/eitanity/kanonarion/internal/vuln/domain"
	"github.com/eitanity/kanonarion/internal/vuln/ports"
)

// FindingTimelines lists, per coordinate the findings index names and per
// analysis frame, the changes of state findingID went through across every
// stored record. Rows the store could not read come back beside the timelines
// as one *ports.UnreadableRows, or a *recordseal.SetAside when every one is
// generation drift, as the store's own listings report them.
func (uc *QueryVulnUseCase) FindingTimelines(ctx context.Context, findingID, walkID string) ([]domain.FindingTimeline, error) {
	// The index names the modules, not the served records: a module whose served
	// record no longer carries the advisory is the history this read exists for.
	named, err := uc.store.ListCoordinatesByFindingID(ctx, findingID, walkID)
	if err != nil {
		err = fmt.Errorf("listing modules indexed for %q: %w", findingID, err)
	}
	bad, err := collectUnreadable(nil, err)
	if err != nil {
		return nil, err
	}
	var all []domain.VulnerabilityRecord
	for _, coord := range named {
		recs, herr := uc.ListRecordsForModuleAllGenerations(ctx, coord)
		if bad, herr = collectUnreadable(bad, herr); herr != nil {
			return nil, herr
		}
		all = append(all, recs...)
	}
	timelines, err := domain.BuildFindingTimelines(findingID, all, newSnapshotAdvisoryCheck(ctx, uc.store))
	if err != nil {
		return nil, fmt.Errorf("building the timeline of %s: %w", findingID, err)
	}
	return timelines, unreadableErr(bad)
}

// collectUnreadable adds the rows a listing could not read to acc and clears
// err when that was its only failure; any other error is returned as it came.
func collectUnreadable(acc []ports.UnreadableRow, err error) ([]ports.UnreadableRow, error) {
	var unreadable *ports.UnreadableRows
	var aside *recordseal.SetAside
	switch {
	case err == nil:
		return acc, nil
	case errors.As(err, new(*recordseal.NothingServable)):
		return acc, err
	case errors.As(err, &unreadable):
		return append(acc, unreadable.Rows...), nil
	case errors.As(err, &aside):
		for _, r := range aside.Rows {
			acc = append(acc, unreadableFromSetAside(r))
		}
		return acc, nil
	default:
		return acc, err
	}
}

// unreadableFromSetAside is UnreadableRow.SetAside inverted, so rows from
// several listings report as one.
func unreadableFromSetAside(r recordseal.SetAsideRow) ports.UnreadableRow {
	row := ports.UnreadableRow{Kind: ports.RowKindRecord, ID: r.ID, ContentHash: r.ContentHash, Reason: r.Reason,
		Generation: ports.RowGeneration{
			PipelineVersion: r.Generation.PipelineVersion,
			SnapshotSource:  r.Generation.Snapshot.Source,
			SnapshotVersion: r.Generation.Snapshot.Version,
		}}
	if r.Kind == ports.SetAsideKindRun {
		row.Kind = ports.RowKindRun
	}
	return row
}

// unreadableErr reports rows as the store's listings do: a set-aside when every
// row is generation drift, unreadable rows otherwise, nil when there are none.
func unreadableErr(rows []ports.UnreadableRow) error {
	if len(rows) == 0 {
		return nil
	}
	aside := make([]recordseal.SetAsideRow, 0, len(rows))
	for _, r := range rows {
		if !errors.Is(r.Reason, recordseal.ErrGenerationDrift) {
			return &ports.UnreadableRows{Rows: rows}
		}
		aside = append(aside, r.SetAside())
	}
	return &recordseal.SetAside{Rows: aside}
}

// newSnapshotAdvisoryCheck answers from the snapshot rows store holds by
// (source, version, content hash) and their stored bytes, never the network, so
// every backend answers alike. Each held snapshot's index is read once.
func newSnapshotAdvisoryCheck(ctx context.Context, store ports.VulnerabilityStore) domain.SnapshotAdvisoryCheck {
	var held map[string]bool
	lists := map[string]map[string]bool{}
	key := func(s domain.DatabaseSnapshot) string {
		return s.Source() + "@" + s.Version() + "@" + s.ContentHash()
	}
	return func(snap domain.DatabaseSnapshot, advisoryID string) (bool, bool, error) {
		if held == nil {
			all, err := store.ListDatabaseSnapshots(ctx)
			if err != nil {
				return false, false, fmt.Errorf("listing held snapshots: %w", err)
			}
			held = map[string]bool{}
			for _, s := range all {
				held[key(s)] = true
			}
		}
		k := key(snap)
		if !held[k] {
			return false, false, nil
		}
		ids, ok := lists[k]
		if !ok {
			var err error
			if ids, err = snapshotAdvisoryIDs(ctx, store, snap); err != nil {
				return false, false, err
			}
			lists[k] = ids
		}
		return true, ids[advisoryID], nil
	}
}

// snapshotAdvisoryIDs reads the advisory ids index/modules.json lists out of a
// stored snapshot's bytes.
func snapshotAdvisoryIDs(ctx context.Context, store ports.VulnerabilityStore, snap domain.DatabaseSnapshot) (map[string]bool, error) {
	rc, err := store.GetDatabaseSnapshot(ctx, snap)
	if err != nil {
		return nil, fmt.Errorf("reading stored snapshot %s: %w", snap, err)
	}
	defer func() { _ = rc.Close() }()
	data, err := io.ReadAll(rc)
	if err != nil {
		return nil, fmt.Errorf("reading stored snapshot %s: %w", snap, err)
	}
	index, err := vulndbindex.FromZip(data)
	if err != nil {
		return nil, fmt.Errorf("reading the index of stored snapshot %s: %w", snap, err)
	}
	ids := map[string]bool{}
	for _, entries := range index {
		for _, e := range entries {
			ids[e.ID] = true
		}
	}
	return ids, nil
}
