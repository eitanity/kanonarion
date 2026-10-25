package ports

import (
	"context"
	"fmt"

	"github.com/eitanity/kanonarion/internal/coordinate"
)

// SupersededArtefacts names, for one coordinate, the artefact identities a read
// of it leaves out: those the fetch ledger holds only as local-source
// measurements under a published coordinate. A derived store is handed one so
// its reads compose from the published artefact alone.
type SupersededArtefacts func(ctx context.Context, coord coordinate.ModuleCoordinate) (map[string]bool, error)

// SupersededArtefactLister is the optional FactStore capability that answers
// SupersededArtefacts.
type SupersededArtefactLister interface {
	SupersededLocalArtefacts(ctx context.Context, coord coordinate.ModuleCoordinate) (map[string]bool, error)
}

// SupersededArtefactsOf asks facts which artefacts of coord are superseded,
// answering none for a store that cannot say: such a store holds no local
// generation a published read could have composed.
func SupersededArtefactsOf(ctx context.Context, facts FactStore, coord coordinate.ModuleCoordinate) (map[string]bool, error) {
	lister, ok := facts.(SupersededArtefactLister)
	if !ok {
		return nil, nil
	}
	ids, err := lister.SupersededLocalArtefacts(ctx, coord)
	if err != nil {
		return nil, fmt.Errorf("reading superseded local generations of %s: %w", coord, err)
	}
	return ids, nil
}

// DropSuperseded returns records without those whose artefact identity fn names
// as superseded for coord. A nil fn, a local coordinate and a coordinate with
// nothing superseded return records unchanged.
func DropSuperseded[R any](ctx context.Context, fn SupersededArtefacts, coord coordinate.ModuleCoordinate, records []R, identity func(R) string) ([]R, error) {
	if fn == nil || coord.IsLocal() || len(records) == 0 {
		return records, nil
	}
	ids, err := fn(ctx, coord)
	if err != nil {
		return nil, err
	}
	if len(ids) == 0 {
		return records, nil
	}
	kept := make([]R, 0, len(records))
	for _, r := range records {
		if !ids[identity(r)] {
			kept = append(kept, r)
		}
	}
	return kept, nil
}

// HoldsSuperseded reports whether the published coordinate path@version has
// artefacts fn names as superseded, so a listing reads its row through the
// composed read instead of from a single stored row. A key that names no
// module, a local key and a nil fn report false.
func HoldsSuperseded(ctx context.Context, fn SupersededArtefacts, path, version string) (bool, error) {
	if fn == nil {
		return false, nil
	}
	coord, err := coordinate.NewModuleCoordinate(path, version)
	if err != nil || coord.IsLocal() {
		return false, nil //nolint:nilerr // a key naming no module is reported by the composed read
	}
	ids, err := fn(ctx, coord)
	if err != nil {
		return false, fmt.Errorf("reading superseded local generations of %s: %w", coord, err)
	}
	return len(ids) > 0, nil
}
