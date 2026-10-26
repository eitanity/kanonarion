package application

import (
	"context"
	"errors"
	"fmt"
	"io"

	"code.eitanity.com/kanonarion/internal/vuln/domain"
	"code.eitanity.com/kanonarion/internal/vuln/ports"
)

// persistSnapshot stores a downloaded snapshot and witnesses it, and returns
// the snapshot the run is judged against. Bytes the store already holds intact
// are not written again and get no event: the held row, with its first
// retrieval time and origin, is the run's snapshot. Every route that downloads
// a snapshot persists it here, so the three cannot disagree.
func persistSnapshot(ctx context.Context, store ports.VulnerabilityStore, sink ports.AuditSink,
	s domain.DatabaseSnapshot, body io.Reader, route string,
) (domain.DatabaseSnapshot, error) {
	held, found, err := heldSnapshot(ctx, store, s)
	if err != nil {
		return domain.DatabaseSnapshot{}, err
	}
	if found {
		rc, gerr := store.GetDatabaseSnapshot(ctx, held)
		if gerr == nil {
			_ = rc.Close()
			return held, nil
		}
		// Held bytes that fail their hash are restored by the write below.
		if !errors.Is(gerr, ports.ErrSnapshotIntegrity) {
			return domain.DatabaseSnapshot{}, fmt.Errorf("reading the held snapshot: %w", gerr)
		}
		s = held
	}
	if err := store.PutDatabaseSnapshot(ctx, s, body); err != nil {
		return domain.DatabaseSnapshot{}, err //nolint:wrapcheck // each caller names its route
	}
	if err := emitSnapshotRecorded(sink, s, route); err != nil {
		return domain.DatabaseSnapshot{}, err
	}
	return s, nil
}

// heldSnapshot finds the stored row with s's source, version and content hash.
func heldSnapshot(ctx context.Context, store ports.VulnerabilityStore, s domain.DatabaseSnapshot) (domain.DatabaseSnapshot, bool, error) {
	if s.ContentHash() == "" {
		return domain.DatabaseSnapshot{}, false, nil
	}
	all, err := store.ListDatabaseSnapshots(ctx)
	if err != nil {
		return domain.DatabaseSnapshot{}, false, fmt.Errorf("listing held snapshots: %w", err)
	}
	for _, h := range all {
		if h.Source() == s.Source() && h.Version() == s.Version() && h.ContentHash() == s.ContentHash() {
			return h, true, nil
		}
	}
	return domain.DatabaseSnapshot{}, false, nil
}
