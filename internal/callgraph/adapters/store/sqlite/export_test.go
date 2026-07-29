package sqlite

import (
	"context"
	"fmt"
)

// BackfillCompletenessForTest runs migration 9's Go step against an already-open
// store, so the back-fill can be exercised directly rather than only through a
// migration that has already been applied by the time a test store opens.
func (s *Store) BackfillCompletenessForTest(ctx context.Context) error {
	tx, err := s.db.DB().BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("beginning transaction: %w", err)
	}
	defer func() { _ = tx.Rollback() }() //nolint:errcheck
	if err := backfillCompleteness(tx); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("committing: %w", err)
	}
	return nil
}
