package sqlite_test

import (
	"context"
	"testing"

	"code.eitanity.com/kanonarion/internal/coordinate/coordinatetest"
	"code.eitanity.com/kanonarion/internal/walk/domain"
)

// TestRefusesZeroCoordinate pins the value-object rule on the walk store: a
// walk whose target names no module is not a walk of anything.
func TestRefusesZeroCoordinate(t *testing.T) {
	s := openMemStore(t)
	ctx := context.Background()

	coordinatetest.AssertRefusesZeroCoordinate(t, "PutWalk", func() error {
		return s.PutWalk(ctx, domain.WalkRecord{})
	})
}
