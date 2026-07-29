package sqlite_test

import (
	"context"
	"testing"

	"github.com/eitanity/kanonarion/internal/coordinate/coordinatetest"
	"github.com/eitanity/kanonarion/internal/walk/domain"
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
