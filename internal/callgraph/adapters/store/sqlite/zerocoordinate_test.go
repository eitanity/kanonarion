package sqlite_test

import (
	"context"
	"fmt"
	"testing"

	"code.eitanity.com/kanonarion/internal/callgraph/domain"
	"code.eitanity.com/kanonarion/internal/coordinate/coordinatetest"
)

// TestRefusesZeroCoordinate pins the value-object rule at this store: the zero
// coordinate names no module, so it is turned away on both legs rather than
// keying a row on the empty path or answering absence to a question about
// nothing.
func TestRefusesZeroCoordinate(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()

	coordinatetest.AssertRefusesZeroCoordinate(t, "PutCallGraphRecord", func() error {
		return s.PutCallGraphRecord(ctx, domain.CallGraphRecord{})
	})
	coordinatetest.AssertRefusesZeroCoordinate(t, "GetCallGraphRecord", func() error {
		_, _, err := s.GetCallGraphRecord(ctx, zeroCoordinate(), "0.1.0")
		if err != nil {
			return fmt.Errorf("GetCallGraphRecord: %w", err)
		}
		return nil
	})
}
