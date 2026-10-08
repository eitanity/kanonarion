package application_test

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/eitanity/kanonarion/internal/vuln/vulntest"
)

// A refresh the run's cancellation stopped returns the cancellation. It is not a
// generation or an index that could not be read, so it neither falls through to
// the download nor reports a reason for one.
func TestRefreshSnapshot_CancelledCheckReturnsTheCancellation(t *testing.T) {
	held := vulntest.MustNew("vuln.go.dev", "2026-07-27T20:14:16Z")
	stopped := fmt.Errorf("reading the generation: %w", context.Canceled)
	cases := map[string]*fakeDatabase{
		"generation read": {snapshot: held, content: "{}", latestVersionErr: stopped},
		"index read": {
			snapshot:      vulntest.MustNew("vuln.go.dev", "2026-08-01T09:00:00Z"),
			content:       "{}",
			latestVersion: "2026-08-01T09:00:00Z",
			indexErr:      stopped,
		},
	}
	for name, db := range cases {
		t.Run(name, func(t *testing.T) {
			uc, store := refreshFixture(t, db)
			seedSnapshot(t, store, held)
			ctx, cancel := context.WithCancel(context.Background())
			cancel()

			got, err := uc.RefreshSnapshot(ctx, "walk-1")
			if !errors.Is(err, context.Canceled) {
				t.Fatalf("err = %v (outcome %q), want the cancellation", err, got.Outcome)
			}
			if n := db.snapshotCalls.Load(); n != 0 {
				t.Errorf("a stopped refresh downloaded the body %d times", n)
			}
		})
	}
}
