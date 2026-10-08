package application_test

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"testing"

	application2 "github.com/eitanity/kanonarion/internal/walk/application"
	"github.com/eitanity/kanonarion/internal/walk/domain"
)

// stoppingGetStore cancels the run when a walk is read back, and fails the read
// with the cancellation, the way a read in flight sees an operator's interrupt.
type stoppingGetStore struct {
	*fakeWalkStore
	cancel context.CancelFunc
	err    error
}

func (s *stoppingGetStore) GetWalk(ctx context.Context, id string) (domain.WalkRecord, error) {
	if s.cancel != nil {
		s.cancel()
		return domain.WalkRecord{}, s.err
	}
	return s.fakeWalkStore.GetWalk(ctx, id)
}

// An identity match whose read the run's cancellation stopped is not an
// unreadable walk: nothing is logged about it. A read that genuinely failed is
// still reported, because the run re-walks instead of serving it.
func TestExecuteWalkUseCase_IdentityReadStoppedByTheCancellationIsNotUnreadable(t *testing.T) {
	const modulePath = "github.com/example/proj"
	for _, tc := range []struct {
		name      string
		err       error
		cancelled bool
	}{
		{"cancelled", fmt.Errorf("reading walk: %w", context.Canceled), true},
		{"genuine failure", errors.New("walk record unreadable"), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			projectDir := t.TempDir()
			store := &stoppingGetStore{fakeWalkStore: newFakeWalkStore()}
			var logs bytes.Buffer
			uc := application2.NewExecuteWalkUseCase(buildMinimalWalker(t, modulePath, "v1.0.0"), store, "test-op", "0.3.0",
				slog.New(slog.NewTextHandler(&logs, nil)))
			req := projectWalkRequest(t, modulePath, projectDir, "")
			if _, err := uc.Execute(context.Background(), req); err != nil {
				t.Fatalf("first Execute: %v", err)
			}

			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			store.err = tc.err
			store.cancel = cancel
			if !tc.cancelled {
				store.cancel = func() {}
			}
			_, _ = uc.Execute(ctx, req)
			logged := strings.Contains(logs.String(), "walk_identity_match_unreadable")
			if tc.cancelled && logged {
				t.Errorf("a stopped read was logged as an unreadable walk:\n%s", logs.String())
			}
			if !tc.cancelled && !logged {
				t.Errorf("a genuinely unreadable walk was not reported:\n%s", logs.String())
			}
		})
	}
}
