package application

import (
	"context"
	"fmt"

	walkdomain "github.com/eitanity/kanonarion/internal/walk/domain"
	walkports "github.com/eitanity/kanonarion/internal/walk/ports"
)

// QueryWalksUseCase provides read-only access to stored walk records.
type QueryWalksUseCase struct {
	store walkports.WalkStore
}

// NewQueryWalksUseCase constructs a QueryWalksUseCase.
func NewQueryWalksUseCase(store walkports.WalkStore) *QueryWalksUseCase {
	return &QueryWalksUseCase{store: store}
}

// GetWalk retrieves a walk record by ID.
func (uc *QueryWalksUseCase) GetWalk(ctx context.Context, id string) (walkdomain.WalkRecord, error) {
	rec, err := uc.store.GetWalk(ctx, id)
	if err != nil {
		return walkdomain.WalkRecord{}, fmt.Errorf("getting walk %s: %w", id, err)
	}
	return rec, nil
}

// ListWalks returns walk summaries matching the given filter.
func (uc *QueryWalksUseCase) ListWalks(ctx context.Context, filter walkports.WalkFilter) ([]walkports.WalkSummary, error) {
	summaries, err := uc.store.ListWalks(ctx, filter)
	if err != nil {
		return nil, fmt.Errorf("listing walks: %w", err)
	}
	return summaries, nil
}
