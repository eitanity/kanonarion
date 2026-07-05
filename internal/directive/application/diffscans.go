package application

import (
	"context"
	"fmt"

	"github.com/eitanity/kanonarion/internal/directive/domain"
	"github.com/eitanity/kanonarion/internal/directive/ports"
)

// DiffScansUseCase loads two directive scans by ID and returns the
// deterministic delta between them. Pure classification lives in
// domain.DiffScans; this use case only orchestrates the loads.
type DiffScansUseCase struct {
	store ports.DirectiveStore
}

// NewDiffScansUseCase constructs the diff use case.
func NewDiffScansUseCase(store ports.DirectiveStore) *DiffScansUseCase {
	return &DiffScansUseCase{store: store}
}

// ErrScanNotFound is returned when one of the requested scan IDs is unknown.
// It is a sentinel so CLI callers can map to a deterministic exit code.
type ErrScanNotFound struct{ ScanID string }

func (e *ErrScanNotFound) Error() string { return "directive scan not found: " + e.ScanID }

// Diff returns the delta between scanA (the older / baseline) and scanB
// (the newer). Both scans must be persisted; a missing ID yields
// *ErrScanNotFound.
func (uc *DiffScansUseCase) Diff(ctx context.Context, scanIDA, scanIDB string) (domain.DirectiveDiff, error) {
	a, foundA, err := uc.store.GetScanByID(ctx, scanIDA)
	if err != nil {
		return domain.DirectiveDiff{}, fmt.Errorf("loading scan %s: %w", scanIDA, err)
	}
	if !foundA {
		return domain.DirectiveDiff{}, &ErrScanNotFound{ScanID: scanIDA}
	}
	b, foundB, err := uc.store.GetScanByID(ctx, scanIDB)
	if err != nil {
		return domain.DirectiveDiff{}, fmt.Errorf("loading scan %s: %w", scanIDB, err)
	}
	if !foundB {
		return domain.DirectiveDiff{}, &ErrScanNotFound{ScanID: scanIDB}
	}
	if a.ProjectModulePath != b.ProjectModulePath {
		return domain.DirectiveDiff{}, fmt.Errorf("scans target different projects: %s vs %s", a.ProjectModulePath, b.ProjectModulePath)
	}
	return domain.DiffScans(a, b), nil
}
