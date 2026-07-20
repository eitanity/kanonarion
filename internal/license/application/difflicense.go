package application

import (
	"context"
	"fmt"

	"github.com/eitanity/kanonarion/internal/coordinate"

	"github.com/eitanity/kanonarion/internal/license/domain"
	licenseports "github.com/eitanity/kanonarion/internal/license/ports"
)

// DiffLicenseUseCase loads two license records by coordinate and returns the
// deterministic delta between them. Pure diff logic lives in
// domain.DiffRecords; this use case only orchestrates the loads.
type DiffLicenseUseCase struct {
	store           licenseports.LicenseStore
	pipelineVersion string
}

// NewDiffLicenseUseCase constructs the diff use case.
func NewDiffLicenseUseCase(store licenseports.LicenseStore) *DiffLicenseUseCase {
	return &DiffLicenseUseCase{store: store, pipelineVersion: PipelineVersion}
}

// ErrLicenseRecordNotFound is returned when one of the requested coordinates
// has no license record in the store. It is a sentinel so CLI callers can map
// to a deterministic exit code.
type ErrLicenseRecordNotFound struct {
	Coordinate coordinate.ModuleCoordinate
}

func (e *ErrLicenseRecordNotFound) Error() string {
	return fmt.Sprintf("license record not found: %s — run 'kanonarion license %s' first", e.Coordinate, e.Coordinate)
}

// Diff returns the deterministic delta between the license records for coordA
// (the older / baseline) and coordB (the newer). Both records must exist in
// the store; a missing coordinate yields *ErrLicenseRecordNotFound.
func (uc *DiffLicenseUseCase) Diff(
	ctx context.Context,
	coordA, coordB coordinate.ModuleCoordinate,
) (domain.LicenseDiff, error) {
	a, foundA, err := uc.store.GetLicenseRecord(ctx, coordA, uc.pipelineVersion)
	if err != nil {
		return domain.LicenseDiff{}, fmt.Errorf("loading license record for %s: %w", coordA, err)
	}
	if !foundA {
		return domain.LicenseDiff{}, &ErrLicenseRecordNotFound{Coordinate: coordA}
	}

	b, foundB, err := uc.store.GetLicenseRecord(ctx, coordB, uc.pipelineVersion)
	if err != nil {
		return domain.LicenseDiff{}, fmt.Errorf("loading license record for %s: %w", coordB, err)
	}
	if !foundB {
		return domain.LicenseDiff{}, &ErrLicenseRecordNotFound{Coordinate: coordB}
	}

	return domain.DiffRecords(a, b), nil
}
