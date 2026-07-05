package application

import (
	"context"
	"fmt"

	fetchdomain "github.com/eitanity/kanonarion/internal/fetch/domain"
	"github.com/eitanity/kanonarion/internal/license/domain"
	licenseports "github.com/eitanity/kanonarion/internal/license/ports"
	walkports "github.com/eitanity/kanonarion/internal/walk/ports"
)

// DepLicenseResult holds the license outcome for a single dependency module.
type DepLicenseResult struct {
	Coordinate  fetchdomain.ModuleCoordinate
	PrimarySPDX string
	Err         error
}

// QueryLicenseUseCase provides read-only access to stored license records.
type QueryLicenseUseCase struct {
	store licenseports.LicenseStore
	walks walkports.WalkStore // nil when walk resolution is not needed
}

// NewQueryLicenseUseCase constructs a QueryLicenseUseCase for simple get/list queries.
func NewQueryLicenseUseCase(store licenseports.LicenseStore) *QueryLicenseUseCase {
	return &QueryLicenseUseCase{store: store}
}

// NewQueryLicenseUseCaseWithWalks constructs a QueryLicenseUseCase that can also
// resolve dependency licenses across a walk graph.
func NewQueryLicenseUseCaseWithWalks(store licenseports.LicenseStore, walks walkports.WalkStore) *QueryLicenseUseCase {
	return &QueryLicenseUseCase{store: store, walks: walks}
}

// GetLicenseRecord retrieves the license record for a module coordinate.
func (uc *QueryLicenseUseCase) GetLicenseRecord(ctx context.Context, coord fetchdomain.ModuleCoordinate, pipelineVersion string) (domain.LicenseRecord, bool, error) {
	rec, found, err := uc.store.GetLicenseRecord(ctx, coord, pipelineVersion)
	if err != nil {
		return domain.LicenseRecord{}, false, fmt.Errorf("getting license record for %s: %w", coord, err)
	}
	return rec, found, nil
}

// ListLicenseRecords returns summaries matching the given filter.
func (uc *QueryLicenseUseCase) ListLicenseRecords(ctx context.Context, filter licenseports.LicenseFilter) ([]licenseports.LicenseSummary, error) {
	sums, err := uc.store.ListLicenseRecords(ctx, filter)
	if err != nil {
		return nil, fmt.Errorf("listing license records: %w", err)
	}
	return sums, nil
}

// ResolveForWalk returns license results for every non-target module in the
// named walk. extractFn is called once per module to retrieve (or extract) its
// license; the caller binds any force/pipeline-version behaviour into it.
// uc must have been constructed with NewQueryLicenseUseCaseWithWalks.
func (uc *QueryLicenseUseCase) ResolveForWalk(
	ctx context.Context,
	walkID string,
	target fetchdomain.ModuleCoordinate,
	extractFn func(context.Context, fetchdomain.ModuleCoordinate) (domain.LicenseRecord, error),
) ([]DepLicenseResult, error) {
	if uc.walks == nil {
		return nil, fmt.Errorf("QueryLicenseUseCase: walks store not configured; use NewQueryLicenseUseCaseWithWalks")
	}

	walk, err := uc.walks.GetWalk(ctx, walkID)
	if err != nil {
		return nil, fmt.Errorf("getting walk %s: %w", walkID, err)
	}

	var results []DepLicenseResult
	for _, node := range walk.Graph.Nodes {
		if node.Coordinate == target {
			continue
		}
		rec, extractErr := extractFn(ctx, node.Coordinate)
		if extractErr != nil {
			results = append(results, DepLicenseResult{Coordinate: node.Coordinate, Err: extractErr})
			continue
		}
		spdx := rec.PrimarySPDX
		if spdx == "" {
			spdx = "None"
		}
		results = append(results, DepLicenseResult{Coordinate: node.Coordinate, PrimarySPDX: spdx})
	}
	return results, nil
}
