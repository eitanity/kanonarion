package application

import (
	"context"
	"fmt"

	"github.com/eitanity/kanonarion/internal/directive/domain"
	"github.com/eitanity/kanonarion/internal/directive/ports"
)

// QueryDirectivesUseCase is read-only access to stored directive records,
// used by the `directives` command and the `audit` directives section.
type QueryDirectivesUseCase struct {
	store ports.DirectiveStore
}

// NewQueryDirectivesUseCase constructs the query use case.
func NewQueryDirectivesUseCase(store ports.DirectiveStore) *QueryDirectivesUseCase {
	return &QueryDirectivesUseCase{store: store}
}

// Get returns the latest stored scan for a project module path. found is
// false (no error) when the project has not been scanned — callers must
// surface that as "not analysed", never as "no directives".
func (uc *QueryDirectivesUseCase) Get(ctx context.Context, projectModulePath string) (domain.Record, bool, error) {
	rec, found, err := uc.store.GetDirectiveRecord(ctx, projectModulePath)
	if err != nil {
		return domain.Record{}, false, fmt.Errorf("querying directive record: %w", err)
	}
	return rec, found, nil
}

// GetScan returns a specific scan by ID.
func (uc *QueryDirectivesUseCase) GetScan(ctx context.Context, scanID string) (domain.Record, bool, error) {
	rec, found, err := uc.store.GetScanByID(ctx, scanID)
	if err != nil {
		return domain.Record{}, false, fmt.Errorf("querying directive scan: %w", err)
	}
	return rec, found, nil
}

// ListScans returns the scan history for a project, newest first.
// limit 0 means unlimited; offset skips that many scans first.
func (uc *QueryDirectivesUseCase) ListScans(ctx context.Context, projectModulePath string, limit, offset int) ([]domain.Record, error) {
	scans, err := uc.store.ListScans(ctx, projectModulePath, limit, offset)
	if err != nil {
		return nil, fmt.Errorf("listing directive scans: %w", err)
	}
	return scans, nil
}

// CountScans returns how many scans the store holds across every project, so a
// caller whose project has none can be told whether anything has ever been
// scanned.
func (uc *QueryDirectivesUseCase) CountScans(ctx context.Context) (int, error) {
	n, err := uc.store.CountScans(ctx)
	if err != nil {
		return 0, fmt.Errorf("counting directive scans: %w", err)
	}
	return n, nil
}
