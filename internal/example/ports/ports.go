// Package ports defines the interfaces the example application layer requires
// from the outside world.
//
// The example context reuses BlobStore, FactStore, and Clock from the fetch
// ports package. Those are not re-declared here; the application layer imports
// them directly from fetch/ports.
package ports

import (
	"context"
	"errors"
	"time"

	"github.com/eitanity/kanonarion/internal/example/domain"
	fetchdomain "github.com/eitanity/kanonarion/internal/fetch/domain"
)

// ErrModuleNotFetched is returned when extraction is attempted for a module
// that has no FactRecord in the store. Callers should run 'kanonarion fetch' first.
var ErrModuleNotFetched = errors.New("module not fetched: run 'kanonarion fetch' first")

// ErrExampleNotFound is returned by ExampleStore.GetExampleRecord when no
// record exists for the given coordinate and pipeline version.
var ErrExampleNotFound = errors.New("example record not found")

// ErrExampleIntegrity is returned by ExampleStore.GetExampleRecord when the
// stored record's content hash does not match the recomputed hash.
var ErrExampleIntegrity = errors.New("example record integrity check failed")

// ExampleParser parses Example* functions out of a module's _test.go files.
type ExampleParser interface {
	// Parse scans every _test.go entry under modulePrefix in the module zip
	// and returns the examples found plus any files that failed to parse.
	Parse(zipData []byte, modulePrefix string) ([]domain.ExampleEntry, []domain.ParseFailure, error)
}

// ExampleStore persists ExampleRecords and supports queries.
type ExampleStore interface {
	// PutExampleRecord persists an example record. Idempotent on
	// (module_path, module_version, pipeline_version).
	PutExampleRecord(ctx context.Context, record domain.ExampleRecord) error

	// GetExampleRecord retrieves the record for the given coordinate and
	// pipeline version. Returns (zero, false, nil) if not found.
	// Returns ErrExampleIntegrity if the stored hash does not verify.
	GetExampleRecord(ctx context.Context, coord fetchdomain.ModuleCoordinate, pipelineVersion string) (domain.ExampleRecord, bool, error)

	// ListExampleRecords returns summaries matching the filter, ordered by
	// extracted_at descending.
	ListExampleRecords(ctx context.Context, filter ExampleFilter) ([]ExampleSummary, error)

	// FindBySymbol returns index entries for all examples associated with the
	// given symbol across all stored modules, filtered by pipeline version.
	FindBySymbol(ctx context.Context, symbol string, pipelineVersion string) ([]ExampleRef, error)

	// FindBySymbolInModule returns index entries for examples associated with
	// the given symbol within a specific module@version. This is the scoped
	// form used by symbol-context to avoid flooding results from unrelated modules.
	FindBySymbolInModule(ctx context.Context, coord fetchdomain.ModuleCoordinate, symbol string, pipelineVersion string) ([]ExampleRef, error)
}

// ExampleFilter constrains ListExampleRecords results.
type ExampleFilter struct {
	Limit  int // 0: no limit
	Offset int
}

// ExampleSummary is a lightweight projection of an ExampleRecord for list views.
type ExampleSummary struct {
	ModulePath      string
	ModuleVersion   string
	PipelineVersion string
	OverallStatus   domain.ExampleStatus
	ExampleCount    int
	ExtractedAt     time.Time
	ContentHash     string
}

// ExampleRef identifies a specific example in the index, returned by FindBySymbol.
type ExampleRef struct {
	ModulePath       string
	ModuleVersion    string
	PipelineVersion  string
	Package          string
	AssociatedSymbol string
	ExampleName      string
	Validates        bool
}
