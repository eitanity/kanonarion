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

	"github.com/eitanity/kanonarion/internal/coordinate"

	"github.com/eitanity/kanonarion/internal/example/domain"
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

// ErrExampleConflict is returned by ExampleStore.GetExampleRecord when the
// ledger holds records for one coordinate that composition must not resolve by
// picking: two records naming different artefacts for one pinned version. The
// wrapped domain.ExampleConflict names the field, the values and the records
// carrying them.
//
// It is an error rather than a quietly chosen answer because there is no ladder
// between answers about two different sets of bytes. Picking one would report an
// answer about bytes the caller never named, and make the disagreement invisible
// at exactly the moment the store is the only thing that could have shown it.
var ErrExampleConflict = errors.New("conflicting example records")

// ExampleParser parses Example* functions out of a module's _test.go files.
type ExampleParser interface {
	// Parse scans every _test.go entry under modulePrefix in the module zip
	// and returns the examples found plus any files that failed to parse.
	Parse(zipData []byte, modulePrefix string) ([]domain.ExampleEntry, []domain.ParseFailure, error)
}

// ExampleStore persists ExampleRecords and supports queries.
//
// The zero coordinate is the one value the signatures cannot exclude: Go
// always permits coordinate.ModuleCoordinate{}, and it names no module.
// Implementations MUST refuse it with coordinate.ErrZeroCoordinate — on a
// write because it would key a row on the empty path at the empty version,
// which every later read treats as a genuine measurement, and on a read
// because absence is the wrong answer to a question about no module.
// coordinatetest.AssertRefusesZeroCoordinate pins the rule for every store.
type ExampleStore interface {
	// PutExampleRecord appends an example record to the ledger. Two distinct
	// extractions are two rows; the same record written twice is one.
	PutExampleRecord(ctx context.Context, record domain.ExampleRecord) error

	// GetExampleRecord retrieves the composed record for the given coordinate
	// and pipeline version. Returns (zero, false, nil) if not found.
	// Returns ErrExampleIntegrity if a stored hash does not verify, and
	// ErrExampleConflict when composition must not pick between the records
	// held.
	GetExampleRecord(ctx context.Context, coord coordinate.ModuleCoordinate, pipelineVersion string) (domain.ExampleRecord, bool, error)

	// ListExampleRecords returns summaries matching the filter, ordered by
	// extracted_at descending.
	ListExampleRecords(ctx context.Context, filter ExampleFilter) ([]ExampleSummary, error)

	// FindBySymbol returns index entries for all examples associated with the
	// given symbol across all stored modules, filtered by pipeline version.
	FindBySymbol(ctx context.Context, symbol string, pipelineVersion string, scope coordinate.ModuleSet) ([]ExampleRef, error)

	// FindBySymbolInModule returns index entries for examples associated with
	// the given symbol within a specific module@version. This is the scoped
	// form used by symbol-context to avoid flooding results from unrelated modules.
	FindBySymbolInModule(ctx context.Context, coord coordinate.ModuleCoordinate, symbol string, pipelineVersion string) ([]ExampleRef, error)
}

// ExampleRecordLister is the optional capability of reading every generation the
// ledger holds for one coordinate, rather than the composed answer.
//
// It is separate from ExampleStore, on the same terms as fetch's
// FactRecordLister and licence's LicenceRecordLister: a store that only ever
// answers "what examples does this module have" needs none of it, and the
// history read exists for the callers that need to show what was found before —
// which is the question the overwriting store could not answer at all.
type ExampleRecordLister interface {
	// ListExampleRecordsFor returns every record held for the coordinate and
	// pipeline version, in the order they were appended. An empty slice and no
	// error means the ledger holds none.
	ListExampleRecordsFor(ctx context.Context, coord coordinate.ModuleCoordinate, pipelineVersion string) ([]domain.ExampleRecord, error)
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

	// Conflict is non-nil when the ledger holds records for this module that
	// composition refused to pick between, and every other field but the three
	// identifying ones is then zero.
	//
	// It is reported on the row rather than raised as the list's error because
	// one disputed module must not delete the answers for every other module.
	// The command still exits non-zero.
	Conflict error
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
