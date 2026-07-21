package ports

import (
	"context"
	"errors"
	"time"

	"github.com/eitanity/kanonarion/internal/coordinate"

	"github.com/eitanity/kanonarion/internal/extract/domain"
)

var (
	ErrExtractionRunNotFound  = errors.New("extraction run not found")
	ErrExtractionRunIntegrity = errors.New("extraction run integrity check failed")
)

type ExtractionStore interface {
	PutExtractionRun(ctx context.Context, run domain.ExtractionRun) error
	GetExtractionRun(ctx context.Context, id string) (domain.ExtractionRun, error)
	ListExtractionRuns(ctx context.Context, filter ExtractionRunFilter) ([]ExtractionRunSummary, error)
}

type ExtractionRunFilter struct {
	WalkID        string
	IDs           []string
	Since         *time.Time
	Until         *time.Time
	OverallStatus *domain.ExtractionRunStatus
	Limit         int
	Offset        int
}

type ExtractionRunSummary struct {
	ID            string
	WalkID        string
	StartedAt     time.Time
	CompletedAt   time.Time
	OverallStatus domain.ExtractionRunStatus
	ModuleCount   int
}

// Extractor abstracts individual stage extractors. The local implementation
// routes by stage name to concrete use cases; a gRPC implementation would
// delegate to a remote service.
type Extractor interface {
	Extract(ctx context.Context, coord coordinate.ModuleCoordinate, stage string, force bool) (StageResult, error)
}

// StageRegistry knows which extraction stages exist and their canonical
// execution order. Injecting this allows the server to register its own set of
// stages without changing the use case.
type StageRegistry interface {
	// Stages returns all known stage names in canonical execution order.
	Stages() []string
	// Has reports whether name is a known stage.
	Has(name string) bool
}

type StageResult struct {
	RecordID   string
	Status     domain.StageStatus
	Error      string
	DurationMs int64
}

// ProgressReporter receives extraction progress so a long, otherwise silent
// run can surface proof of life. done is the count of modules that have
// completed all requested stages so far. Implementations must be safe for
// concurrent use: Execute calls Advance from multiple worker goroutines.
type ProgressReporter interface {
	Advance(done int)
}
