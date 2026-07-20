package ports

import (
	"context"
	"errors"
	"io/fs"
	"time"

	"github.com/eitanity/kanonarion/internal/coordinate"

	"github.com/eitanity/kanonarion/internal/iface/domain"
)

// ErrModuleNotFetched is returned when extraction is attempted for a module
// that has no FactRecord in the store. Callers should run 'kanonarion fetch' first.
var ErrModuleNotFetched = errors.New("module not fetched: run 'kanonarion fetch' first")

// ErrInterfaceNotFound is returned by InterfaceStore.GetInterfaceRecord when no
// record exists for the given coordinate and pipeline version.
var ErrInterfaceNotFound = errors.New("interface record not found")

// ErrInterfaceIntegrity is returned when the stored record's content hash does
// not match the recomputed hash.
var ErrInterfaceIntegrity = errors.New("interface record integrity check failed")

// InterfaceExtractor extracts the public API from a module source tree.
type InterfaceExtractor interface {
	// Extract parses the module source tree and returns an InterfaceRecord.
	// The record may have OverallStatus == Partial if some files failed to
	// parse; only fatal errors return a non-nil error.
	Extract(ctx context.Context, sourceTree fs.FS, coord coordinate.ModuleCoordinate) (domain.InterfaceRecord, error)
}

// InterfaceStore persists InterfaceRecords and supports queries.
type InterfaceStore interface {
	// PutInterfaceRecord persists an interface record. Idempotent on
	// (module_path, module_version, pipeline_version).
	PutInterfaceRecord(ctx context.Context, record domain.InterfaceRecord) error

	// GetInterfaceRecord retrieves the record for the given coordinate and
	// pipeline version. Returns (zero, false, nil) if not found.
	// Returns ErrInterfaceIntegrity if the stored hash does not verify.
	GetInterfaceRecord(ctx context.Context, coord coordinate.ModuleCoordinate, pipelineVersion string) (domain.InterfaceRecord, bool, error)

	// ListInterfaceRecords returns summaries matching the filter, ordered by
	// extracted_at descending.
	ListInterfaceRecords(ctx context.Context, filter InterfaceFilter) ([]InterfaceSummary, error)

	// FindSymbol returns index entries for all packages that export a symbol
	// with the given name across all stored modules.
	FindSymbol(ctx context.Context, symbolName string, pipelineVersion string) ([]SymbolRef, error)
}

// InterfaceFilter constrains ListInterfaceRecords results.
type InterfaceFilter struct {
	Limit  int // 0: no limit
	Offset int
}

// InterfaceSummary is a lightweight projection of an InterfaceRecord for list views.
type InterfaceSummary struct {
	ModulePath      string
	ModuleVersion   string
	PipelineVersion string
	OverallStatus   domain.InterfaceStatus
	PackageCount    int
	ExtractedAt     time.Time
	ContentHash     string
}

// SymbolRef identifies a symbol in the index, returned by FindSymbol.
type SymbolRef struct {
	ModulePath      string `json:"module_path"`
	ModuleVersion   string `json:"module_version"`
	PipelineVersion string `json:"pipeline_version"`
	PackagePath     string `json:"package_path"`
	SymbolKind      string `json:"symbol_kind"` // "type", "func", "method", "const", "var"
	SymbolName      string `json:"symbol_name"`
	ParentType      string `json:"parent_type,omitempty"` // non-empty for methods
	Signature       string `json:"signature,omitempty"`   // canonical signature or type; empty for pre-migration records
}

// ZipFS is a helper interface satisfied by archive/zip.Reader, used to present
// a module zip as fs.FS.
type ZipFS interface {
	fs.FS
}
