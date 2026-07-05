// Package ports defines the interfaces the license application layer requires
// from the outside world.
//
// The license context reuses BlobStore, FactStore, and Clock from the fetch
// ports package. Those are not re-declared here; the application layer imports
// them directly from fetch/ports.
package ports

import (
	"context"
	"errors"
	"time"

	"github.com/eitanity/kanonarion/internal/audit"
	fetchdomain "github.com/eitanity/kanonarion/internal/fetch/domain"
	"github.com/eitanity/kanonarion/internal/license/domain"
)

// AuditSink appends an audit event to the assurance log. The shared JSONL
// AuditLog satisfies this; the application depends only on this narrow port,
// not on the factstore adapter that persists it.
type AuditSink interface {
	RecordEvent(audit.Event) error
}

// ErrModuleNotFetched is returned when extraction is attempted for a module
// that has no FactRecord in the store. Callers should run 'kanonarion fetch'
// first.
var ErrModuleNotFetched = errors.New("module not fetched: run 'kanonarion fetch' first")

// ErrLicenceNotFound is returned by LicenceStore.GetLicenceRecord when no
// record exists for the given coordinate and pipeline version.
var ErrLicenceNotFound = errors.New("license record not found")

// ErrLicenceIntegrity is returned by LicenceStore.GetLicenceRecord when the
// stored record's content hash does not match the recomputed hash.
var ErrLicenceIntegrity = errors.New("license record integrity check failed")

// LicenseMatch is the result of running the detector on a single file's
// content. An empty SPDX means no license was identified.
type LicenseMatch struct {
	SPDX       string
	Confidence float64
	AltMatches []LicenseMatch // non-empty when multiple candidates were found
	// LowConfidenceSPDX records a match that fell below the substantive
	// coverage floor. When set, SPDX is empty (the file is not confidently
	// classified) but a recognisable licence fragment was found — e.g. a
	// truncated GPL/AGPL text where only the "how to apply" appendix matches.
	// Callers surface this as a caveat so absence-of-classification is not
	// reported as absence-of-licence.
	LowConfidenceSPDX     string
	LowConfidenceCoverage float64 // coverage fraction (0.0–1.0) of the low-confidence match
}

// DetectorMetadata identifies the detector implementation and its corpus.
type DetectorMetadata struct {
	Name           string
	Version        string
	DataSetVersion string
}

// LicenseDetector classifies file content against known license patterns.
// Implementations must be safe for concurrent use.
type LicenseDetector interface {
	// Detect scans content and returns the best license match. Returns an
	// empty LicenseMatch (zero SPDX) when no license is identified.
	Detect(ctx context.Context, content []byte) (LicenseMatch, error)
	// DetectorMetadata returns metadata identifying the detector version.
	DetectorMetadata() DetectorMetadata
}

// LicenseStore persists LicenceRecords and supports queries.
type LicenseStore interface {
	// PutLicenceRecord persists a license record. Idempotent on
	// (module_path, module_version, pipeline_version).
	PutLicenseRecord(ctx context.Context, record domain.LicenseRecord) error

	// GetLicenceRecord retrieves the record for the given coordinate and
	// pipeline version. Returns (zero, false, nil) if not found.
	// Returns ErrLicenceIntegrity if the stored hash does not verify.
	GetLicenseRecord(ctx context.Context, coord fetchdomain.ModuleCoordinate, pipelineVersion string) (domain.LicenseRecord, bool, error)

	// ListLicenceRecords returns summaries matching the filter, ordered by
	// extracted_at descending.
	ListLicenseRecords(ctx context.Context, filter LicenseFilter) ([]LicenseSummary, error)
}

// LicenseOverrideStore provides operator-supplied license corrections from a
// source the application layer does not care about (YAML config today;
// alternate backends may implement the same port). Implementations return a
// fully materialised set; the precedence rule lives in domain so every
// source resolves identically.
type LicenseOverrideStore interface {
	// LoadOverrides returns the current override set. Implementations return an
	// empty set (not an error) when no overrides are configured.
	LoadOverrides(ctx context.Context) (domain.LicenseOverrideSet, error)
}

// LicenseFilter constrains ListLicenceRecords results.
type LicenseFilter struct {
	SPDX   string                // non-empty: filter by primary_spdx
	Status *domain.LicenseStatus // nil: any status
	Limit  int                   // 0: no limit
	Offset int
}

// LicenseSummary is a lightweight projection of a LicenceRecord for list views.
type LicenseSummary struct {
	ModulePath      string
	ModuleVersion   string
	PipelineVersion string
	PrimarySPDX     string
	Expression      string
	OverallStatus   domain.LicenseStatus
	ExtractedAt     time.Time
	ContentHash     string
}
