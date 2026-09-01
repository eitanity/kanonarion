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

	"github.com/eitanity/kanonarion/internal/coordinate"

	"github.com/eitanity/kanonarion/internal/audit"

	"github.com/eitanity/kanonarion/internal/license/domain"
)

// AuditSink appends an audit event to the assurance log. The shared JSONL
// AuditLog satisfies this; the application depends only on this narrow port,
// not on the factstore adapter that persists it.
type AuditSink interface {
	RecordEvent(audit.Event) error
}

// ErrModuleNotFetched is returned when extraction is attempted for a module
// that has no FactRecord in the store. It states the fact only: the remedy
// depends on the coordinate, so wrappers add fetchdomain.NotFetchedRemedy.
var ErrModuleNotFetched = errors.New("module not fetched")

// ErrLicenceNotFound is returned by LicenceStore.GetLicenceRecord when no
// record exists for the given coordinate and pipeline version.
var ErrLicenceNotFound = errors.New("license record not found")

// ErrLicenceIntegrity is returned by LicenceStore.GetLicenceRecord when the
// stored record's content hash does not match the recomputed hash.
var ErrLicenceIntegrity = errors.New("license record integrity check failed")

// ErrLicenceConflict is returned by LicenceStore.GetLicenceRecord when the
// ledger holds records for one coordinate that composition must not resolve by
// picking: two equally confident detections of the same artefact naming
// different licences, or two records naming different artefacts for one pinned
// version. The wrapped domain.LicenceConflict names the field, the values and
// the records carrying them.
//
// It is an error rather than a quietly chosen answer because a licence is the
// downstream fact with legal weight. Picking one and reporting it as the answer
// makes a relicensing or a misdetection invisible at exactly the moment the
// store is the only thing that could have shown it.
var ErrLicenceConflict = errors.New("conflicting license records")

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
//
// The zero coordinate is the one value the signatures cannot exclude: Go
// always permits coordinate.ModuleCoordinate{}, and it names no module.
// Implementations MUST refuse it with coordinate.ErrZeroCoordinate — on a
// write because it would key a row on the empty path at the empty version,
// which every later read treats as a genuine measurement, and on a read
// because absence is the wrong answer to a question about no module.
// coordinatetest.AssertRefusesZeroCoordinate pins the rule for every store.
type LicenseStore interface {
	// PutLicenceRecord persists a license record. Idempotent on
	// (module_path, module_version, pipeline_version).
	PutLicenseRecord(ctx context.Context, record domain.LicenseRecord) error

	// GetLicenceRecord retrieves the record for the given coordinate and
	// pipeline version. Returns (zero, false, nil) if not found.
	// Returns ErrLicenceIntegrity if the stored hash does not verify.
	GetLicenseRecord(ctx context.Context, coord coordinate.ModuleCoordinate, pipelineVersion string) (domain.LicenseRecord, bool, error)

	// ListLicenceRecords returns summaries matching the filter, ordered by
	// extracted_at descending.
	ListLicenseRecords(ctx context.Context, filter LicenseFilter) ([]LicenseSummary, error)
}

// LicenceRecordLister is the optional capability of reading every generation the
// ledger holds for one coordinate, rather than the composed answer.
//
// It is separate from LicenseStore, on the same terms as fetch's
// FactRecordLister: a store that only ever answers "what is the licence" needs
// none of it, and the history read exists for the callers that need to show what
// was believed before — which is the question the overwriting store could not
// answer at all.
type LicenceRecordLister interface {
	// ListLicenceRecordsFor returns every record held for the coordinate and
	// pipeline version, in the order they were appended. An empty slice and no
	// error means the ledger holds none.
	ListLicenseRecordsFor(ctx context.Context, coord coordinate.ModuleCoordinate, pipelineVersion string) ([]domain.LicenseRecord, error)
}

// IdenticalGenerationReader is the optional after-the-fact read: the generation
// the ledger ALREADY holds that states the measurement a run has just taken.
//
// It answers a question the cache lookup cannot. A cache lookup runs before the
// extraction and asks whether a stored record may be SERVED; for a local
// coordinate the answer is always no, because a local version pins no content
// and the working tree mutates. Recognising afterwards that the extraction came
// back saying what the ledger already says is a different question, and one a run
// can only ask once it holds the answer.
//
// A store that does not offer it appends a generation per run, which is what
// every store did before it existed.
type IdenticalGenerationReader interface {
	// IdenticalGeneration returns the generation stating the same measurement as
	// rec — differing at most in when it was taken — or (zero, false, nil) when
	// the ledger holds none.
	//
	// A record that does not name the artefact it read matches nothing, including
	// another record that names none: absence is not a value two records can
	// share.
	IdenticalGeneration(ctx context.Context, rec domain.LicenseRecord) (domain.LicenseRecord, bool, error)
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

	// Conflict is non-nil when the ledger holds records for this module that
	// composition refuses to resolve by picking, and the other fields are then
	// the zero values — there is no answer to project.
	//
	// It is carried on the row rather than returned as the list's error because
	// those are different failures. One module in dispute must be impossible to
	// miss, but it must not delete the answers for every other module: an
	// operator running license-list over 2,206 modules needs the 2,205 that are
	// fine AND the one that is not. The command still exits non-zero.
	Conflict error
}

// WithLicenceIdentity fills a list row's licence identity from the record it is
// a projection of, read through what each of that record's licences covers.
//
// It lives here, beside the type, because it is the ONE place a listing's
// identity is decided and more than one caller has to reach it: the store
// projects rows through it, and the cross-surface control asserts the listing
// agrees with every other surface through it. A caller that assembled the two
// fields itself would be a second implementation, and a second implementation
// is how the listing came to serve a Go library's embedded font licence while
// `license` on the same coordinate served its own.
//
// The identity does NOT come from the indexed `primary_spdx` and
// `spdx_expression` columns. Those hold what extraction measured, and a record
// written before coverage existed holds a documentation or an embedded-asset
// licence in them; the listing must decode the record to answer, which is what
// its caller does.
func WithLicenceIdentity(row LicenseSummary, rec domain.LicenseRecord) LicenseSummary {
	covered := domain.ReadCoverage(rec)
	row.PrimarySPDX = covered.PrimarySPDX
	row.Expression = covered.Expression
	return row
}
