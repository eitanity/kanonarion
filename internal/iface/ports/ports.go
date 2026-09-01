package ports

import (
	"context"
	"errors"
	"io/fs"
	"time"

	"github.com/eitanity/kanonarion/internal/coordinate"
	"github.com/eitanity/kanonarion/internal/gotoolchain"

	"github.com/eitanity/kanonarion/internal/audit"
	"github.com/eitanity/kanonarion/internal/iface/domain"
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

// ErrInterfaceNotFound is returned by InterfaceStore.GetInterfaceRecord when no
// record exists for the given coordinate and pipeline version.
var ErrInterfaceNotFound = errors.New("interface record not found")

// ErrInterfaceIntegrity is returned when the stored record's content hash does
// not match the recomputed hash.
var ErrInterfaceIntegrity = errors.New("interface record integrity check failed")

// ErrInterfaceConflict is returned by InterfaceStore.GetInterfaceRecord when the
// ledger holds records for one coordinate that composition must not resolve by
// picking: two records naming different artefacts for one pinned version, or two
// records describing the same artefact at the same extraction status that
// disagree about the exported API. The wrapped domain.InterfaceConflict names
// the field, the values and the records carrying them.
//
// The second case is the one this store exists to make visible. A public API is
// close to a deterministic function of the artefact's bytes, so two records that
// the ladder cannot separate and that still disagree are evidence of
// non-determinism in the extractor — and an overwriting store absorbed exactly
// that signal, every time, by keeping only the last answer.
var ErrInterfaceConflict = errors.New("conflicting interface records")

// InterfaceExtractor extracts the public API from a module source tree.
type InterfaceExtractor interface {
	// Extract parses the module source tree and returns an InterfaceRecord.
	// The record may have OverallStatus == Partial if some files failed to
	// parse; only fatal errors return a non-nil error.
	Extract(ctx context.Context, sourceTree fs.FS, coord coordinate.ModuleCoordinate) (domain.InterfaceRecord, error)

	// BuildFrame names the build configuration Extract measures in. A public
	// API is only comparable with another measured in the same frame, so the
	// caller needs the frame even when Extract returned an error: a record that
	// says extraction failed and does not say at what configuration cannot be
	// told apart from one measured elsewhere.
	BuildFrame() domain.BuildFrame

	// Toolchain names the Go toolchain whose release tags Extract measures under,
	// for the same reason and on the same terms as BuildFrame: a failed extraction
	// is still an attempt under one toolchain, and one that cannot say which is
	// not comparable with anything.
	Toolchain() gotoolchain.Version
}

// SignatureReader is the driven port for reading Go declaration TEXT.
//
// An interface record carries formatted signature strings and no type
// information, so any question about what a signature MEANS — whether two of
// them denote the same declaration, whether a declared type is a string-keyed
// registry — has to be answered by parsing that text. Parsing is
// infrastructure, so the comparison asks this port rather than reaching for
// go/parser itself. iface/adapters/spelling/goast implements it.
//
// It restates domain.SignatureReader because a domain package cannot import
// ports; the two shapes are checked against each other at compile time in the
// adapter.
type SignatureReader interface {
	DiffersOnlyInSpelling(a, b string) bool
	RegistryShape(typeText string, localTypes map[string]string) (string, bool)
	ResultRegistryShape(signature string, localTypes map[string]string) (string, bool)
}

// InterfaceStore persists InterfaceRecords and supports queries.
//
// The zero coordinate is the one value the signatures cannot exclude: Go
// always permits coordinate.ModuleCoordinate{}, and it names no module.
// Implementations MUST refuse it with coordinate.ErrZeroCoordinate — on a
// write because it would key a row on the empty path at the empty version,
// which every later read treats as a genuine measurement, and on a read
// because absence is the wrong answer to a question about no module.
// coordinatetest.AssertRefusesZeroCoordinate pins the rule for every store.
type InterfaceStore interface {
	// PutInterfaceRecord appends an interface record to the ledger. Two distinct
	// extractions are two rows; the same record written twice is one.
	PutInterfaceRecord(ctx context.Context, record domain.InterfaceRecord) error

	// GetInterfaceRecord retrieves the composed record for the given coordinate
	// and pipeline version. Returns (zero, false, nil) if not found.
	// Returns ErrInterfaceIntegrity if a stored hash does not verify, and
	// ErrInterfaceConflict when composition must not pick between the records
	// held.
	GetInterfaceRecord(ctx context.Context, coord coordinate.ModuleCoordinate, pipelineVersion string) (domain.InterfaceRecord, bool, error)

	// ListInterfaceRecords returns summaries matching the filter, ordered by
	// extracted_at descending. Every field of the filter is honoured; an
	// implementation that ignored one would answer a narrower question with a
	// wider corpus.
	ListInterfaceRecords(ctx context.Context, filter InterfaceFilter) ([]InterfaceSummary, error)

	// FindSymbol returns index entries for all packages that export a symbol
	// with the given name.
	//
	// scope restricts the result to the modules in one build's resolved version
	// set; the zero ModuleSet imposes no restriction and answers across every
	// stored version, which is what a query that names no build means.
	FindSymbol(ctx context.Context, symbolName string, pipelineVersion string, scope coordinate.ModuleSet) ([]SymbolRef, error)
}

// InterfaceRecordLister is the optional capability of reading every generation
// the ledger holds for one coordinate, rather than the composed answer.
//
// It is separate from InterfaceStore, on the same terms as fetch's
// FactRecordLister and licence's LicenceRecordLister: a store that only ever
// answers "what is this module's API" needs none of it, and the history read
// exists for the callers that need to show what the extractor said before —
// which is where a non-determination becomes examinable rather than merely
// reported.
type InterfaceRecordLister interface {
	// ListInterfaceRecordsFor returns every record held for the coordinate and
	// pipeline version, in the order they were appended. An empty slice and no
	// error means the ledger holds none.
	ListInterfaceRecordsFor(ctx context.Context, coord coordinate.ModuleCoordinate, pipelineVersion string) ([]domain.InterfaceRecord, error)
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
	IdenticalGeneration(ctx context.Context, rec domain.InterfaceRecord) (domain.InterfaceRecord, bool, error)
}

// InterfaceFilter constrains ListInterfaceRecords results.
type InterfaceFilter struct {
	// Coordinate restricts the listing to one module coordinate; nil is
	// unrestricted, on the same terms as walk's WalkFilter.Target.
	//
	// It exists because a question about one coordinate must be askable as one:
	// without it a caller answering "what does the ledger hold for this module"
	// reads the whole corpus and discards all of it but one module's rows, and
	// the ledger is composed generation by generation to produce what it throws
	// away. Restriction happens before that composition.
	Coordinate *coordinate.ModuleCoordinate

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

	// Conflict is non-nil when the ledger holds records for this module that
	// composition refused to pick between, and every other field but the three
	// identifying ones is then zero.
	//
	// It is reported on the row rather than raised as the list's error because
	// one disputed module must not delete the answers for every other module.
	// The command still exits non-zero.
	Conflict error
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
