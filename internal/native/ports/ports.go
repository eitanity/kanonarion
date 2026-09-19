// Package ports declares the interfaces the native application layer requires
// from the outside world.
//
// The context reuses BlobStore, FactStore, Clock and Stopwatch from the fetch
// ports package rather than re-declaring them; only what this context owns is
// here.
package ports

import (
	"context"
	"errors"
	"time"

	"github.com/eitanity/kanonarion/internal/audit"
	"github.com/eitanity/kanonarion/internal/coordinate"
	"github.com/eitanity/kanonarion/internal/native/domain"
)

// ErrModuleNotFetched is returned when a module has no fetch record, so there
// is no verified artefact to read.
var ErrModuleNotFetched = errors.New("module not fetched")

// ErrNativeConflict is returned when the store holds records describing two
// different artefacts for one pinned version at one generation. Composition
// refuses to pick: the records disagree about what the version's bytes are, and
// choosing one would hide that.
var ErrNativeConflict = errors.New("conflicting embedded-native-component records")

// AuditSink appends an audit event to the assurance log. The shared JSONL
// AuditLog satisfies this; the application depends only on this
// narrow port, not on the factstore adapter.
type AuditSink interface {
	RecordEvent(audit.Event) error
}

// GoSourceReader reports what one Go source file declares about how its package
// is built: what it imports, and the C preamble it attaches to `import "C"`.
//
// It is a port because reading either means parsing Go, which is
// infrastructure. The rules those facts feed — that `import "C"` makes a package
// a cgo package, and what a `#cgo LDFLAGS` line names as linked — are the
// domain's.
type GoSourceReader interface {
	// ImportPaths returns the unquoted import paths declared by src. filename
	// is used for error messages only. A file whose import block cannot be
	// parsed is an error, never an empty import set: a package silently read as
	// importing nothing is a package silently read as not using cgo.
	ImportPaths(filename string, src []byte) ([]string, error)

	// CgoPreamble returns the C preamble attached to src's `import "C"`, with
	// the comment markers stripped and the lines otherwise verbatim. A file
	// that declares no such preamble yields the empty string with no error;
	// that is a measured "it links nothing it declares", not a failure.
	CgoPreamble(filename string, src []byte) (string, error)
}

// NativeStore persists and retrieves per-module native-component records.
//
// The zero coordinate is the one value the signatures cannot exclude: Go always
// permits coordinate.ModuleCoordinate{}, and it names no module. Implementations
// MUST refuse it with coordinate.ErrZeroCoordinate on both legs — on a write
// because it would key a row on the empty path at the empty version, and on a
// read because absence is the wrong answer to a question about no module.
type NativeStore interface {
	// PutNativeRecord persists a record. Idempotent for one artefact at one
	// generation: the measurement is a function of the artefact's bytes.
	PutNativeRecord(ctx context.Context, rec domain.Record) error

	// GetNativeRecord returns the record for a coordinate at the current
	// pipeline fingerprint. found is false (with a nil error) when none is
	// held; that reads as "not examined", never as "no native component".
	// It returns ErrNativeConflict when the held records name different
	// artefacts for the same pinned version.
	GetNativeRecord(ctx context.Context, coord coordinate.ModuleCoordinate) (rec domain.Record, found bool, err error)
}

// NativeRecordLister is the optional capability of surveying every native
// record the store holds, rather than fetching one module's.
//
// It is separate from NativeStore, on the same terms as iface's
// InterfaceRecordLister: the SBOM generator asks only "what does this one
// module ship", and forcing a survey onto every consumer of the store would
// make that reader answer for a question it never asks.
type NativeRecordLister interface {
	// ListNativeRecords returns summaries matching the filter. Every field of
	// the filter is honoured; an implementation that ignored one would answer a
	// narrower question with a wider corpus.
	ListNativeRecords(ctx context.Context, filter NativeFilter) ([]NativeSummary, error)
}

// NativeFilter constrains ListNativeRecords results.
type NativeFilter struct {
	// Presence restricts the listing to the presence values named. Empty is
	// unrestricted. Each value is compared for exact equality against the stored
	// presence column, and a row matching any of them is listed.
	//
	// It is a set rather than one value because the question the listing exists
	// to answer — which of my dependencies ship or link native code — is the
	// three values that are not "absent", and asking it must be one command.
	Presence []string

	// AllGenerations lifts the generation restriction. The default — false —
	// lists only records taken at the generation this build serves, because a
	// record from a superseded generation answers no query and would silently
	// pad a count of what is known.
	AllGenerations bool

	Limit  int // 0: no limit
	Offset int
}

// NativeSummary is a projection of one stored record for list views.
//
// It carries the component names and the external libraries rather than only
// their counts, because the question the listing exists to answer — which of
// my dependencies ship or link native code — is not answered by a number.
type NativeSummary struct {
	Coordinate coordinate.ModuleCoordinate
	// Generation is the pipeline fingerprint the record was taken at: the
	// detection logic folded with the recipe catalogue.
	Generation string
	// ArtefactIdentity is the module zip the measurement read. It is on the row
	// because it is part of the record's key: two rows for one coordinate at one
	// generation differ only here, and that difference is a contradiction.
	ArtefactIdentity string
	Presence         domain.Presence
	// Components is every identified native library, empty at every presence but
	// PresenceIdentified. Evidence is carried with them, so a caller that wants
	// to show the declaration need not re-read the record.
	Components []domain.Component
	// SourceCount is how many native files the build compiles from this
	// artefact.
	SourceCount int
	// LinkedExternal is the DISTINCT external libraries the cgo directives name,
	// sorted. Distinct names rather than directives, because one library named
	// by five per-platform directives is one library; the C runtime every cgo
	// binary links is excluded, so it never inflates the count.
	LinkedExternal []string
	ExtractedAt    time.Time
	ContentHash    string

	// Conflict is non-nil when the store holds another record describing a
	// different artefact for this coordinate at this generation. Both rows are
	// listed and both are marked: they disagree about what the version's bytes
	// are, and `native <coord>` refuses to answer for it.
	//
	// It is reported on the row rather than raised as the listing's error
	// because one disputed coordinate must not delete the answers for every
	// other. The command still exits non-zero.
	Conflict error
}
