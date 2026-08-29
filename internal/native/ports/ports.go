// Package ports declares the interfaces the native application layer requires
// from the outside world.
//
// The context reuses BlobStore, FactStore, Clock and Stopwatch from the fetch
// ports package rather than re-declaring them; only the two things this context
// owns are here.
package ports

import (
	"context"
	"errors"

	"github.com/eitanity/kanonarion/internal/coordinate"
	"github.com/eitanity/kanonarion/internal/native/domain"
)

// ErrModuleNotFetched is returned when a module has no fetch record, so there
// is no verified artefact to read.
var ErrModuleNotFetched = errors.New("module not fetched: run 'kanonarion fetch' first")

// ErrNativeConflict is returned when the store holds records describing two
// different artefacts for one pinned version at one generation. Composition
// refuses to pick: the records disagree about what the version's bytes are, and
// choosing one would hide that.
var ErrNativeConflict = errors.New("conflicting embedded-native-component records")

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
