// Package nativefacts reads a module's stored native-component measurement so
// an SBOM can list the C library a cgo module compiles into the binary from
// source its own published zip ships.
//
// It is an adapter and nothing more: it names the native context's store under
// the port the SBOM context declares, so neither package has to know about the
// other's use cases.
package nativefacts

import (
	"context"
	"fmt"

	"github.com/eitanity/kanonarion/internal/coordinate"

	nativedomain "github.com/eitanity/kanonarion/internal/native/domain"
	nativeports "github.com/eitanity/kanonarion/internal/native/ports"
	sbomports "github.com/eitanity/kanonarion/internal/sbom/ports"
)

// Reader answers what one module's artefact was measured to compile in from
// native source it ships itself.
type Reader struct {
	store nativeports.NativeStore
}

// New returns a Reader over the given native store.
func New(store nativeports.NativeStore) *Reader {
	return &Reader{store: store}
}

// NativeRecord implements sbomports.NativeRecordReader.
//
// A coordinate with no record at the current native generation yields
// (zero, false, nil). That is "this module was never examined", and it is the
// caller's job to keep it distinct from "this module ships no native code" —
// the store cannot tell them apart because only one of them was ever measured.
//
// An error is returned rather than swallowed. The one error this read produces
// is the store holding records that describe two different artefacts for one
// pinned version, which is a contradiction in the evidence an inventory would
// be assembled from; answering "nothing recorded" there would publish a
// document that silently dropped the disagreement.
func (r *Reader) NativeRecord(
	ctx context.Context,
	coord coordinate.ModuleCoordinate,
) (nativedomain.Record, bool, error) {
	rec, found, err := r.store.GetNativeRecord(ctx, coord)
	if err != nil {
		return nativedomain.Record{}, false, fmt.Errorf("reading native-component record for %s: %w", coord, err)
	}
	return rec, found, nil
}

// Reader satisfies the port it is written against; the check is here so a
// signature drift fails at compile time in this package rather than at the
// wiring site.
var _ sbomports.NativeRecordReader = (*Reader)(nil)
