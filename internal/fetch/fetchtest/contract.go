package fetchtest

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/eitanity/kanonarion/internal/fetch/domain"
)

// RecordWriter is the write half of ports.FactStore. The contract assertions
// below take this rather than the full interface so a fake that only writes —
// and the audit decorator, which is not a whole store either — can be checked
// without growing a read path it does not have.
type RecordWriter interface {
	PutFetchRecord(ctx context.Context, record domain.SealedRecord) error
}

// AssertRefusesUnsealed is the ports.FactStore contract test for the one value
// the PutFetchRecord signature cannot exclude.
//
// SealedRecord is meant to be self-evidencing: Seal and Rehydrate are the only
// ways to make one, so holding one proves the record was hashed. The exported
// struct leaves a gap — domain.SealedRecord{} compiles in any package and seals
// nothing — and an implementation that stores it appends an all-empty row that
// every later read treats as a genuine measurement of the empty module at the
// empty version.
//
// It lives here so the rule has one definition rather than one per store. Every
// FactStore implementation should call it, fakes included: a fake that accepts
// an unsealed record lets an application-layer test go green on a write the real
// store rejects, which is the failure this whole guard exists to prevent.
//
// It asserts the refusal only. Whether the refusal also left the store untouched
// needs a reader, so that leg stays with the implementation that has one.
func AssertRefusesUnsealed(t testing.TB, w RecordWriter) {
	t.Helper()
	err := putRecovering(w)
	if err == nil {
		t.Fatal("fetchtest: the zero SealedRecord was accepted; an unsealed record must never reach storage")
	}
	if !errors.Is(err, domain.ErrUnsealedRecord) {
		t.Fatalf("fetchtest: PutFetchRecord(zero) error = %v, want %v", err, domain.ErrUnsealedRecord)
	}
}

// AssertRefusesZeroIdentity asserts that op refuses the zero artefact identity
// with domain.ErrZeroIdentity.
//
// It exists for the same reason AssertRefusesUnsealed and
// coordinatetest.AssertRefusesZeroCoordinate do: the rule needs one definition
// rather than one per store. Unexporting ArtefactIdentity's fields makes a
// hand-built identity impossible, but Go always permits the zero value, and the
// zero identity names no artefact at all — it would key a row on the empty hash
// on a write, and on a read it asks about nothing, to which absence is the
// wrong answer.
//
// Every implementation that takes an identity should call it, fakes included: a
// fake that accepts the zero identity lets an application-layer test go green
// on a call the real store rejects.
//
// It asserts the refusal only. Whether the refusal also left the store
// untouched needs a reader, so that leg stays with the implementation that has
// one.
func AssertRefusesZeroIdentity(t testing.TB, name string, op func() error) {
	t.Helper()
	err := recovering(op)
	if err == nil {
		t.Fatalf("fetchtest: %s accepted the zero artefact identity; it names no artefact and must never reach storage", name)
	}
	if !errors.Is(err, domain.ErrZeroIdentity) {
		t.Fatalf("fetchtest: %s(zero) error = %v, want %v", name, err, domain.ErrZeroIdentity)
	}
}

// recovering turns a panic into an error so AssertRefusesZeroIdentity reports a
// contract failure rather than a stack trace, on the same terms as
// putRecovering below.
func recovering(op func() error) (err error) {
	defer func() {
		if p := recover(); p != nil {
			err = fmt.Errorf("panicked instead of refusing the zero artefact identity: %v", p)
		}
	}()
	return op()
}

// putRecovering turns a panic into an error so the assertion above reports a
// contract failure rather than a stack trace. An implementation that reaches its
// storage before checking the record panics here as readily as it corrupts
// anything else — the fakes, whose maps are nil until seeded, do exactly that —
// and "it panicked" is the same verdict as "it did not refuse", stated where the
// reader is looking.
func putRecovering(w RecordWriter) (err error) {
	defer func() {
		if p := recover(); p != nil {
			err = fmt.Errorf("panicked instead of refusing the zero SealedRecord: %v", p)
		}
	}()
	// Returned undecorated: the assertion matches it with errors.Is and prints it
	// on failure, so a wrapper here would only put this helper's name in front of
	// the implementation's own answer.
	//nolint:wrapcheck // the caller inspects and reports this error verbatim
	return w.PutFetchRecord(context.Background(), domain.SealedRecord{})
}
