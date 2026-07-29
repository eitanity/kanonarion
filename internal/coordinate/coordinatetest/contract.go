package coordinatetest

import (
	"errors"
	"fmt"
	"testing"

	"github.com/eitanity/kanonarion/internal/coordinate"
)

// AssertRefusesZeroCoordinate asserts that op refuses the zero coordinate with
// coordinate.ErrZeroCoordinate.
//
// It exists for the same reason fetchtest.AssertRefusesUnsealed does: the rule
// needs one definition rather than one per store. Unexporting ModuleCoordinate's
// fields makes a half-built coordinate impossible, but Go always permits the
// zero value, so the empty coordinate is the one that still has to be turned
// away at the boundary — on a write because it would key a row on the empty
// path at the empty version, and on a read because absence is the wrong answer
// to a question about no module.
//
// Every implementation should call it, fakes included: a fake that accepts the
// zero coordinate lets an application-layer test go green on a call the real
// store rejects, which is the failure this guard exists to prevent.
//
// It asserts the refusal only. Whether the refusal also left the store
// untouched needs a reader, so that leg stays with the implementation that has
// one.
func AssertRefusesZeroCoordinate(t testing.TB, name string, op func() error) {
	t.Helper()
	err := recovering(op)
	if err == nil {
		t.Fatalf("coordinatetest: %s accepted the zero coordinate; it names no module and must never reach storage", name)
	}
	if !errors.Is(err, coordinate.ErrZeroCoordinate) {
		t.Fatalf("coordinatetest: %s(zero) error = %v, want %v", name, err, coordinate.ErrZeroCoordinate)
	}
}

// recovering turns a panic into an error so the assertion reports a contract
// failure rather than a stack trace. An implementation that reaches its storage
// before checking the coordinate panics here as readily as it corrupts anything
// else, and "it panicked" is the same verdict as "it did not refuse", stated
// where the reader is looking.
func recovering(op func() error) (err error) {
	defer func() {
		if p := recover(); p != nil {
			err = fmt.Errorf("panicked instead of refusing the zero coordinate: %v", p)
		}
	}()
	return op()
}
