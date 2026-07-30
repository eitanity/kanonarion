package vulntest

import (
	"errors"
	"fmt"
	"testing"

	"github.com/eitanity/kanonarion/internal/vuln/domain"
)

// AssertRefusesZeroSnapshot asserts that op refuses the zero database snapshot
// with domain.ErrZeroSnapshot.
//
// It exists for the same reason coordinatetest.AssertRefusesZeroCoordinate and
// fetchtest.AssertRefusesUnsealed do: the rule needs one definition rather than
// one per store. Unexporting DatabaseSnapshot's fields makes a half-built
// snapshot impossible, but Go always permits the zero value, so the empty
// snapshot is the one that still has to be turned away at the boundary — on a
// write because vulnerability_records composes on (coordinate, pipeline version,
// snapshot), so an admitted row joins the group holding every other record that
// named no snapshot, and on a read because absence is the wrong answer to a
// question about no advisory database.
//
// Every implementation that models the key should call it, fakes included: a
// fake that keys records or blobs on the snapshot and accepts the zero one lets
// an application-layer test go green on a call the real store rejects, which is
// the failure this guard exists to prevent. Measured when the vuln application's
// fakeVulnStore was first held to it: ten diff tests were writing records that
// named no snapshot at all, and the fake had been accepting them.
//
// A fake whose snapshot methods are one-line stubs — `return nil`, `return zero,
// false, nil`, present only to satisfy the interface — is deliberately left
// alone. It models no key, so there is no wrong answer for the guard to catch,
// and adding a refusal would make it look like it stores something it does not.
// A fault-injecting fake is left alone for the same reason in the other
// direction: the error it returns is the subject of its test, and a refusal
// competing with it would answer a different question than the one asked.
//
// It asserts the refusal only. Whether the refusal also left the store untouched
// needs a reader, so that leg stays with the implementation that has one.
func AssertRefusesZeroSnapshot(t testing.TB, name string, op func() error) {
	t.Helper()
	err := recovering(op)
	if err == nil {
		t.Fatalf("vulntest: %s accepted the zero snapshot; it names no advisory database and must never reach storage", name)
	}
	if !errors.Is(err, domain.ErrZeroSnapshot) {
		t.Fatalf("vulntest: %s(zero) error = %v, want %v", name, err, domain.ErrZeroSnapshot)
	}
}

// recovering turns a panic into an error so the assertion reports a contract
// failure rather than a stack trace. An implementation that reaches its storage
// before checking the snapshot panics here as readily as it corrupts anything
// else, and "it panicked" is the same verdict as "it did not refuse", stated
// where the reader is looking.
func recovering(op func() error) (err error) {
	defer func() {
		if p := recover(); p != nil {
			err = fmt.Errorf("panicked instead of refusing the zero snapshot: %v", p)
		}
	}()
	return op()
}
