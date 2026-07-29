package application_test

import (
	"testing"

	"github.com/eitanity/kanonarion/internal/fetch/fetchtest"
)

// The fake stands in for a real fact store, so it owes the same refusal: a fake
// that accepted the zero SealedRecord would let a test here go green on a write
// the sqlite store rejects.
func TestFakeFactStore_RefusesTheZeroSealedRecord(t *testing.T) {
	fetchtest.AssertRefusesUnsealed(t, &fakeFactStore{})
}
