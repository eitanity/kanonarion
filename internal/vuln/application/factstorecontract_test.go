package application_test

import (
	"testing"

	"github.com/eitanity/kanonarion/internal/fetch/fetchtest"
)

// The fake stands in for a real fact store, so it owes the same refusal: a fake
// that accepted the zero SealedRecord would let a test here go green on a write
// the sqlite store rejects.
func TestFakeFactStore_RefusesTheZeroSealedRecord(t *testing.T) {
	fetchtest.AssertRefusesUnsealed(t, &fakeFacts{})
}

// The composed read is what every extraction stage now calls, so the fake owes
// the same answer the sqlite store gives: find the coordinate whatever fetch
// pipeline version measured it, hand every measurement to the composer, and serve
// the strongest rather than the newest.
func TestFakeFactStore_ComposesAcrossFetchPipelineVersions(t *testing.T) {
	fetchtest.AssertComposesAcrossPipelineVersions(t, newFakeFacts())
}
