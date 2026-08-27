package domain_test

import (
	"reflect"
	"testing"
	"time"

	domain "github.com/eitanity/kanonarion/internal/fetch/domain"
	"github.com/eitanity/kanonarion/internal/wireshape"
)

// determinismSeals is how many times a guard re-seals one value. Map iteration
// order differs between range statements, so a canonical form that leaked one
// would disagree with itself within a handful of attempts.
const determinismSeals = 50

// TestFactRecord_ContentHashIsIndependentOfInputOrder is the determinism guard
// for the fetch fact record.
//
// The record is flat: every field the seal covers is a scalar, so there is no
// arrangement for the seal to depend on and nothing to shuffle. That is a
// property of the shape rather than a promise, so it is enumerated by
// reflection — adding a collection fails here, which is where the decision of
// how to order it has to be made.
func TestFactRecord_ContentHashIsIndependentOfInputOrder(t *testing.T) {
	t.Parallel()

	for _, path := range wireshape.Collections(t, reflect.TypeOf(domain.FactRecord{})) {
		t.Errorf("FactRecord now carries the collection %q, whose order reaches its seal: "+
			"give it a total order in a named comparator and shuffle it here", path)
	}

	var h domain.CanonicalHasher
	var want string
	for i := range determinismSeals {
		sealed, err := h.SetContentHash(makeDeterminismFactRecord())
		if err != nil {
			t.Fatalf("seal %d: SetContentHash: %v", i, err)
		}
		if i == 0 {
			want = sealed.ContentHash
			continue
		}
		if sealed.ContentHash != want {
			t.Fatalf("seal %d: content hash %s, seal 0 gave %s: the seal is not a function of the record alone",
				i, sealed.ContentHash, want)
		}
	}
}

func makeDeterminismFactRecord() domain.FactRecord {
	return domain.FactRecord{
		SchemaVersion:      domain.SchemaVersion,
		Ecosystem:          domain.EcosystemGo,
		ModulePath:         "example.com/mod",
		ModuleVersion:      "v1.2.3",
		ModuleHash:         "h1:aaaa",
		GoModHash:          "h1:bbbb",
		VerificationStatus: "verified",
		FetchedAt:          time.Date(2026, 1, 15, 10, 0, 0, 0, time.UTC),
		PipelineVersion:    "0.1.0",
	}
}
