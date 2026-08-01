package domain

import (
	"errors"
	"strings"
	"testing"

	"github.com/eitanity/kanonarion/internal/coordinate"
	"github.com/eitanity/kanonarion/internal/coordinate/coordinatetest"
	fetchdomain "github.com/eitanity/kanonarion/internal/fetch/domain"
)

func TestMarshalCanonicalWalk_MarshalFailure(t *testing.T) {
	original := canonicalMarshal
	t.Cleanup(func() { canonicalMarshal = original })
	injected := errors.New("injected marshal failure")
	canonicalMarshal = func(any) ([]byte, error) { return nil, injected }

	_, err := WalkRecordHasher{}.SetContentHash(WalkRecord{})
	if err == nil {
		t.Fatal("SetContentHash() error = nil, want wrapped marshal error")
	}
	if !errors.Is(err, injected) {
		t.Errorf("SetContentHash() error = %v, want it to wrap the injected error", err)
	}
	if !strings.Contains(err.Error(), "canonical walk record") {
		t.Errorf("SetContentHash() error = %q, want it to name the record being marshalled", err.Error())
	}
}

func TestVerifyContentHash_MarshalFailure(t *testing.T) {
	original := canonicalMarshal
	t.Cleanup(func() { canonicalMarshal = original })
	injected := errors.New("injected marshal failure")
	canonicalMarshal = func(any) ([]byte, error) { return nil, injected }

	err := WalkRecordHasher{}.VerifyContentHash(WalkRecord{})
	if !errors.Is(err, injected) {
		t.Errorf("VerifyContentHash() error = %v, want it to wrap the injected error", err)
	}
}

// TestSetContentHash_FetchRecordMarshalFailure drives the injected
// composite-marshal failure through toCanonicalNodeEntry,
// canonicalNodeResults and marshalCanonicalWalk: a node's fetch record that
// cannot be canonicalised must fail the hash with the coordinate named, never
// hash a record that silently dropped a node's evidence.
func TestSetContentHash_FetchRecordMarshalFailure(t *testing.T) {
	original := marshalCompositeFetch
	t.Cleanup(func() { marshalCompositeFetch = original })
	injected := errors.New("injected composite marshal failure")
	marshalCompositeFetch = func(fetchdomain.CompositeRecord) ([]byte, error) { return nil, injected }

	coord := coordinatetest.MustNew("example.com/mod", "v1.0.0")
	rec := WalkRecord{
		PerNodeResults: map[coordinate.ModuleCoordinate]NodeResult{
			coord: {Coordinate: coord, FetchRecord: &fetchdomain.CompositeRecord{}},
		},
	}
	_, err := WalkRecordHasher{}.SetContentHash(rec)
	if err == nil {
		t.Fatal("SetContentHash() error = nil, want wrapped composite marshal error")
	}
	if !errors.Is(err, injected) {
		t.Errorf("SetContentHash() error = %v, want it to wrap the injected error", err)
	}
	if !strings.Contains(err.Error(), "example.com/mod") {
		t.Errorf("SetContentHash() error = %q, want it to name the failing coordinate", err.Error())
	}
}
