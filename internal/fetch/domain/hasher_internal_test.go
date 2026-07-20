package domain

import (
	"errors"
	"strings"
	"testing"
)

func TestMarshalCanonical_MarshalFailure(t *testing.T) {
	original := canonicalMarshal
	t.Cleanup(func() { canonicalMarshal = original })
	injected := errors.New("injected marshal failure")
	canonicalMarshal = func(any) ([]byte, error) { return nil, injected }

	_, err := CanonicalHasher{}.SetContentHash(FactRecord{})
	if err == nil {
		t.Fatal("SetContentHash() error = nil, want wrapped marshal error")
	}
	if !errors.Is(err, injected) {
		t.Errorf("SetContentHash() error = %v, want it to wrap the injected error", err)
	}
	if !strings.Contains(err.Error(), "canonical record") {
		t.Errorf("SetContentHash() error = %q, want it to name the record being marshalled", err.Error())
	}
}

func TestVerifyContentHash_MarshalFailure(t *testing.T) {
	original := canonicalMarshal
	t.Cleanup(func() { canonicalMarshal = original })
	injected := errors.New("injected marshal failure")
	canonicalMarshal = func(any) ([]byte, error) { return nil, injected }

	err := CanonicalHasher{}.VerifyContentHash(FactRecord{})
	if !errors.Is(err, injected) {
		t.Errorf("VerifyContentHash() error = %v, want it to wrap the injected error", err)
	}
}
