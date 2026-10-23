package domain

import (
	"errors"
	"testing"
)

// A failure to marshal a recorded string is named and propagated, never
// rendered as an empty or null value.
func TestMarshalJSONString_FailureIsPropagated(t *testing.T) {
	original := marshalJSONString
	t.Cleanup(func() { marshalJSONString = original })
	injected := errors.New("injected")
	marshalJSONString = func(string) ([]byte, error) { return nil, injected }

	if _, err := RepoSubdir("client/v3").MarshalJSON(); !errors.Is(err, injected) {
		t.Errorf("RepoSubdir.MarshalJSON = %v, want the injected error", err)
	}
	if _, err := VersionTime("2026-09-08T16:29:55Z").MarshalJSON(); !errors.Is(err, injected) {
		t.Errorf("VersionTime.MarshalJSON = %v, want the injected error", err)
	}
}
