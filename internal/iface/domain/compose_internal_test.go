package domain

import (
	"errors"
	"strings"
	"testing"
)

// A digest that cannot be computed must not read as agreement. The marshal is a
// fault seam because no value this shape holds can make json.Marshal fail today;
// the guard exists for the never-silent invariant, and this proves it returns a
// marker no other record's digest can equal rather than a plausible hash.
func TestAPIDigest_UnhashableRecordIsMarkedNotDigested(t *testing.T) {
	original := canonicalMarshal
	t.Cleanup(func() { canonicalMarshal = original })
	injected := errors.New("injected marshal failure")
	canonicalMarshal = func(any) ([]byte, error) { return nil, injected }

	got := APIDigest(InterfaceRecord{})
	if !strings.HasPrefix(got, "unhashable:") {
		t.Errorf("APIDigest = %q, want an unhashable marker", got)
	}
	if !strings.Contains(got, injected.Error()) {
		t.Errorf("the marker does not name the failure: %q", got)
	}
	if strings.HasPrefix(got, "sha256:") {
		t.Errorf("a failure was rendered as a digest: %q", got)
	}
}
