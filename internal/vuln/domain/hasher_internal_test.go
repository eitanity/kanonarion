package domain

import (
	"errors"
	"testing"
)

// TestWalkScanRunHasher_MarshalFailure exercises the marshal-failure guard via
// the walkScanRunMarshal seam. No field in WalkScanRun can make json.Marshal
// fail today, so this proves the guard's wrapping and propagation are correct,
// not that it is reachable with a real value.
func TestWalkScanRunHasher_MarshalFailure(t *testing.T) {
	original := walkScanRunMarshal
	t.Cleanup(func() { walkScanRunMarshal = original })
	injected := errors.New("injected marshal failure")
	walkScanRunMarshal = func(any) ([]byte, error) { return nil, injected }

	var h WalkScanRunHasher
	if _, err := h.SetContentHash(WalkScanRun{}); !errors.Is(err, injected) {
		t.Errorf("SetContentHash() error = %v, want it to wrap the injected error", err)
	}
	if err := h.VerifyContentHash(WalkScanRun{}); !errors.Is(err, injected) {
		t.Errorf("VerifyContentHash() error = %v, want it to wrap the injected error", err)
	}
}
