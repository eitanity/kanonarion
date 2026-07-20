package application

import (
	"errors"
	"testing"

	"github.com/eitanity/kanonarion/internal/vuln/domain"
)

func TestComputeContentHash_WalkScanRun_MarshalFailure(t *testing.T) {
	original := walkScanRunMarshal
	t.Cleanup(func() { walkScanRunMarshal = original })
	injected := errors.New("injected marshal failure")
	walkScanRunMarshal = func(any) ([]byte, error) { return nil, injected }

	uc := &ScanWalkUseCase{}
	if _, err := uc.ComputeContentHash(domain.WalkScanRun{}); !errors.Is(err, injected) {
		t.Errorf("ComputeContentHash() error = %v, want it to wrap the injected error", err)
	}
}
