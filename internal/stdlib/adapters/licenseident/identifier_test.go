package licenseident_test

import (
	"context"
	"errors"
	"testing"

	licports "github.com/eitanity/kanonarion/internal/license/ports"
	"github.com/eitanity/kanonarion/internal/stdlib/adapters/licenseident"
)

type stubDetector struct {
	match licports.LicenseMatch
	err   error
}

func (s stubDetector) Detect(context.Context, []byte) (licports.LicenseMatch, error) {
	return s.match, s.err
}

func (s stubDetector) DetectorMetadata() licports.DetectorMetadata {
	return licports.DetectorMetadata{}
}

func TestIdentify_ReturnsSPDX(t *testing.T) {
	id := licenseident.New(stubDetector{match: licports.LicenseMatch{SPDX: "BSD-3-Clause"}})
	spdx, err := id.Identify(context.Background(), []byte("license text"))
	if err != nil {
		t.Fatalf("Identify: %v", err)
	}
	if spdx != "BSD-3-Clause" {
		t.Errorf("spdx = %q, want BSD-3-Clause", spdx)
	}
}

func TestIdentify_EmptyOnNoMatch(t *testing.T) {
	id := licenseident.New(stubDetector{})
	spdx, err := id.Identify(context.Background(), nil)
	if err != nil || spdx != "" {
		t.Errorf("Identify no-match: spdx=%q err=%v", spdx, err)
	}
}

func TestIdentify_PropagatesError(t *testing.T) {
	id := licenseident.New(stubDetector{err: errors.New("boom")})
	if _, err := id.Identify(context.Background(), nil); err == nil {
		t.Error("expected error to propagate")
	}
}
