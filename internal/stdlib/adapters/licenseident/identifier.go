// Package licenseident adapts the licence-extraction stage's detector to the
// standard-library ports.LicenseIdentifier, so the stdlib licence is classified
// by the same corpus every module licence is, rather than asserted.
package licenseident

import (
	"context"
	"fmt"

	licports "github.com/eitanity/kanonarion/internal/license/ports"
	"github.com/eitanity/kanonarion/internal/stdlib/ports"
)

// Identifier wraps a license.LicenseDetector.
type Identifier struct {
	detector licports.LicenseDetector
}

// New wraps a licence detector as a stdlib LicenseIdentifier.
func New(detector licports.LicenseDetector) *Identifier {
	return &Identifier{detector: detector}
}

// Identify returns the SPDX identifier the detector reports for content, or ""
// when nothing is confidently classified.
func (i *Identifier) Identify(ctx context.Context, content []byte) (string, error) {
	match, err := i.detector.Detect(ctx, content)
	if err != nil {
		return "", fmt.Errorf("detecting license: %w", err)
	}
	return match.SPDX, nil
}

var _ ports.LicenseIdentifier = (*Identifier)(nil)
