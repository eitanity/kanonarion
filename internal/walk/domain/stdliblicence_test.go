package domain_test

import (
	"testing"

	"github.com/eitanity/kanonarion/internal/walk/domain"
)

// TestStdlibLicense pins the single stdlib licence resolution rule every
// surface (SBOM, license-compat, audit) shares: extracted tarball facts when
// present, the published BSD-3-Clause constant when not, with fromFacts
// distinguishing evidence from knowledge.
func TestStdlibLicense(t *testing.T) {
	cases := []struct {
		name          string
		facts         *domain.StdlibFacts
		wantSPDX      string
		wantFromFacts bool
	}{
		{"facts with extracted licence", &domain.StdlibFacts{LicenseSPDX: "BSD-3-Clause"}, "BSD-3-Clause", true},
		{"facts without licence fall back", &domain.StdlibFacts{VerificationStatus: "VerifiedGoDevChecksum"}, domain.StdlibLicenseSPDX, false},
		{"nil facts fall back", nil, domain.StdlibLicenseSPDX, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			spdx, fromFacts := domain.StdlibLicense(tc.facts)
			if spdx != tc.wantSPDX {
				t.Errorf("spdx = %q, want %q", spdx, tc.wantSPDX)
			}
			if fromFacts != tc.wantFromFacts {
				t.Errorf("fromFacts = %v, want %v", fromFacts, tc.wantFromFacts)
			}
		})
	}
}
