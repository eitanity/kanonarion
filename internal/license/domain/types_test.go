package domain_test

import (
	"testing"

	"github.com/eitanity/kanonarion/internal/coordinate"

	"github.com/eitanity/kanonarion/internal/license/domain"
)

func TestLicenceStatusString(t *testing.T) {
	cases := []struct {
		status domain.LicenseStatus
		want   string
	}{
		{domain.LicenseStatusDetected, "Detected"},
		{domain.LicenceStatusAmbiguous, "Ambiguous"},
		{domain.LicenseStatusMultiple, "Multiple"},
		{domain.LicenseStatusNone, "None"},
		{domain.LicenseStatusUnclassified, "Unclassified"},
		{domain.LicenseStatusExtractionFailed, "ExtractionFailed"},
		{domain.LicenseStatusCancelled, "Cancelled"},
		{domain.LicenceStatusUnknown, "Unknown"},
		{domain.LicenseStatus(99), "Unknown"},
	}
	for _, tc := range cases {
		if got := tc.status.String(); got != tc.want {
			t.Errorf("LicenceStatus(%d).String() = %q; want %q", int(tc.status), got, tc.want)
		}
	}
}

func TestSortFiles(t *testing.T) {
	coord := mustCoord(t, "example.com/m", "v1.0.0")
	r := domain.LicenseRecord{
		Coordinate: coord,
		LicenseFiles: []domain.LicenseFileEntry{
			{Path: "z_LICENSE"},
			{Path: "a_COPYING"},
			{
				Path: "vendor/dep/LICENSE",
				AltMatches: []domain.AltMatch{
					{SPDX: "MIT", Confidence: 0.5},
					{SPDX: "Apache-2.0", Confidence: 0.9},
				},
			},
		},
	}
	r.SortFiles()

	if r.LicenseFiles[0].Path != "a_COPYING" {
		t.Errorf("expected first file a_COPYING, got %s", r.LicenseFiles[0].Path)
	}
	if r.LicenseFiles[1].Path != "vendor/dep/LICENSE" {
		t.Errorf("expected second file vendor/dep/LICENSE, got %s", r.LicenseFiles[1].Path)
	}
	if r.LicenseFiles[2].Path != "z_LICENSE" {
		t.Errorf("expected third file z_LICENSE, got %s", r.LicenseFiles[2].Path)
	}
	alts := r.LicenseFiles[1].AltMatches
	if alts[0].SPDX != "Apache-2.0" || alts[1].SPDX != "MIT" {
		t.Errorf("AltMatches not sorted by Confidence desc: %+v", alts)
	}
}

func mustCoord(t *testing.T, path, version string) coordinate.ModuleCoordinate {
	t.Helper()
	c, err := coordinate.NewModuleCoordinate(path, version)
	if err != nil {
		t.Fatalf("NewModuleCoordinate(%q, %q): %v", path, version, err)
	}
	return c
}
