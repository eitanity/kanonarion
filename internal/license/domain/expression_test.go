package domain_test

import (
	"testing"

	"github.com/eitanity/kanonarion/internal/license/domain"
)

func TestDeriveExpression_NoEntries(t *testing.T) {
	if got := domain.DeriveExpression(nil); got != "" {
		t.Errorf("DeriveExpression(nil) = %q, want empty", got)
	}
}

func TestDeriveExpression_SingleLicense(t *testing.T) {
	entries := []domain.LicenseFileEntry{
		{Path: "LICENSE", SPDX: "MIT", Confidence: 0.99},
	}
	if got := domain.DeriveExpression(entries); got != "MIT" {
		t.Errorf("single license = %q, want MIT", got)
	}
}

func TestDeriveExpression_AmbiguousNoCompound(t *testing.T) {
	// Alt confidence is well below primary (>0.005 gap) → single id, not OR.
	entries := []domain.LicenseFileEntry{
		{
			Path:       "LICENSE",
			SPDX:       "MIT",
			Confidence: 0.99,
			AltMatches: []domain.AltMatch{
				{SPDX: "Apache-2.0", Confidence: 0.50},
			},
		},
	}
	if got := domain.DeriveExpression(entries); got != "MIT" {
		t.Errorf("ambiguous (non-compound) = %q, want MIT", got)
	}
}

func TestDeriveExpression_CompoundFile_OR(t *testing.T) {
	// yaml.v3 scenario: one file, two licenses at near-equal coverage (delta ≤ 0.005).
	entries := []domain.LicenseFileEntry{
		{
			Path:       "LICENSE",
			SPDX:       "MIT",
			Confidence: 0.999,
			AltMatches: []domain.AltMatch{
				{SPDX: "Apache-2.0", Confidence: 0.996},
			},
		},
	}
	got := domain.DeriveExpression(entries)
	if got != "Apache-2.0 OR MIT" {
		t.Errorf("compound file = %q, want Apache-2.0 OR MIT", got)
	}
}

func TestDeriveExpression_MultipleFilesSameSPDX(t *testing.T) {
	// Two MIT files → still just "MIT".
	entries := []domain.LicenseFileEntry{
		{Path: "LICENSE", SPDX: "MIT", Confidence: 0.99},
		{Path: "LICENSE.txt", SPDX: "MIT", Confidence: 0.98},
	}
	if got := domain.DeriveExpression(entries); got != "MIT" {
		t.Errorf("same license twice = %q, want MIT", got)
	}
}

func TestDeriveExpression_OmnibusFile_TwoAlts(t *testing.T) {
	// klauspost/compress pattern: root LICENSE bundles Apache-2.0 primary plus
	// BSD-3-Clause and MIT texts for vendored sub-packages. 2 alts at identical
	// confidence → omnibus attribution file, not dual-licensing. Return primary only.
	entries := []domain.LicenseFileEntry{
		{
			Path:       "LICENSE",
			SPDX:       "Apache-2.0",
			Confidence: 0.991,
			AltMatches: []domain.AltMatch{
				{SPDX: "BSD-3-Clause", Confidence: 0.991},
				{SPDX: "MIT", Confidence: 0.991},
			},
		},
	}
	if got := domain.DeriveExpression(entries); got != "Apache-2.0" {
		t.Errorf("omnibus 2-alt = %q, want Apache-2.0", got)
	}
}

func TestDeriveExpression_OmnibusFile_ManyAlts(t *testing.T) {
	// apache/arrow pattern: root LICENSE.txt bundles 8 third-party license texts.
	// All 9 identifiers at identical confidence → omnibus attribution, return primary.
	entries := []domain.LicenseFileEntry{
		{
			Path:       "LICENSE.txt",
			SPDX:       "Apache-2.0",
			Confidence: 0.844,
			AltMatches: []domain.AltMatch{
				{SPDX: "OpenSSL", Confidence: 0.844},
				{SPDX: "BSD-3-Clause", Confidence: 0.844},
				{SPDX: "NCSA", Confidence: 0.844},
				{SPDX: "BSD-2-Clause", Confidence: 0.844},
				{SPDX: "MIT", Confidence: 0.844},
				{SPDX: "BSL-1.0", Confidence: 0.844},
				{SPDX: "Zlib", Confidence: 0.844},
				{SPDX: "HPND", Confidence: 0.844},
			},
		},
	}
	if got := domain.DeriveExpression(entries); got != "Apache-2.0" {
		t.Errorf("omnibus 8-alt = %q, want Apache-2.0", got)
	}
}

func TestDeriveExpression_DualLicenseNaming_OR(t *testing.T) {
	// LICENSE-MIT + LICENSE-APACHE → consumer picks one → OR.
	entries := []domain.LicenseFileEntry{
		{Path: "LICENSE-MIT", SPDX: "MIT", Confidence: 0.99},
		{Path: "LICENSE-APACHE", SPDX: "Apache-2.0", Confidence: 0.99},
	}
	got := domain.DeriveExpression(entries)
	if got != "Apache-2.0 OR MIT" {
		t.Errorf("dual-license naming = %q, want Apache-2.0 OR MIT", got)
	}
}

func TestDeriveExpression_MixedFiles_AND(t *testing.T) {
	// Two files with different licenses and no dual-license naming → AND.
	entries := []domain.LicenseFileEntry{
		{Path: "LICENSE", SPDX: "Apache-2.0", Confidence: 0.99},
		{Path: "COPYING", SPDX: "GPL-2.0-only", Confidence: 0.98},
	}
	got := domain.DeriveExpression(entries)
	if got != "Apache-2.0 AND GPL-2.0-only" {
		t.Errorf("mixed files = %q, want Apache-2.0 AND GPL-2.0-only", got)
	}
}

func TestDeriveExpression_IgnoresVendored(t *testing.T) {
	// Only the root-level file should determine the expression.
	entries := []domain.LicenseFileEntry{
		{Path: "LICENSE", SPDX: "MIT", Confidence: 0.99},
		{Path: "vendor/github.com/foo/bar/LICENSE", SPDX: "Apache-2.0", Confidence: 0.99, IsVendored: true},
	}
	if got := domain.DeriveExpression(entries); got != "MIT" {
		t.Errorf("ignores vendored = %q, want MIT", got)
	}
}

func TestDeriveExpression_IgnoresNotice(t *testing.T) {
	// NOTICE files do not determine the expression.
	entries := []domain.LicenseFileEntry{
		{Path: "LICENSE", SPDX: "Apache-2.0", Confidence: 0.99},
		{Path: "NOTICE", SPDX: "MIT", Confidence: 0.50},
	}
	if got := domain.DeriveExpression(entries); got != "Apache-2.0" {
		t.Errorf("ignores NOTICE = %q, want Apache-2.0", got)
	}
}

func TestDeriveExpression_IgnoresSubdirectory(t *testing.T) {
	// Only root-level files count; sub-directory entries are ignored.
	entries := []domain.LicenseFileEntry{
		{Path: "LICENSE", SPDX: "MIT", Confidence: 0.99},
		{Path: "subpkg/LICENSE", SPDX: "BSD-3-Clause", Confidence: 0.98},
	}
	if got := domain.DeriveExpression(entries); got != "MIT" {
		t.Errorf("ignores subdirectory = %q, want MIT", got)
	}
}

func TestDeriveExpression_NoSPDX(t *testing.T) {
	// Files present but none identified → empty expression.
	entries := []domain.LicenseFileEntry{
		{Path: "LICENSE", SPDX: "", Confidence: 0},
	}
	if got := domain.DeriveExpression(entries); got != "" {
		t.Errorf("no SPDX = %q, want empty", got)
	}
}

func TestDeriveExpression_FiltersPseudoIdentifier(t *testing.T) {
	// jezek/xgb pattern: BSD-3-Clause file with GooglePatentClause pseudo-alt
	// at near-equal confidence. GooglePatentClause is not a real SPDX id and
	// must not produce a spurious OR expression.
	entries := []domain.LicenseFileEntry{
		{
			Path:       "LICENSE",
			SPDX:       "BSD-3-Clause",
			Confidence: 0.98,
			AltMatches: []domain.AltMatch{
				{SPDX: "GooglePatentClause", Confidence: 0.975},
			},
		},
	}
	if got := domain.DeriveExpression(entries); got != "BSD-3-Clause" {
		t.Errorf("pseudo-id filtered = %q, want BSD-3-Clause", got)
	}
}

func TestDeriveExpression_BareNameDualLicence_OR(t *testing.T) {
	// gorhill/cronexpr ships APLv2 beside GPLv3: bare licence-name files are
	// per-licence naming, so the consumer elects one arm → OR, never AND.
	entries := []domain.LicenseFileEntry{
		{Path: "APLv2", SPDX: "Apache-2.0", Confidence: 0.99},
		{Path: "GPLv3", SPDX: "GPL-3.0", Confidence: 0.95},
	}
	got := domain.DeriveExpression(entries)
	if got != "Apache-2.0 OR GPL-3.0" {
		t.Errorf("bare-name dual licence = %q, want Apache-2.0 OR GPL-3.0", got)
	}
}

func TestDeriveExpression_ReversedNameBesidePlainLicence_OR(t *testing.T) {
	// sergi/go-diff ships APACHE-LICENSE-2.0 beside a plain MIT LICENSE: the
	// licence-naming file signals the election even when its sibling is plain.
	entries := []domain.LicenseFileEntry{
		{Path: "LICENSE", SPDX: "MIT", Confidence: 0.99},
		{Path: "APACHE-LICENSE-2.0", SPDX: "Apache-2.0", Confidence: 0.99},
	}
	got := domain.DeriveExpression(entries)
	if got != "Apache-2.0 OR MIT" {
		t.Errorf("reversed-name dual licence = %q, want Apache-2.0 OR MIT", got)
	}
}

func TestDisjunctionArms(t *testing.T) {
	cases := []struct {
		name string
		expr string
		want []string
	}{
		{"empty", "", nil},
		{"single identifier", "MIT", nil},
		{"two arms", "Apache-2.0 OR GPL-3.0", []string{"Apache-2.0", "GPL-3.0"}},
		{"three arms", "Apache-2.0 OR GPL-3.0 OR MIT", []string{"Apache-2.0", "GPL-3.0", "MIT"}},
		{"conjunction is not an election", "Apache-2.0 AND GPL-2.0-only", nil},
		{"mixed operators are not an election", "MIT OR Apache-2.0 AND GPL-2.0-only", nil},
		{"WITH exception is not an election", "GPL-3.0 WITH Classpath-exception-2.0 OR MIT", nil},
		{"duplicate arms collapse below two", "MIT OR MIT", nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := domain.DisjunctionArms(tc.expr)
			if len(got) != len(tc.want) {
				t.Fatalf("DisjunctionArms(%q) = %v, want %v", tc.expr, got, tc.want)
			}
			for i := range got {
				if got[i] != tc.want[i] {
					t.Errorf("DisjunctionArms(%q)[%d] = %q, want %q", tc.expr, i, got[i], tc.want[i])
				}
			}
		})
	}
}
