package domain_test

import (
	"strings"
	"testing"

	"github.com/eitanity/kanonarion/internal/license/domain"
)

func TestDeriveExpression_NoEntries(t *testing.T) {
	if got := domain.DeriveExpression(nil, nil); got != "" {
		t.Errorf("DeriveExpression(nil) = %q, want empty", got)
	}
}

func TestDeriveExpression_SingleLicense(t *testing.T) {
	entries := []domain.LicenseFileEntry{
		{Path: "LICENSE", SPDX: "MIT", Confidence: 0.99},
	}
	if got := domain.DeriveExpression(entries, nil); got != "MIT" {
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
	if got := domain.DeriveExpression(entries, nil); got != "MIT" {
		t.Errorf("ambiguous (non-compound) = %q, want MIT", got)
	}
}

// TestDeriveExpression_CompoundFile_TextUnavailable pins what happens when a
// file carries two grants and its text was not supplied: the relationship
// cannot be read, so the expression takes the conservative reading and the
// basis says why. It must never be an election — a choice the file was never
// consulted about is a claim nobody made.
func TestDeriveExpression_CompoundFile_TextUnavailable(t *testing.T) {
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
	res := domain.DeriveExpressionResult(entries, nil)
	if res.Expression != "Apache-2.0 AND MIT" {
		t.Errorf("compound file, no text = %q, want Apache-2.0 AND MIT", res.Expression)
	}
	if !strings.Contains(res.Basis, "unavailable") {
		t.Errorf("basis = %q, want it to state the text was unavailable", res.Basis)
	}
}

func TestDeriveExpression_MultipleFilesSameSPDX(t *testing.T) {
	// Two MIT files → still just "MIT".
	entries := []domain.LicenseFileEntry{
		{Path: "LICENSE", SPDX: "MIT", Confidence: 0.99},
		{Path: "LICENSE.txt", SPDX: "MIT", Confidence: 0.98},
	}
	if got := domain.DeriveExpression(entries, nil); got != "MIT" {
		t.Errorf("same license twice = %q, want MIT", got)
	}
}

// TestDeriveExpression_OmnibusFile_ComponentScoped pins the klauspost/compress
// shape: the module's own grant first, then further grants each scoped by a
// "Files:" stanza to a bundled sub-directory. The module is licensed under its
// own grant alone; the scoped grants are recorded beside the expression, never
// inside it.
func TestDeriveExpression_OmnibusFile_ComponentScoped(t *testing.T) {
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
	res := domain.DeriveExpressionResult(entries, map[string]string{"LICENSE": omnibusText})
	if res.Expression != "BSD-3-Clause" {
		t.Errorf("component-scoped omnibus = %q, want BSD-3-Clause", res.Expression)
	}
	// The most-covered text is the bundled Apache-2.0; the module's own grant
	// is the unscoped one, so the primary follows the reading, not the span.
	if res.PrimarySPDX != "BSD-3-Clause" {
		t.Errorf("primary = %q, want BSD-3-Clause", res.PrimarySPDX)
	}
	if len(res.BundledSPDXs) != 2 || res.BundledSPDXs[0] != "Apache-2.0" || res.BundledSPDXs[1] != "MIT" {
		t.Errorf("bundled = %v, want [Apache-2.0 MIT]", res.BundledSPDXs)
	}
}

// TestDeriveExpression_OmnibusFile_UnanchoredIdentifiers pins the residual
// case: a file bundling licences whose texts cannot be located in it cannot be
// put in order, so no grant can be shown to be somebody else's. The reading is
// conservative and says so.
func TestDeriveExpression_OmnibusFile_UnanchoredIdentifiers(t *testing.T) {
	entries := []domain.LicenseFileEntry{
		{
			Path:       "LICENSE.txt",
			SPDX:       "Apache-2.0",
			Confidence: 0.844,
			AltMatches: []domain.AltMatch{
				{SPDX: "OpenSSL", Confidence: 0.844},
				{SPDX: "NCSA", Confidence: 0.844},
			},
		},
	}
	res := domain.DeriveExpressionResult(entries, map[string]string{"LICENSE.txt": omnibusText})
	if res.Expression != "Apache-2.0 AND NCSA AND OpenSSL" {
		t.Errorf("unanchored omnibus = %q, want the conservative conjunction", res.Expression)
	}
	if !strings.HasPrefix(res.Basis, "conservative:") {
		t.Errorf("basis = %q, want it to state the reading was conservative", res.Basis)
	}
}

func TestDeriveExpression_DualLicenseNaming_OR(t *testing.T) {
	// LICENSE-MIT + LICENSE-APACHE → consumer picks one → OR.
	entries := []domain.LicenseFileEntry{
		{Path: "LICENSE-MIT", SPDX: "MIT", Confidence: 0.99},
		{Path: "LICENSE-APACHE", SPDX: "Apache-2.0", Confidence: 0.99},
	}
	got := domain.DeriveExpression(entries, nil)
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
	got := domain.DeriveExpression(entries, nil)
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
	if got := domain.DeriveExpression(entries, nil); got != "MIT" {
		t.Errorf("ignores vendored = %q, want MIT", got)
	}
}

func TestDeriveExpression_IgnoresNotice(t *testing.T) {
	// NOTICE files do not determine the expression.
	entries := []domain.LicenseFileEntry{
		{Path: "LICENSE", SPDX: "Apache-2.0", Confidence: 0.99},
		{Path: "NOTICE", SPDX: "MIT", Confidence: 0.50},
	}
	if got := domain.DeriveExpression(entries, nil); got != "Apache-2.0" {
		t.Errorf("ignores NOTICE = %q, want Apache-2.0", got)
	}
}

func TestDeriveExpression_IgnoresSubdirectory(t *testing.T) {
	// Only root-level files count; sub-directory entries are ignored.
	entries := []domain.LicenseFileEntry{
		{Path: "LICENSE", SPDX: "MIT", Confidence: 0.99},
		{Path: "subpkg/LICENSE", SPDX: "BSD-3-Clause", Confidence: 0.98},
	}
	if got := domain.DeriveExpression(entries, nil); got != "MIT" {
		t.Errorf("ignores subdirectory = %q, want MIT", got)
	}
}

func TestDeriveExpression_NoSPDX(t *testing.T) {
	// Files present but none identified → empty expression.
	entries := []domain.LicenseFileEntry{
		{Path: "LICENSE", SPDX: "", Confidence: 0},
	}
	if got := domain.DeriveExpression(entries, nil); got != "" {
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
	if got := domain.DeriveExpression(entries, nil); got != "BSD-3-Clause" {
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
	got := domain.DeriveExpression(entries, nil)
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
	got := domain.DeriveExpression(entries, nil)
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

// TestConjunctionArms is the mirror of TestDisjunctionArms: an expression
// yields arms to exactly one of the two, so every disjunctive and mixed shape
// here must come back empty.
func TestConjunctionArms(t *testing.T) {
	cases := []struct {
		name string
		expr string
		want []string
	}{
		{"empty", "", nil},
		{"single identifier", "MIT", nil},
		{"two arms", "Apache-2.0 AND MIT", []string{"Apache-2.0", "MIT"}},
		{"three arms", "Apache-2.0 AND BSD-3-Clause AND MIT", []string{"Apache-2.0", "BSD-3-Clause", "MIT"}},
		{"disjunction is not an obligation set", "Apache-2.0 OR MIT", nil},
		{"mixed operators are not an obligation set", "MIT OR Apache-2.0 AND GPL-2.0-only", nil},
		{"WITH exception qualifies an arm rather than adding one", "GPL-3.0 WITH Classpath-exception-2.0 AND MIT", nil},
		{"duplicate arms collapse below two", "MIT AND MIT", nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := domain.ConjunctionArms(tc.expr)
			if len(got) != len(tc.want) {
				t.Fatalf("ConjunctionArms(%q) = %v, want %v", tc.expr, got, tc.want)
			}
			for i := range got {
				if got[i] != tc.want[i] {
					t.Errorf("ConjunctionArms(%q)[%d] = %q, want %q", tc.expr, i, got[i], tc.want[i])
				}
			}
			if len(domain.DisjunctionArms(tc.expr)) > 0 && len(got) > 0 {
				t.Errorf("%q yielded arms to both readings", tc.expr)
			}
		})
	}
}

// TestSoleIdentifier pins the one-identifier reading: an expression naming a
// single licence resolves to it, and anything carrying an operator resolves to
// nothing — a choice and a set of obligations are both more than one licence.
func TestSoleIdentifier(t *testing.T) {
	cases := map[string]string{
		"Apache-2.0":                        "Apache-2.0",
		"  MIT  ":                           "MIT",
		"":                                  "",
		"Apache-2.0 OR MIT":                 "",
		"MIT AND BSD-3-Clause":              "",
		"GPL-2.0-only WITH Classpath-e":     "",
		"Apache-2.0 OR BSD-3-Clause OR MIT": "",
	}
	for expr, want := range cases {
		if got := domain.SoleIdentifier(expr); got != want {
			t.Errorf("SoleIdentifier(%q) = %q, want %q", expr, got, want)
		}
	}
}
