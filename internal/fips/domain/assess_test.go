package domain_test

import (
	"strings"
	"testing"

	"github.com/eitanity/kanonarion/internal/fips/domain"
)

// allow is a no-op evaluator for tests that don't care about policy.
func allow(c domain.Category) (string, bool) { return "allow", false }

// flagDeviation evaluates per the default-FIPS-required posture: deviations
// and unknowns warn (blocking); compliant allows.
func flagDeviation(c domain.Category) (string, bool) {
	switch c {
	case domain.CategoryCompliant:
		return "allow", false
	default:
		return "warn", true
	}
}

func TestAssembleAssessmentStockGo(t *testing.T) {
	// Stock Go, no non-FIPS imports → not eligible (toolchain headline).
	res := domain.ParseResult{ProjectModulePath: "example.com/m", ToolchainRaw: "go1.22.0"}
	capable, variant, fs, hash, summary := domain.AssembleAssessment(res, allow)
	if capable || variant != "" {
		t.Fatalf("expected not capable, got capable=%t variant=%q", capable, variant)
	}
	if len(fs) != 1 || fs[0].Kind != domain.FindingToolchain {
		t.Fatalf("expected single toolchain finding, got %+v", fs)
	}
	if fs[0].Category != domain.CategoryDeviation {
		t.Errorf("toolchain finding category = %q, want deviation", fs[0].Category)
	}
	if !strings.Contains(summary, "not eligible") {
		t.Errorf("summary = %q, want not-eligible", summary)
	}
	if hash == "" {
		t.Error("hash is empty")
	}
}

func TestAssembleAssessmentBoringCryptoClean(t *testing.T) {
	// Recognised toolchain, no algorithm findings → eligible.
	res := domain.ParseResult{
		ProjectModulePath: "example.com/m",
		ToolchainRaw:      "go1.22.0 X:boringcrypto",
	}
	capable, variant, _, _, summary := domain.AssembleAssessment(res, allow)
	if !capable || variant != "boringcrypto" {
		t.Fatalf("expected capable boringcrypto, got capable=%t variant=%q", capable, variant)
	}
	if !strings.Contains(summary, "eligible") || strings.Contains(summary, "not eligible") {
		t.Errorf("summary = %q, want eligible", summary)
	}
}

func TestAssembleAssessmentNativeFIPS140(t *testing.T) {
	// Native FIPS mode is capable only when the directive is enabled AND the
	// declared go version ships the Go Cryptographic Module (>= 1.24).
	cases := []struct {
		name        string
		goVersion   string
		fips140     string
		wantCapable bool
	}{
		{"enabled on 1.24", "1.24", "on", true},
		{"enabled on 1.26.4", "1.26.4", "on", true},
		{"versioned value on 1.24", "1.24.0", "v1.0.0", true},
		{"enabled but go 1.23 — mode not effective", "1.23", "on", false},
		{"explicitly off on 1.24", "1.24", "off", false},
		{"directive absent on 1.26", "1.26.4", "", false},
		{"unparseable go version", "garbage", "on", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			res := domain.ParseResult{
				ProjectModulePath: "example.com/m",
				ToolchainRaw:      "go" + tc.goVersion,
				GoVersion:         tc.goVersion,
				FIPS140:           tc.fips140,
			}
			capable, variant, _, _, summary := domain.AssembleAssessment(res, allow)
			if capable != tc.wantCapable {
				t.Fatalf("capable = %t, want %t (variant=%q summary=%q)", capable, tc.wantCapable, variant, summary)
			}
			if tc.wantCapable && variant != domain.NativeFIPS140Variant {
				t.Errorf("variant = %q, want %q", variant, domain.NativeFIPS140Variant)
			}
			if !tc.wantCapable && variant != "" {
				t.Errorf("variant = %q, want empty for not-capable", variant)
			}
		})
	}
}

func TestAssembleAssessmentNotCapableReasons(t *testing.T) {
	// A not-capable toolchain must explain *why*, so a toolchain that simply
	// has FIPS mode switched off is never confused with one too old to support
	// it. The native path must not mention a "catalogue".
	cases := []struct {
		name       string
		goVersion  string
		fips140    string
		wantSubstr []string
		notSubstr  []string
	}{
		{
			name:       "native available, directive absent — not enabled",
			goVersion:  "1.26.4",
			fips140:    "",
			wantSubstr: []string{"not enabled", "go1.26.4", "fips140", "is not set"},
			notSubstr:  []string{"catalogue", "not eligible"},
		},
		{
			name:       "native available, directive off — not enabled",
			goVersion:  "1.24",
			fips140:    "off",
			wantSubstr: []string{"not enabled", "fips140", "is set to off"},
			notSubstr:  []string{"catalogue", "not eligible"},
		},
		{
			name:       "toolchain too old — not eligible",
			goVersion:  "1.23",
			fips140:    "on",
			wantSubstr: []string{"not eligible", "go1.23", "predates", "1.24.0"},
			notSubstr:  []string{"catalogue", "not enabled"},
		},
		{
			name:       "unparseable go version — generic not eligible",
			goVersion:  "garbage",
			fips140:    "",
			wantSubstr: []string{"not eligible"},
			notSubstr:  []string{"catalogue", "not enabled"},
		},
		{
			name:       "go version absent — generic not eligible",
			goVersion:  "",
			fips140:    "",
			wantSubstr: []string{"not eligible"},
			notSubstr:  []string{"catalogue", "not enabled"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			res := domain.ParseResult{
				ProjectModulePath: "example.com/m",
				ToolchainRaw:      "go" + tc.goVersion,
				GoVersion:         tc.goVersion,
				FIPS140:           tc.fips140,
			}
			capable, _, _, _, summary := domain.AssembleAssessment(res, allow)
			if capable {
				t.Fatalf("expected not capable, got capable=true (summary=%q)", summary)
			}
			for _, want := range tc.wantSubstr {
				if !strings.Contains(summary, want) {
					t.Errorf("summary = %q, want it to contain %q", summary, want)
				}
			}
			for _, no := range tc.notSubstr {
				if strings.Contains(summary, no) {
					t.Errorf("summary = %q, must not contain %q", summary, no)
				}
			}
		})
	}
}

func TestAssembleAssessmentDistributionMarkerWinsOverNative(t *testing.T) {
	// An out-of-tree distribution marker is recognised even on an old go
	// version where native mode would not apply.
	res := domain.ParseResult{
		ProjectModulePath: "example.com/m",
		ToolchainRaw:      "go1.22.0 X:boringcrypto",
		GoVersion:         "1.22",
		FIPS140:           "on",
	}
	capable, variant, _, _, _ := domain.AssembleAssessment(res, allow)
	if !capable || variant != "boringcrypto" {
		t.Fatalf("expected boringcrypto, got capable=%t variant=%q", capable, variant)
	}
}

func TestAssembleAssessmentBoringCryptoWithMD5(t *testing.T) {
	// Recognised toolchain, but an algorithm import flags the assessment.
	res := domain.ParseResult{
		ProjectModulePath: "example.com/m",
		ToolchainRaw:      "go1.22.0 X:boringcrypto",
		Findings: []domain.Finding{
			{Kind: domain.FindingAlgorithm, Package: "crypto/md5", Module: "example.com/dep", Source: "dep/hash.go", Line: 10},
		},
	}
	capable, _, fs, _, summary := domain.AssembleAssessment(res, flagDeviation)
	if !capable {
		t.Fatal("expected toolchain capable")
	}
	if !strings.Contains(summary, "crypto/md5") {
		t.Errorf("summary = %q, want it to mention crypto/md5", summary)
	}
	// Sort places toolchain (rank 0) first, then algorithm.
	if fs[0].Kind != domain.FindingToolchain || fs[1].Kind != domain.FindingAlgorithm {
		t.Errorf("order = %v, want toolchain then algorithm", []domain.FindingKind{fs[0].Kind, fs[1].Kind})
	}
	// The algorithm finding is a deviation and blocking under flagDeviation.
	if fs[1].Category != domain.CategoryDeviation || !fs[1].PolicyBlocking {
		t.Errorf("algorithm finding = %+v, want deviation+blocking", fs[1])
	}
}

func TestAssembleAssessmentCgoLimitsAssessment(t *testing.T) {
	res := domain.ParseResult{
		ProjectModulePath: "example.com/m",
		ToolchainRaw:      "go1.22.0 X:boringcrypto",
		Findings: []domain.Finding{
			{Kind: domain.FindingCgoCrypto, Module: "github.com/openssl/openssl-go", Source: "vendor/github.com/openssl/openssl-go/lib.go", Line: 1},
		},
	}
	_, _, fs, _, summary := domain.AssembleAssessment(res, flagDeviation)
	if !strings.Contains(summary, "cgo") || !strings.Contains(summary, "limited") {
		t.Errorf("summary = %q, want cgo-limited summary", summary)
	}
	// Cgo finding is classified unknown (never silently compliant).
	for _, f := range fs {
		if f.Kind == domain.FindingCgoCrypto && f.Category != domain.CategoryUnknown {
			t.Errorf("cgo finding category = %q, want unknown", f.Category)
		}
	}
}

func TestHashIsDeterministic(t *testing.T) {
	res := domain.ParseResult{
		ProjectModulePath: "example.com/m",
		ToolchainRaw:      "go1.22.0 X:boringcrypto",
		Findings: []domain.Finding{
			{Kind: domain.FindingAlgorithm, Package: "crypto/md5", Source: "a.go", Line: 1},
			{Kind: domain.FindingAlgorithm, Package: "crypto/rc4", Source: "b.go", Line: 2},
		},
	}
	_, _, _, h1, _ := domain.AssembleAssessment(res, allow)
	// Reverse input order; assembly must sort, so the hash is unchanged.
	res2 := res
	res2.Findings = []domain.Finding{res.Findings[1], res.Findings[0]}
	_, _, _, h2, _ := domain.AssembleAssessment(res2, allow)
	if h1 != h2 {
		t.Errorf("hash differs for re-ordered findings: %q vs %q", h1, h2)
	}
}

func TestEligibilityCaveatPresent(t *testing.T) {
	// The caveat must mention validation explicitly so consumers cannot
	// misread eligibility as CMVP attestation (acceptance).
	if !strings.Contains(strings.ToLower(domain.EligibilityCaveat), "validation") {
		t.Errorf("caveat = %q, must reference validation distinction", domain.EligibilityCaveat)
	}
}

func TestCatalogueLoaded(t *testing.T) {
	if domain.CatalogueVersion() == "" {
		t.Fatal("CatalogueVersion is empty — embedded catalogue did not load")
	}
	if !domain.IsNonFIPSAlgorithmPackage("crypto/md5") {
		t.Error("crypto/md5 must be a known non-FIPS algorithm package")
	}
	if domain.IsNonFIPSAlgorithmPackage("crypto/sha256") {
		t.Error("crypto/sha256 must NOT be flagged as non-FIPS")
	}
	if got := domain.RecogniseToolchain("go1.22.0 X:boringcrypto"); got != "boringcrypto" {
		t.Errorf("RecogniseToolchain boringcrypto = %q, want boringcrypto", got)
	}
	if got := domain.RecogniseToolchain("go1.22.0"); got != "" {
		t.Errorf("RecogniseToolchain stock = %q, want empty", got)
	}
}
