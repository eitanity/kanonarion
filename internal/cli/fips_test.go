package cli

import (
	"bytes"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/eitanity/kanonarion/internal/fips/domain"
)

// fipsRec builds a deterministic record for projection tests. Findings are
// already domain-sorted by the application; we pass them through Sort to
// keep the test honest about what the CLI actually receives.
func fipsRec(capable bool, variant string, findings []domain.Finding) domain.Record {
	domain.Sort(findings)
	return domain.Record{
		ProjectModulePath:    "example.com/proj",
		ToolchainCapable:     capable,
		ToolchainVariant:     variant,
		ToolchainRaw:         "go1.22.0 X:" + variant,
		Findings:             findings,
		ComplianceAssessment: "test assessment",
		Caveat:               domain.EligibilityCaveat,
		CatalogueVersion:     domain.CatalogueVersion(),
		SchemaVersion:        domain.FIPSSchemaVersion,
		PipelineVersion:      domain.PipelineVersion,
		ContentHash:          "sha256:test",
	}
}

// TestToFIPSSection_BucketsByKind: each kind lands in the right top-level
// bucket so an agent reading only `non_fips_algorithm_usage` sees the
// algorithm findings without filtering — 's JSON shape acceptance.
func TestToFIPSSection_BucketsByKind(t *testing.T) {
	rec := fipsRec(true, "boringcrypto", []domain.Finding{
		{Kind: domain.FindingAlgorithm, Package: "crypto/md5",
			Module: "example.com/dep", Source: "a.go", Line: 3,
			Category: domain.CategoryDeviation, PolicyOutcome: "warn", PolicyBlocking: true},
		{Kind: domain.FindingCgoCrypto, Module: "github.com/x/openssl",
			Source: "vendor/github.com/x/openssl/o.go", Line: 1,
			Category: domain.CategoryUnknown, PolicyOutcome: "warn", PolicyBlocking: true},
		{Kind: domain.FindingDirectRandom, Package: "crypto/rand",
			Module: "example.com/proj", Source: "main.go", Line: 4,
			Category: domain.CategoryCompliant, PolicyOutcome: "allow"},
	})
	s := toFIPSSection(rec)

	if !s.ToolchainFIPSCapable || s.ToolchainVariant != "boringcrypto" {
		t.Errorf("toolchain headline lost: %+v", s)
	}
	if s.Caveat == "" || !strings.Contains(strings.ToLower(s.Caveat), "validation") {
		t.Errorf("caveat not surfaced: %q", s.Caveat)
	}
	if len(s.NonFIPSAlgorithmUsage) != 1 || s.NonFIPSAlgorithmUsage[0].Package != "crypto/md5" {
		t.Errorf("non_fips_algorithm_usage bucket wrong: %+v", s.NonFIPSAlgorithmUsage)
	}
	if len(s.CgoCryptoDependencies) != 1 || !strings.Contains(s.CgoCryptoDependencies[0].Module, "openssl") {
		t.Errorf("cgo_crypto_dependencies bucket wrong: %+v", s.CgoCryptoDependencies)
	}
	if len(s.DirectCryptoRandUsage) != 1 {
		t.Errorf("direct_crypto_rand_usage bucket wrong: %+v", s.DirectCryptoRandUsage)
	}
}

// TestToFIPSSection_EmptyBucketsAreArrays: a clean project must still
// serialise non_fips_algorithm_usage: [] (not null) so a JSON consumer
// iterating the bucket never NPEs on missing-vs-empty.
func TestToFIPSSection_EmptyBucketsAreArrays(t *testing.T) {
	s := toFIPSSection(fipsRec(true, "boringcrypto", nil))
	buf, err := json.Marshal(s)
	if err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{`"non_fips_algorithm_usage":[]`, `"cgo_crypto_dependencies":[]`, `"direct_crypto_rand_usage":[]`} {
		if !bytes.Contains(buf, []byte(key)) {
			t.Errorf("missing %s in %s", key, buf)
		}
	}
}

// TestFipsBlockingErr_FlagsToolchainAlgorithmAndCgo: every kind of blocking
// finding produces a recognisable, actionable message in the error string.
// Without provenance the operator could not act on the violation.
func TestFipsBlockingErr_FlagsToolchainAlgorithmAndCgo(t *testing.T) {
	cases := []struct {
		name    string
		section fipsSection
		wantIn  []string
		wantErr bool
	}{
		{
			name: "clean",
			section: toFIPSSection(fipsRec(true, "boringcrypto", []domain.Finding{
				{Kind: domain.FindingToolchain, Category: domain.CategoryCompliant, PolicyOutcome: "allow"},
			})),
			wantErr: false,
		},
		{
			name: "toolchain not capable",
			section: toFIPSSection(fipsRec(false, "", []domain.Finding{
				{Kind: domain.FindingToolchain, ToolchainRaw: "go1.22.0",
					Category: domain.CategoryDeviation, PolicyOutcome: "warn", PolicyBlocking: true},
			})),
			wantIn:  []string{"toolchain", "not FIPS-capable", "go1.22.0"},
			wantErr: true,
		},
		{
			name: "algorithm import",
			section: toFIPSSection(fipsRec(true, "boringcrypto", []domain.Finding{
				{Kind: domain.FindingAlgorithm, Package: "crypto/md5", Module: "example.com/dep",
					Category: domain.CategoryDeviation, PolicyOutcome: "warn", PolicyBlocking: true},
			})),
			wantIn:  []string{"crypto/md5", "example.com/dep"},
			wantErr: true,
		},
		{
			name: "cgo crypto",
			section: toFIPSSection(fipsRec(true, "boringcrypto", []domain.Finding{
				{Kind: domain.FindingCgoCrypto, Module: "github.com/openssl/openssl-go",
					Category: domain.CategoryUnknown, PolicyOutcome: "warn", PolicyBlocking: true},
			})),
			wantIn:  []string{"cgo crypto", "openssl-go"},
			wantErr: true,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			err := fipsBlockingErr(c.section)
			if c.wantErr && err == nil {
				t.Fatalf("want error, got nil")
			}
			if !c.wantErr && err != nil {
				t.Fatalf("want nil, got %v", err)
			}
			if err == nil {
				return
			}
			var xerr *exitError
			if !errors.As(err, &xerr) || xerr.code != ExitConfig {
				t.Errorf("want ExitConfig exitError, got %v", err)
			}
			for _, want := range c.wantIn {
				if !strings.Contains(err.Error(), want) {
					t.Errorf("err = %q, want it to contain %q", err.Error(), want)
				}
			}
		})
	}
}

// TestPrintFIPSTable_RendersHeadlineAndFindings: the human-readable table
// must lead with the toolchain headline + caveat, then list findings with
// source:line provenance so an operator can navigate to the source.
func TestPrintFIPSTable_RendersHeadlineAndFindings(t *testing.T) {
	s := toFIPSSection(fipsRec(true, "boringcrypto", []domain.Finding{
		{Kind: domain.FindingAlgorithm, Package: "crypto/md5", Module: "example.com/dep",
			Source: "vendor/example.com/dep/hash.go", Line: 7,
			Category: domain.CategoryDeviation, PolicyOutcome: "warn"},
	}))
	var buf bytes.Buffer
	if err := printFIPSTable(&buf, s); err != nil {
		t.Fatalf("printFIPSTable: %v", err)
	}
	out := buf.String()
	for _, want := range []string{
		"boringcrypto", "capable=yes", "Caveat:",
		"crypto/md5", "example.com/dep", "vendor/example.com/dep/hash.go:7",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("table output missing %q\n%s", want, out)
		}
	}
}

// TestPrintFIPSTable_CleanProjectMessage: with no findings the table still
// prints the headline and explicitly says "no FIPS findings" rather than
// leaving the user staring at empty output.
func TestPrintFIPSTable_CleanProjectMessage(t *testing.T) {
	s := toFIPSSection(fipsRec(true, "boringcrypto", nil))
	var buf bytes.Buffer
	if err := printFIPSTable(&buf, s); err != nil {
		t.Fatalf("printFIPSTable: %v", err)
	}
	if !strings.Contains(buf.String(), "no FIPS findings") {
		t.Errorf("clean output missing 'no FIPS findings'\n%s", buf.String())
	}
}
