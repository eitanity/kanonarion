package domain_test

import (
	"testing"

	"github.com/eitanity/kanonarion/internal/license/domain"
)

const modulePrefix = "example.com/mod@v1.0.0/"

func buildReadFile(files map[string]string) func(string) ([]byte, bool, error) {
	return func(name string) ([]byte, bool, error) {
		content, ok := files[name]
		if !ok {
			return nil, false, nil
		}
		return []byte(content), true, nil
	}
}

func names(files map[string]string) []string {
	out := make([]string, 0, len(files))
	for k := range files {
		out = append(out, k)
	}
	return out
}

// TestExtractProvenance_InboundOutbound verifies that a CONTRIBUTING file with
// an inbound=outbound declaration produces the InboundOutbound signal.
func TestExtractProvenance_InboundOutbound(t *testing.T) {
	files := map[string]string{
		modulePrefix + "CONTRIBUTING.md": "All contributions are licensed under the same license as the project.\n",
		modulePrefix + "LICENSE":         "MIT License...",
	}
	p := domain.ExtractProvenance(modulePrefix, names(files), buildReadFile(files))
	if !p.HasSignal(domain.ProvenanceSignalInboundOutbound) {
		t.Error("expected InboundOutbound signal")
	}
	if p.HasSignal(domain.ProvenanceSignalCLARequired) {
		t.Error("unexpected CLARequired signal")
	}
	if p.HasSignal(domain.ProvenanceSignalDCORequired) {
		t.Error("unexpected DCORequired signal")
	}
}

// TestExtractProvenance_CLARequired verifies CLA detection in CONTRIBUTING.
func TestExtractProvenance_CLARequired(t *testing.T) {
	files := map[string]string{
		modulePrefix + "CONTRIBUTING": "Please sign the Contributor License Agreement before submitting.\n",
	}
	p := domain.ExtractProvenance(modulePrefix, names(files), buildReadFile(files))
	if !p.HasSignal(domain.ProvenanceSignalCLARequired) {
		t.Error("expected CLARequired signal")
	}
}

// TestExtractProvenance_DCORequired verifies DCO detection in CONTRIBUTING.
func TestExtractProvenance_DCORequired(t *testing.T) {
	files := map[string]string{
		modulePrefix + "CONTRIBUTING.md": "We use the Developer Certificate of Origin for all contributions.\n" +
			"Add a Signed-off-by line to your commits.\n",
	}
	p := domain.ExtractProvenance(modulePrefix, names(files), buildReadFile(files))
	if !p.HasSignal(domain.ProvenanceSignalDCORequired) {
		t.Error("expected DCORequired signal")
	}
}

// TestExtractProvenance_AuthorsAndContributors verifies AUTHORS/CONTRIBUTORS
// presence detection.
func TestExtractProvenance_AuthorsAndContributors(t *testing.T) {
	files := map[string]string{
		modulePrefix + "AUTHORS":      "Jane Doe <jane@example.com>\n",
		modulePrefix + "CONTRIBUTORS": "Jane Doe <jane@example.com>\n",
		modulePrefix + "LICENSE":      "Apache 2.0...",
	}
	p := domain.ExtractProvenance(modulePrefix, names(files), buildReadFile(files))
	if !p.HasSignal(domain.ProvenanceSignalAuthorsFile) {
		t.Error("expected AuthorsFile signal")
	}
	if !p.HasSignal(domain.ProvenanceSignalContributorsFile) {
		t.Error("expected ContributorsFile signal")
	}
}

// TestExtractProvenance_PatentsFile verifies PATENTS file detection.
func TestExtractProvenance_PatentsFile(t *testing.T) {
	files := map[string]string{
		modulePrefix + "PATENTS": "Additional IP Rights Grant...",
	}
	p := domain.ExtractProvenance(modulePrefix, names(files), buildReadFile(files))
	if !p.HasSignal(domain.ProvenanceSignalPatentsFile) {
		t.Error("expected PatentsFile signal")
	}
}

// TestExtractProvenance_NoSignals verifies that a bare module with only a
// LICENSE file produces no provenance signals.
func TestExtractProvenance_NoSignals(t *testing.T) {
	files := map[string]string{
		modulePrefix + "LICENSE": "MIT License...",
	}
	p := domain.ExtractProvenance(modulePrefix, names(files), buildReadFile(files))
	if len(p.Signals) != 0 {
		t.Errorf("expected no signals, got %v", p.Signals)
	}
}

// TestExtractProvenance_VendoredIgnored ensures vendored CONTRIBUTING files
// are not detected.
func TestExtractProvenance_VendoredIgnored(t *testing.T) {
	files := map[string]string{
		modulePrefix + "vendor/dep/CONTRIBUTING.md": "inbound=outbound\n",
		modulePrefix + "LICENSE":                    "MIT License...",
	}
	p := domain.ExtractProvenance(modulePrefix, names(files), buildReadFile(files))
	if p.HasSignal(domain.ProvenanceSignalInboundOutbound) {
		t.Error("vendored CONTRIBUTING must not produce signals")
	}
}

// TestDeriveProvenanceConfidence_High verifies that a contribution-licensing
// statement yields High confidence regardless of copyright status.
func TestDeriveProvenanceConfidence_High(t *testing.T) {
	p := domain.ProvenanceSummary{Signals: []domain.ProvenanceSignal{domain.ProvenanceSignalInboundOutbound}}
	got := domain.DeriveProvenanceConfidence(p, domain.CopyrightStatusNoneFound)
	if got != domain.ChainOfTitleHigh {
		t.Errorf("expected High, got %s", got)
	}
}

// TestDeriveProvenanceConfidence_MediumCopyright verifies that copyright alone
// (without a contribution statement) yields Medium confidence.
func TestDeriveProvenanceConfidence_MediumCopyright(t *testing.T) {
	p := domain.ProvenanceSummary{Signals: nil}
	got := domain.DeriveProvenanceConfidence(p, domain.CopyrightStatusFound)
	if got != domain.ChainOfTitleMedium {
		t.Errorf("expected Medium, got %s", got)
	}
}

// TestDeriveProvenanceConfidence_MediumAuthors verifies that an AUTHORS file
// alone yields Medium confidence.
func TestDeriveProvenanceConfidence_MediumAuthors(t *testing.T) {
	p := domain.ProvenanceSummary{Signals: []domain.ProvenanceSignal{domain.ProvenanceSignalAuthorsFile}}
	got := domain.DeriveProvenanceConfidence(p, domain.CopyrightStatusNoneFound)
	if got != domain.ChainOfTitleMedium {
		t.Errorf("expected Medium, got %s", got)
	}
}

// TestDeriveProvenanceConfidence_Low_Regression verifies that a module
// with neither copyright nor contribution signals reports Low ("claimed but
// unevidenced"), distinct from NotAnalysed (regression pair for).
func TestDeriveProvenanceConfidence_Low_Regression(t *testing.T) {
	p := domain.ProvenanceSummary{Signals: nil}
	got := domain.DeriveProvenanceConfidence(p, domain.CopyrightStatusNoneFound)
	if got != domain.ChainOfTitleLow {
		t.Errorf("expected Low (unevidenced), got %s", got)
	}
	if got == domain.ChainOfTitleNotAnalysed {
		t.Error("Low must be distinct from NotAnalysed")
	}
}
