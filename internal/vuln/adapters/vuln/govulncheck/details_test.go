package govulncheck

import (
	"strings"
	"testing"

	"github.com/eitanity/kanonarion/internal/vuln/domain"
)

// longDetails is longer than the 512-byte clip this parse used to apply.
var longDetails = strings.Repeat("the parser allocates without bound. ", 40)

func longDetailsStream() string {
	return `
{"osv": {"id": "GO-2026-1234", "summary": "unbounded allocation", "details": "` + longDetails + `"}}
{"finding": {"osv": "GO-2026-1234", "trace": [{"module": "example.com/mod", "version": "v1.0.0", "function": "Parse"}]}}
`
}

// TestParseResults_CarriesTheAdvisoryDescriptionWhole is the regression test for
// the second half of the route asymmetry: this route clipped an advisory's
// description at 512 bytes, so one advisory described itself differently
// depending on which route recorded it, in a sealed and content-hashed field.
func TestParseResults_CarriesTheAdvisoryDescriptionWhole(t *testing.T) {
	s := New("v1", nil)

	findings, err := s.parseResults(t.Context(), strings.NewReader(longDetailsStream()), "example.com/mod", domain.ScanModeSource)
	if err != nil {
		t.Fatalf("parseResults: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("got %d findings, want 1", len(findings))
	}
	assertWholeDetails(t, findings[0])
}

// TestParseResultsByModule_CarriesTheAdvisoryDescriptionWhole covers the grouped
// parse, which shares the OSV ingest with the isolated one, so neither route can
// keep a clip the other dropped.
func TestParseResultsByModule_CarriesTheAdvisoryDescriptionWhole(t *testing.T) {
	s := New("v1", nil)

	byModule, err := s.parseResultsByModule(t.Context(), strings.NewReader(longDetailsStream()), domain.ScanModeSource)
	if err != nil {
		t.Fatalf("parseResultsByModule: %v", err)
	}
	if len(byModule) != 1 {
		t.Fatalf("got %d modules, want 1: %v", len(byModule), byModule)
	}
	for coord, findings := range byModule {
		if len(findings) != 1 {
			t.Fatalf("%s: got %d findings, want 1", coord, len(findings))
		}
		assertWholeDetails(t, findings[0])
	}
}

func assertWholeDetails(t *testing.T, f domain.VulnerabilityFinding) {
	t.Helper()
	if strings.Contains(f.Details, "(truncated)") {
		t.Errorf("Details carries a truncation marker: %q", f.Details[max(0, len(f.Details)-60):])
	}
	if f.Details != longDetails {
		t.Errorf("Details = %d bytes, want the advisory's %d: the description a reader gets must not depend on which route recorded it",
			len(f.Details), len(longDetails))
	}
}
