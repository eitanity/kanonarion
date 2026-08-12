package govulncheck

import (
	"strings"
	"testing"

	"github.com/eitanity/kanonarion/internal/vuln/domain"
)

// referencesStream is a govulncheck -json stream carrying one advisory with its
// references. govulncheck emits the whole OSV entry, so these were on the wire
// for the same reason the retraction timestamp was. Measured on a real
// `govulncheck -format json` run: 233 of 233 OSV messages carried a non-empty
// references array.
const referencesStream = `
{"osv": {"id": "GO-2020-0001", "summary": "HTTP request smuggling", "references": [
  {"type": "WEB", "url": "https://github.com/gin-gonic/gin/issues/2231"},
  {"type": "FIX", "url": "https://github.com/gin-gonic/gin/pull/2237"},
  {"type": "ADVISORY", "url": "https://nvd.nist.gov/vuln/detail/CVE-2020-28483"}
]}}
{"finding": {"osv": "GO-2020-0001", "trace": [{"module": "github.com/gin-gonic/gin", "version": "v1.6.2", "package": "github.com/gin-gonic/gin", "function": "ClientIP", "receiver": "Context"}]}}
`

var wantStreamReferences = []domain.AdvisoryReference{
	{Type: "WEB", URL: "https://github.com/gin-gonic/gin/issues/2231"},
	{Type: "FIX", URL: "https://github.com/gin-gonic/gin/pull/2237"},
	{Type: "ADVISORY", URL: "https://nvd.nist.gov/vuln/detail/CVE-2020-28483"},
}

// TestParseResults_CarriesAdvisoryReferences covers the isolated-module parse.
//
// It matters that this route has the references at all: a finding the source
// analysis reported WINS over the coordinate match that would otherwise have
// supplied them, so without this the same advisory carried its links on a
// metadata-only record and none on an analysed one.
func TestParseResults_CarriesAdvisoryReferences(t *testing.T) {
	s := New("v1", nil)

	findings, err := s.parseResults(t.Context(), strings.NewReader(referencesStream), "github.com/gin-gonic/gin", domain.ScanModeSource)
	if err != nil {
		t.Fatalf("parseResults: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("got %d findings, want 1", len(findings))
	}
	assertReferences(t, findings[0].References)
}

// TestParseResultsByModule_CarriesAdvisoryReferences covers the grouped
// (project- and target-rooted) parse. Both paths share applyOSV precisely so a
// field cannot hold on one and not the other, and the project-rooted path is the
// one a default walk treats as authoritative.
func TestParseResultsByModule_CarriesAdvisoryReferences(t *testing.T) {
	s := New("v1", nil)

	byModule, err := s.parseResultsByModule(t.Context(), strings.NewReader(referencesStream), domain.ScanModeSource)
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
		assertReferences(t, findings[0].References)
	}
}

// TestApplyOSV_MissingEntryStatesNoReferences guards the honest absence: a
// stream that carried findings for an advisory whose OSV message never arrived
// leaves the list nil. An empty list there is the truth about the route, and
// nothing may invent one.
func TestApplyOSV_MissingEntryStatesNoReferences(t *testing.T) {
	s := New("v1", nil)

	stream := `
{"finding": {"osv": "GO-2020-0001", "trace": [{"module": "github.com/gin-gonic/gin", "version": "v1.6.2", "function": "ClientIP", "receiver": "Context"}]}}
`
	findings, err := s.parseResults(t.Context(), strings.NewReader(stream), "github.com/gin-gonic/gin", domain.ScanModeSource)
	if err != nil {
		t.Fatalf("parseResults: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("got %d findings, want 1", len(findings))
	}
	if findings[0].References != nil {
		t.Errorf("references = %+v, want nil: no advisory entry arrived for this finding", findings[0].References)
	}
}

func assertReferences(t *testing.T, got []domain.AdvisoryReference) {
	t.Helper()

	if len(got) != len(wantStreamReferences) {
		t.Fatalf("references = %+v, want %d entries", got, len(wantStreamReferences))
	}
	for i, want := range wantStreamReferences {
		if got[i] != want {
			t.Errorf("reference %d = %+v, want %+v", i, got[i], want)
		}
	}
}
