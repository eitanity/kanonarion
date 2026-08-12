package cli

import (
	"bytes"
	"strings"
	"testing"
	"time"

	coordinatetest "github.com/eitanity/kanonarion/internal/coordinate/coordinatetest"
	vuldomain "github.com/eitanity/kanonarion/internal/vuln/domain"
)

// referencesGinRecord is the record a scan produces for GO-2020-0001, carrying
// the advisory's own references: two FIX links and two that are not.
func referencesGinRecord() vuldomain.VulnerabilityRecord {
	return vuldomain.VulnerabilityRecord{
		Coordinate:     coordinatetest.MustNew("github.com/gin-gonic/gin", "v1.6.2"),
		WalkID:         "walk-1",
		OverallStatus:  vuldomain.StatusAffected,
		CoverageStatus: vuldomain.CoverageAnalysed,
		FindingsStatus: vuldomain.FindingsRecordAffected,
		ScannedAt:      time.Date(2026, 7, 28, 0, 0, 0, 0, time.UTC),
		Findings: []vuldomain.VulnerabilityFinding{{
			ID:            "GO-2020-0001",
			Summary:       "HTTP request smuggling",
			AffectedRange: "< v1.7.7",
			FixedIn:       "v1.7.7",
			References: []vuldomain.AdvisoryReference{
				{Type: "ADVISORY", URL: "https://nvd.nist.gov/vuln/detail/CVE-2020-28483"},
				{Type: "FIX", URL: "https://github.com/gin-gonic/gin/pull/2237"},
				{Type: "FIX", URL: "https://github.com/gin-gonic/gin/commit/a71af9c1"},
				{Type: "WEB", URL: "https://github.com/gin-gonic/gin/issues/2231"},
			},
		}},
	}
}

// TestPrintVulnRecord_PrintsTheFixReferences covers the text view. An advisory
// publishes up to a dozen links and most of them are places the vulnerability is
// discussed; the FIX ones are the commit or CL that remediates it, and that is
// the only kind this view acts on. The whole list is on the record and in
// --json.
func TestPrintVulnRecord_PrintsTheFixReferences(t *testing.T) {
	var out bytes.Buffer
	printVulnRecord(&out, referencesGinRecord(), nil)
	got := out.String()

	if !strings.Contains(got, "fix refs: https://github.com/gin-gonic/gin/pull/2237, https://github.com/gin-gonic/gin/commit/a71af9c1") {
		t.Errorf("output does not carry the advisory's FIX references:\n%s", got)
	}
	// The other reference types are deliberately not printed here: a WEB mention
	// is not remediation, and printing every link would bury the two that are.
	if strings.Contains(got, "issues/2231") || strings.Contains(got, "nvd.nist.gov") {
		t.Errorf("the text view printed non-FIX references:\n%s", got)
	}
}

// TestPrintVulnRecord_NoReferencesPrintsNoLine guards the honest absence: a
// finding whose advisory was never read carries no references, and the view must
// print nothing rather than an empty label a reader would take for "none
// published".
func TestPrintVulnRecord_NoReferencesPrintsNoLine(t *testing.T) {
	rec := referencesGinRecord()
	rec.Findings[0].References = nil

	var out bytes.Buffer
	printVulnRecord(&out, rec, nil)
	if got := out.String(); strings.Contains(got, "fix refs:") {
		t.Errorf("output carries a fix-refs line for a finding with no references:\n%s", got)
	}
}

// TestPrintVulnRecord_NonFixReferencesAlonePrintNoLine is the pair: an advisory
// that published references but no FIX one has no remediation link to show, and
// an empty "fix refs:" label would state one existed.
func TestPrintVulnRecord_NonFixReferencesAlonePrintNoLine(t *testing.T) {
	rec := referencesGinRecord()
	rec.Findings[0].References = []vuldomain.AdvisoryReference{
		{Type: "WEB", URL: "https://example.com/discussion"},
	}

	var out bytes.Buffer
	printVulnRecord(&out, rec, nil)
	if got := out.String(); strings.Contains(got, "fix refs:") {
		t.Errorf("output carries a fix-refs line for an advisory with no FIX reference:\n%s", got)
	}
}
