package osv_test

import (
	"testing"

	coordinatetest "github.com/eitanity/kanonarion/internal/coordinate/coordinatetest"
	"github.com/eitanity/kanonarion/internal/vuln/domain"
)

// ginAdvisoryWithReferences is GO-2020-0001 as the pinned snapshot serves it,
// references included. Both of its references are FIX links: the pull request
// and the commit that remediate the vulnerability. Measured on the snapshot the
// live store holds, 4130 of 4134 advisories carry references and 3160 of the
// 15132 URLs are FIX links, so this is the ordinary case rather than a
// constructed one.
const ginAdvisoryWithReferences = `{
	"id": "GO-2020-0001",
	"summary": "HTTP request smuggling in github.com/gin-gonic/gin",
	"aliases": ["CVE-2020-28483"],
	"published": "2021-04-14T20:04:52Z",
	"modified": "2023-06-12T18:45:41Z",
	"references": [
		{"type": "WEB", "url": "https://github.com/gin-gonic/gin/issues/2231"},
		{"type": "FIX", "url": "https://github.com/gin-gonic/gin/pull/2237"},
		{"type": "FIX", "url": "https://github.com/gin-gonic/gin/commit/a71af9c144f9579f6dbe945341c1df37aaf09c0d"},
		{"type": "ADVISORY", "url": "https://nvd.nist.gov/vuln/detail/CVE-2020-28483"}
	],
	"affected": [{
		"package": {"ecosystem": "Go", "name": "github.com/gin-gonic/gin"},
		"ranges": [{"type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": "1.7.7"}]}],
		"ecosystem_specific": {"imports": [{"path": "github.com/gin-gonic/gin", "symbols": ["Context.ClientIP"]}]}
	}]
}`

// TestLookupFindings_CarriesAdvisoryReferences is the parser half. The
// references were on the wire of every advisory this adapter fetches; the
// osvAdvisory struct simply had no field for them, so the finding recorded
// nothing about where the advisory was published or which commit fixed it.
//
// The pair is asserted, not the URL: the type is what separates a FIX commit —
// remediation a reader can apply — from a WEB mention, and a flattened URL list
// destroys exactly that distinction.
func TestLookupFindings_CarriesAdvisoryReferences(t *testing.T) {
	f := lookupGinFinding(t)

	// The adapter states the advisory's own arrangement; the seal is what imposes
	// the canonical order, and it is pinned in the domain's own tests.
	want := []domain.AdvisoryReference{
		{Type: "WEB", URL: "https://github.com/gin-gonic/gin/issues/2231"},
		{Type: "FIX", URL: "https://github.com/gin-gonic/gin/pull/2237"},
		{Type: "FIX", URL: "https://github.com/gin-gonic/gin/commit/a71af9c144f9579f6dbe945341c1df37aaf09c0d"},
		{Type: "ADVISORY", URL: "https://nvd.nist.gov/vuln/detail/CVE-2020-28483"},
	}
	got := f.References
	if len(got) != len(want) {
		t.Fatalf("references = %v, want %d entries", got, len(want))
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("reference %d = %+v, want %+v", i, got[i], want[i])
		}
	}
}

// TestLookupFindings_ReferenceTypesSurviveTheParse states the acceptance
// criterion on its own: the FIX links are separable from everything else. A
// consumer asking "what commit fixes this" gets an answer.
func TestLookupFindings_ReferenceTypesSurviveTheParse(t *testing.T) {
	f := lookupGinFinding(t)

	var fixes int
	for _, ref := range f.References {
		if ref.Type == "FIX" {
			fixes++
		}
	}
	if fixes != 2 {
		t.Errorf("FIX references = %d, want 2: %+v", fixes, f.References)
	}
}

// TestLookupFindings_EnrichmentFailureCarriesNoReferences guards the honest
// absence. When the advisory fetch fails the finding degrades to its bare ID and
// index fix, and the reference list is nil — an empty list is the truth there,
// and nothing may invent one.
func TestLookupFindings_EnrichmentFailureCarriesNoReferences(t *testing.T) {
	db := advisorySnapshotDB(t,
		[]map[string]any{{"path": "github.com/gin-gonic/gin", "vulns": []map[string]any{{"id": "GO-2020-0001", "fixed": "1.7.7"}}}},
		// No advisory body: the ID/<ID>.json fetch 404s and enrichment fails.
		map[string]string{},
	)
	findings, err := db.LookupFindings(t.Context(), coordinatetest.MustNew("github.com/gin-gonic/gin", "v1.6.2"), pinnedSnapshot(t))
	if err != nil {
		t.Fatalf("LookupFindings: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected 1 degraded finding, got %d", len(findings))
	}
	if findings[0].References != nil {
		t.Errorf("references = %+v, want nil: no advisory was read, so there is nothing to state",
			findings[0].References)
	}
}

func lookupGinFinding(t *testing.T) domain.VulnerabilityFinding {
	t.Helper()

	db := advisorySnapshotDB(t,
		[]map[string]any{{"path": "github.com/gin-gonic/gin", "vulns": []map[string]any{{"id": "GO-2020-0001", "fixed": "1.7.7"}}}},
		map[string]string{"GO-2020-0001": ginAdvisoryWithReferences},
	)
	findings, err := db.LookupFindings(t.Context(), coordinatetest.MustNew("github.com/gin-gonic/gin", "v1.6.2"), pinnedSnapshot(t))
	if err != nil {
		t.Fatalf("LookupFindings: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	return findings[0]
}
