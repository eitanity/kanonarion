package osv_test

import (
	"net/http/httptest"
	"testing"

	coordinatetest "github.com/eitanity/kanonarion/internal/coordinate/coordinatetest"
	"github.com/eitanity/kanonarion/internal/vuln/adapters/vulndb/osv"
)

// threeBranchAdvisory is the shape a backported advisory has: one
// introduced/fixed pair per maintained release branch, oldest first. It is the
// standard-library case that made the defect visible — the last pair names an
// unreleased release candidate — and index/modules.json collapses the three to
// that single highest value.
const threeBranchAdvisory = `{
	"id": "GO-2026-9200",
	"summary": "Fix Javascript regexp context tracking in html/template",
	"published": "2026-08-01T00:00:00Z",
	"modified": "2026-08-02T00:00:00Z",
	"affected": [{
		"package": {"ecosystem": "Go", "name": "stdlib"},
		"ranges": [{"type": "SEMVER", "events": [
			{"introduced": "0"}, {"fixed": "1.25.13"},
			{"introduced": "1.26.0-0"}, {"fixed": "1.26.6"},
			{"introduced": "1.27.0-0"}, {"fixed": "1.27.0-rc.3"}
		]}],
		"ecosystem_specific": {"imports": [{"path": "html/template", "symbols": ["Template.Execute"]}]}
	}]
}`

// moduleThreeBranchAdvisory is the same shape on an ordinary module path. The
// selection must not be a standard-library special case: a library backporting a
// fix across two supported minors has exactly the same problem.
const moduleThreeBranchAdvisory = `{
	"id": "GO-2026-9201",
	"summary": "Excessive CPU in example.com/text",
	"published": "2026-08-01T00:00:00Z",
	"modified": "2026-08-02T00:00:00Z",
	"affected": [{
		"package": {"ecosystem": "Go", "name": "example.com/text"},
		"ranges": [{"type": "SEMVER", "events": [
			{"introduced": "0"}, {"fixed": "0.38.1"},
			{"introduced": "0.39.0"}, {"fixed": "0.39.2"},
			{"introduced": "0.40.0"}, {"fixed": "0.40.0-rc.1"}
		]}],
		"ecosystem_specific": {"imports": [{"path": "example.com/text/unicode", "symbols": ["Form.String"]}]}
	}]
}`

// lookupOne runs a metadata lookup against a one-advisory fake database and
// returns the single finding it produced.
func lookupOne(t *testing.T, path, indexFixed, id, advisory, version string) (fixedIn, affectedRange string) {
	t.Helper()
	mux := advisoryMux(t,
		[]map[string]any{{"path": path, "vulns": []map[string]any{{"id": id, "fixed": indexFixed}}}},
		map[string]string{id: advisory},
	)
	srv := httptest.NewServer(mux)
	defer srv.Close()

	db := osv.New(clientRewritingTo(t, srv), &fakeVulnStore{})
	findings, err := db.LookupFindings(t.Context(), coordinatetest.MustNew(path, version))
	if err != nil {
		t.Fatalf("LookupFindings: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("findings = %d, want 1: %+v", len(findings), findings)
	}
	return findings[0].FixedIn, findings[0].AffectedRange
}

// TestLookupFindings_FixIsTheContainingBranchsFix is the ticket's own case. A
// version on the middle branch is told to move to the middle branch's fix, not
// to the release candidate at the end of the list — which is what the index's
// single collapsed "fixed" value says, and what was being reported.
func TestLookupFindings_FixIsTheContainingBranchsFix(t *testing.T) {
	fixed, affected := lookupOne(t, "stdlib", "1.27.0-rc.3", "GO-2026-9200", threeBranchAdvisory, "v1.26.5")
	if fixed != "v1.26.6" {
		t.Errorf("fixed_in = %q, want v1.26.6 — the fix for the branch this version is on", fixed)
	}
	// The whole range list is still rendered: selecting one branch's fix must not
	// hide that the advisory covers others.
	if want := "< v1.25.13, >= v1.26.0-0, < v1.26.6, >= v1.27.0-0, < v1.27.0-rc.3"; affected != want {
		t.Errorf("affected range = %q, want %q", affected, want)
	}
}

// TestLookupFindings_FixTracksTheVersionAcrossBranches walks every branch of one
// advisory. Asserting a single version would pass on a rule as wrong as "take
// the middle one"; the answer has to move with the input.
func TestLookupFindings_FixTracksTheVersionAcrossBranches(t *testing.T) {
	for _, tc := range []struct{ version, want string }{
		{"v1.24.2", "v1.25.13"},
		{"v1.25.12", "v1.25.13"},
		{"v1.26.0", "v1.26.6"},
		{"v1.26.5", "v1.26.6"},
		{"v1.27.0-rc.1", "v1.27.0-rc.3"},
	} {
		fixed, _ := lookupOne(t, "stdlib", "1.27.0-rc.3", "GO-2026-9200", threeBranchAdvisory, tc.version)
		if fixed != tc.want {
			t.Errorf("%s: fixed_in = %q, want %q", tc.version, fixed, tc.want)
		}
	}
}

// TestLookupFindings_BranchFixAppliesToModulePaths is the family half of the
// ticket's acceptance: the same selection, on a module that is not the standard
// library.
func TestLookupFindings_BranchFixAppliesToModulePaths(t *testing.T) {
	fixed, _ := lookupOne(t, "example.com/text", "0.40.0-rc.1", "GO-2026-9201", moduleThreeBranchAdvisory, "v0.39.0")
	if fixed != "v0.39.2" {
		t.Errorf("fixed_in = %q, want v0.39.2", fixed)
	}
}

// TestLookupFindings_UnfixedBranchReportsNoFix is the control that must NOT
// change. A version inside an interval with no fixed bound has no fix, and
// borrowing an earlier branch's would tell a reader to move to a version that
// does not carry the remediation.
func TestLookupFindings_UnfixedBranchReportsNoFix(t *testing.T) {
	const advisory = `{
		"id": "GO-2026-9202",
		"summary": "Unfixed on the current branch",
		"affected": [{
			"package": {"ecosystem": "Go", "name": "example.com/text"},
			"ranges": [{"type": "SEMVER", "events": [
				{"introduced": "0"}, {"fixed": "0.38.1"},
				{"introduced": "0.39.0"}
			]}]
		}]
	}`
	fixed, _ := lookupOne(t, "example.com/text", "", "GO-2026-9202", advisory, "v0.39.0")
	if fixed != "" {
		t.Errorf("fixed_in = %q, want empty — no fix exists on this branch", fixed)
	}
}
