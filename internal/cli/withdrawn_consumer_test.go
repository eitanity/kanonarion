package cli

import (
	"strings"
	"testing"

	vulndomain "github.com/eitanity/kanonarion/internal/vuln/domain"
)

// TestBuildVulnerabilityContext_CarriesTheRetractionOntoTheFinding covers the
// `context` projection. The module's status word already read Withdrawn, but the
// per-finding shape carried id/aliases/summary/fixed_in/score/reachable and
// nothing else — so the entry an agent reads was identical to a live finding's,
// with the retraction legible only as prose in the upstream summary. That prose is
// exactly what must stop being the signal.
func TestBuildVulnerabilityContext_CarriesTheRetractionOntoTheFinding(t *testing.T) {
	rec := withdrawnBboltRecord()
	out := vulnRecordToContext(&rec, "", "")

	if out.Status != string(vulndomain.StatusWithdrawn) {
		t.Errorf("status = %q, want %q", out.Status, vulndomain.StatusWithdrawn)
	}
	if len(out.Findings) != 1 {
		t.Fatalf("findings = %d, want the retracted advisory retained as the historical fact", len(out.Findings))
	}
	if out.Findings[0].WithdrawnAt != "2026-04-08T13:33:56Z" {
		t.Errorf("withdrawn_at = %q, want the retraction date on the finding itself", out.Findings[0].WithdrawnAt)
	}
}

// TestContextFindingCount_SeparatesRetractedFromLive covers the text render. A
// single "N finding(s)" tally printed "1 finding(s)" beside the Withdrawn status
// word, so the row asserted a finding and denied it in the same line. A mixture
// states both numbers: the live count is what the reader acts on, the retracted
// count is what explains the rest of the entry.
func TestContextFindingCount_SeparatesRetractedFromLive(t *testing.T) {
	live := contextCVE{ID: "GO-2026-5970"}
	retracted := contextCVE{ID: "GO-2026-4923", WithdrawnAt: "2026-04-08T13:33:56Z"}

	if got := contextFindingCount(nil); got != "" {
		t.Errorf("no findings rendered %q, want no tally at all", got)
	}
	if got := contextFindingCount([]contextCVE{live}); !strings.Contains(got, "1 finding(s)") {
		t.Errorf("live-only tally = %q, want it to report one finding", got)
	}
	got := contextFindingCount([]contextCVE{retracted})
	if strings.Contains(got, "finding") {
		t.Errorf("retracted-only tally = %q, want it not to count a retraction as a finding", got)
	}
	if !strings.Contains(got, "retracted") {
		t.Errorf("retracted-only tally = %q, want the retraction named rather than omitted", got)
	}
	mixed := contextFindingCount([]contextCVE{live, retracted})
	if !strings.Contains(mixed, "1 finding(s)") || !strings.Contains(mixed, "1 retracted") {
		t.Errorf("mixed tally = %q, want both counts stated", mixed)
	}
}

// TestVulnAuditStatus_CountsRetractionsWithoutRedefiningTheFindingCount covers the
// `audit` row, which printed "Withdrawn (1 findings)" — a finding asserted and
// denied in the same line.
//
// It also pins the compatibility rule that fix had to respect. vuln_findings keeps
// counting every advisory on the record, retractions included; narrowing it to live
// advisories would have changed the number behind an existing field name, with the
// same type and no signal, so a consumer parsing audit JSON would silently read a
// different fact. The retraction is carried by a new field instead, and live is the
// difference.
func TestVulnAuditStatus_CountsRetractionsWithoutRedefiningTheFindingCount(t *testing.T) {
	status, _, findings, withdrawn := vulnAuditStatus(withdrawnBboltRecord(), true, nil)

	if status != string(vulndomain.StatusWithdrawn) {
		t.Errorf("status = %q, want %q", status, vulndomain.StatusWithdrawn)
	}
	if findings != 1 {
		t.Errorf("findings = %d, want 1: the total keeps its established meaning", findings)
	}
	if withdrawn != 1 {
		t.Errorf("withdrawn = %d, want 1: the retraction is reported, not subtracted into silence", withdrawn)
	}
	if live := findings - withdrawn; live != 0 {
		t.Errorf("live advisories = %d, want 0: nothing here stands against the module", live)
	}
}

// TestVulnAuditStatus_MixedSetKeepsBothCounts covers the case the axis itself
// resolves to Affected: one live advisory decides the verdict however many
// retracted ones sit beside it, and the row must not lose either number.
func TestVulnAuditStatus_MixedSetKeepsBothCounts(t *testing.T) {
	rec := withdrawnBboltRecord()
	rec.OverallStatus = vulndomain.StatusAffected
	rec.FindingsStatus = vulndomain.FindingsRecordAffected
	rec.Findings = append(rec.Findings, vulndomain.VulnerabilityFinding{
		ID:      "GO-2026-9999",
		Summary: "a live advisory beside the retracted one",
	})

	_, _, findings, withdrawn := vulnAuditStatus(rec, true, nil)

	if findings != 2 {
		t.Errorf("findings = %d, want both advisories in the total", findings)
	}
	if withdrawn != 1 {
		t.Errorf("withdrawn = %d, want the retracted one counted apart", withdrawn)
	}
	if live := findings - withdrawn; live != 1 {
		t.Errorf("live advisories = %d, want the one that stands", live)
	}
}
