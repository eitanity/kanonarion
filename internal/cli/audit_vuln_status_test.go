package cli

import (
	"errors"
	"strings"
	"testing"

	vulndomain "github.com/eitanity/kanonarion/internal/vuln/domain"
)

// TestVulnAuditStatus_ReadErrorIsNotReportedAsNotScanned is the regression for
// an audit row that told the operator a module was never scanned when the store
// could not be read. Absence and unreadability are different facts: "(not
// scanned)" is an accurate report of the first and a false one of the second,
// and it is false in the direction that closes the question rather than raising
// it. A read failure must name itself.
func TestVulnAuditStatus_ReadErrorIsNotReportedAsNotScanned(t *testing.T) {
	status, reason, findings := vulnAuditStatus(vulndomain.VulnerabilityRecord{}, false, errors.New("database is locked"))

	if status == "(not scanned)" {
		t.Errorf("a store read error must not render as %q: the module may well have been scanned", status)
	}
	if status == "" {
		t.Errorf("a store read error must render as something, got an empty status")
	}
	if !strings.Contains(reason, "database is locked") {
		t.Errorf("reason = %q, want it to carry the underlying read error", reason)
	}
	if findings != 0 {
		t.Errorf("findings = %d, want 0 when no record could be read", findings)
	}
}

// TestVulnAuditStatus_ReadErrorWithFoundRecordIsStillAnError covers the shape
// that produced a blank column: an error alongside a found record left the
// status unset entirely, so the row rendered empty with nothing said about why.
func TestVulnAuditStatus_ReadErrorWithFoundRecordIsStillAnError(t *testing.T) {
	rec := vulndomain.VulnerabilityRecord{OverallStatus: vulndomain.StatusAffected}
	status, _, _ := vulnAuditStatus(rec, true, errors.New("decode failed"))

	if status == "" {
		t.Errorf("an errored lookup must not leave the status blank")
	}
	if status == string(vulndomain.StatusAffected) {
		t.Errorf("a record returned alongside an error must not be trusted as %q", status)
	}
}

// TestVulnAuditStatus_AbsentAndPresent covers the two honest outcomes either
// side of the error case.
func TestVulnAuditStatus_AbsentAndPresent(t *testing.T) {
	status, _, _ := vulnAuditStatus(vulndomain.VulnerabilityRecord{}, false, nil)
	if status != "(not scanned)" {
		t.Errorf("a clean lookup that found nothing = %q, want %q", status, "(not scanned)")
	}

	rec := vulndomain.VulnerabilityRecord{
		OverallStatus:     vulndomain.StatusUnscannable,
		UnscannableReason: "no buildable files",
		Findings:          []vulndomain.VulnerabilityFinding{{ID: "GO-2026-0001"}},
	}
	status, reason, findings := vulnAuditStatus(rec, true, nil)
	if status != string(vulndomain.StatusUnscannable) {
		t.Errorf("status = %q, want %q", status, vulndomain.StatusUnscannable)
	}
	if reason != "no buildable files" {
		t.Errorf("reason = %q, want the unscannable reason", reason)
	}
	if findings != 1 {
		t.Errorf("findings = %d, want 1", findings)
	}

	failed := vulndomain.VulnerabilityRecord{
		OverallStatus: vulndomain.StatusScanFailed,
		ErrorDetail:   "govulncheck: exit status 1",
	}
	if _, reason, _ := vulnAuditStatus(failed, true, nil); reason != "govulncheck: exit status 1" {
		t.Errorf("reason = %q, want the scan-failed error detail", reason)
	}
}
