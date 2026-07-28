package govulncheck

import (
	"strings"
	"testing"
	"time"

	"github.com/eitanity/kanonarion/internal/vuln/domain"
)

// withdrawnStream is a govulncheck -json stream carrying one retracted advisory.
// govulncheck emits the whole OSV entry, retraction timestamp included, so the
// fact was always on the wire; the parser's OSV struct just had no field for it.
const withdrawnStream = `
{"osv": {"id": "GO-2026-4923", "summary": "WITHDRAWN: out-of-range-index in go.etcd.io/bbolt", "published": "2026-04-06T17:49:14Z", "withdrawn": "2026-04-08T13:33:56Z", "modified": "2026-04-08T15:08:18Z"}}
{"finding": {"osv": "GO-2026-4923", "trace": [{"module": "go.etcd.io/bbolt", "version": "v1.4.3", "function": "Check", "receiver": "Tx"}]}}
`

var wantWithdrawnAt = time.Date(2026, 4, 8, 13, 33, 56, 0, time.UTC)

// TestParseResults_CarriesTheWithdrawalTimestamp covers the isolated-module parse.
func TestParseResults_CarriesTheWithdrawalTimestamp(t *testing.T) {
	s := New("v1", nil)

	findings, err := s.parseResults(t.Context(), strings.NewReader(withdrawnStream), "go.etcd.io/bbolt")
	if err != nil {
		t.Fatalf("parseResults: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("got %d findings, want 1", len(findings))
	}
	if !findings[0].WithdrawnAt.Equal(wantWithdrawnAt) {
		t.Errorf("WithdrawnAt = %v, want %v", findings[0].WithdrawnAt, wantWithdrawnAt)
	}
	// The verdict, not just the field: a stream whose only finding names a retracted
	// advisory must not produce an Affected record. Reachability is not the lever
	// here — this finding was reached, and it still must not count.
	if got := domain.DetermineFindingsAxis(findings); got != domain.FindingsRecordWithdrawn {
		t.Errorf("findings axis = %q, want %q", got, domain.FindingsRecordWithdrawn)
	}
}

// TestParseResultsByModule_CarriesTheWithdrawalTimestamp covers the grouped
// (project- and target-rooted) parse. Both paths share applyOSV precisely so this
// cannot hold on one and not the other — the project-rooted path is the one the
// default walk treats as authoritative, so a gap there is the one that reaches an
// operator.
func TestParseResultsByModule_CarriesTheWithdrawalTimestamp(t *testing.T) {
	s := New("v1", nil)

	byModule, err := s.parseResultsByModule(t.Context(), strings.NewReader(withdrawnStream))
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
		if !findings[0].WithdrawnAt.Equal(wantWithdrawnAt) {
			t.Errorf("%s: WithdrawnAt = %v, want %v", coord, findings[0].WithdrawnAt, wantWithdrawnAt)
		}
	}
	if got := projectScanStatus(byModule); got != domain.StatusWithdrawn {
		t.Errorf("grouped scan status = %q, want %q: counting modules-with-findings reported Affected here",
			got, domain.StatusWithdrawn)
	}
}

// TestProjectScanStatus_OneLiveAdvisoryStillAffects guards the scan-level word
// against over-applying the retraction: a build carrying one live advisory beside
// a retracted one is affected, and the live one must not be masked.
func TestProjectScanStatus_OneLiveAdvisoryStillAffects(t *testing.T) {
	s := New("v1", nil)

	stream := withdrawnStream + `
{"osv": {"id": "GO-2026-5970", "summary": "live advisory in x/text"}}
{"finding": {"osv": "GO-2026-5970", "trace": [{"module": "golang.org/x/text", "version": "v0.37.0", "function": "Parse"}]}}
`
	byModule, err := s.parseResultsByModule(t.Context(), strings.NewReader(stream))
	if err != nil {
		t.Fatalf("parseResultsByModule: %v", err)
	}
	if got := projectScanStatus(byModule); got != domain.StatusAffected {
		t.Errorf("grouped scan status = %q, want %q", got, domain.StatusAffected)
	}
}
