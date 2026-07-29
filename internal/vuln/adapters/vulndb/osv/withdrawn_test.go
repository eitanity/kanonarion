package osv_test

import (
	"net/http/httptest"
	"testing"
	"time"

	coordinatetest "github.com/eitanity/kanonarion/internal/coordinate/coordinatetest"
	"github.com/eitanity/kanonarion/internal/vuln/adapters/vulndb/osv"
	"github.com/eitanity/kanonarion/internal/vuln/domain"
)

// bboltWithdrawnAdvisory is GO-2026-4923 as the live record serves it: still
// carried in the snapshot, still matching go.etcd.io/bbolt@v1.4.3, and retracted
// two days after publication with the retraction stated twice — once in the
// top-level timestamp and once as a "WITHDRAWN: " prefix on the summary.
//
// Only the timestamp is machine-readable. Reading the prefix instead would be
// reading prose, and the prefix is exactly what made the bug look fixed: the word
// WITHDRAWN already appeared in kanonarion's output, echoed from this summary,
// while the verdict beside it said Affected.
const bboltWithdrawnAdvisory = `{
	"id": "GO-2026-4923",
	"summary": "WITHDRAWN: out-of-range-index in go.etcd.io/bbolt",
	"aliases": ["CVE-2026-33817", "GHSA-6jwv-w5xf-7j27"],
	"published": "2026-04-06T17:49:14Z",
	"withdrawn": "2026-04-08T13:33:56Z",
	"modified": "2026-04-08T15:08:18Z",
	"affected": [{
		"package": {"ecosystem": "Go", "name": "go.etcd.io/bbolt"},
		"ranges": [{"type": "SEMVER", "events": [{"introduced": "1.4.0"}]}],
		"ecosystem_specific": {"imports": [{"path": "go.etcd.io/bbolt", "symbols": ["Tx.Check"]}]}
	}]
}`

// TestLookupFindings_ParsesTheWithdrawalTimestamp is the parser half of the fix.
// The retraction was on the wire all along; osvAdvisory simply did not have a
// field for it, so nothing downstream could know the advisory had been retracted.
func TestLookupFindings_ParsesTheWithdrawalTimestamp(t *testing.T) {
	mux := advisoryMux(t,
		[]map[string]any{{"path": "go.etcd.io/bbolt", "vulns": []map[string]any{{"id": "GO-2026-4923"}}}},
		map[string]string{"GO-2026-4923": bboltWithdrawnAdvisory},
	)
	srv := httptest.NewServer(mux)
	defer srv.Close()

	db := osv.New(clientRewritingTo(t, srv), &fakeVulnStore{})
	findings, err := db.LookupFindings(t.Context(), coordinatetest.MustNew("go.etcd.io/bbolt", "v1.4.3"))
	if err != nil {
		t.Fatalf("LookupFindings: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	f := findings[0]
	// The finding is retained, not dropped: the advisory did match this version, and
	// that it was retracted is a fact about it rather than a reason to forget it.
	if f.ID != "GO-2026-4923" {
		t.Fatalf("ID = %q", f.ID)
	}
	want := time.Date(2026, 4, 8, 13, 33, 56, 0, time.UTC)
	if !f.WithdrawnAt.Equal(want) {
		t.Errorf("WithdrawnAt = %v, want %v", f.WithdrawnAt, want)
	}
	if !f.IsWithdrawn() {
		t.Error("IsWithdrawn() = false for an advisory carrying a withdrawal timestamp")
	}
	// The acceptance criterion: this coordinate must not be counted affected on the
	// strength of a retracted advisory.
	if got := domain.DetermineFindingsAxis(findings); got != domain.FindingsRecordWithdrawn {
		t.Errorf("findings axis = %q, want %q — this is the false finding the ticket was filed for", got, domain.FindingsRecordWithdrawn)
	}
}

// TestLookupFindings_LiveAdvisoryCarriesNoWithdrawal guards the other direction:
// an advisory with no top-level withdrawn field must leave the timestamp zero, so
// a live finding is never read as retracted.
func TestLookupFindings_LiveAdvisoryCarriesNoWithdrawal(t *testing.T) {
	advisory := `{
		"id": "GO-2026-5970",
		"summary": "live advisory",
		"published": "2026-06-01T00:00:00Z",
		"modified": "2026-06-02T00:00:00Z",
		"affected": [{
			"package": {"ecosystem": "Go", "name": "golang.org/x/text"},
			"ranges": [{"type": "SEMVER", "events": [{"introduced": "0.1.0"}]}]
		}]
	}`
	mux := advisoryMux(t,
		[]map[string]any{{"path": "golang.org/x/text", "vulns": []map[string]any{{"id": "GO-2026-5970"}}}},
		map[string]string{"GO-2026-5970": advisory},
	)
	srv := httptest.NewServer(mux)
	defer srv.Close()

	db := osv.New(clientRewritingTo(t, srv), &fakeVulnStore{})
	findings, err := db.LookupFindings(t.Context(), coordinatetest.MustNew("golang.org/x/text", "v0.37.0"))
	if err != nil {
		t.Fatalf("LookupFindings: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	if findings[0].IsWithdrawn() {
		t.Errorf("IsWithdrawn() = true, want false: WithdrawnAt = %v", findings[0].WithdrawnAt)
	}
	if got := domain.DetermineFindingsAxis(findings); got != domain.FindingsRecordAffected {
		t.Errorf("findings axis = %q, want %q", got, domain.FindingsRecordAffected)
	}
}
