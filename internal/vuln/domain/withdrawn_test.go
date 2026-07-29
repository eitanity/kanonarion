package domain_test

import (
	"testing"
	"time"

	"github.com/eitanity/kanonarion/internal/vuln/domain"
)

// withdrawnAt is the retraction timestamp of GO-2026-4923, the advisory this
// behaviour was built for: published 2026-04-06, withdrawn 2026-04-08 after the
// reporter and the maintainer agreed it was a false positive.
var withdrawnAt = time.Date(2026, 4, 8, 13, 33, 56, 0, time.UTC)

func liveFinding(id string) domain.VulnerabilityFinding {
	return domain.VulnerabilityFinding{ID: id, Summary: "out-of-range-index"}
}

func withdrawnFinding(id string) domain.VulnerabilityFinding {
	return domain.VulnerabilityFinding{ID: id, Summary: "WITHDRAWN: out-of-range-index", WithdrawnAt: withdrawnAt}
}

// TestDetermineFindingsAxis pins the three-way rule the findings axis now
// answers. The middle case is the one the whole change turns on: a matched
// advisory that has been retracted is not a finding against the module, and it is
// not an absence of one either.
func TestDetermineFindingsAxis(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name     string
		findings []domain.VulnerabilityFinding
		want     domain.RecordFindingsStatus
	}{
		{"no match is clean", nil, domain.FindingsRecordClean},
		{"a live advisory is a finding", []domain.VulnerabilityFinding{liveFinding("GO-1")}, domain.FindingsRecordAffected},
		{"the only advisory withdrawn is not a finding and not clean",
			[]domain.VulnerabilityFinding{withdrawnFinding("GO-2026-4923")}, domain.FindingsRecordWithdrawn},
		{"every advisory withdrawn",
			[]domain.VulnerabilityFinding{withdrawnFinding("GO-1"), withdrawnFinding("GO-2")}, domain.FindingsRecordWithdrawn},
		// One live advisory decides the axis. Reporting Withdrawn because most of the
		// set was retracted would retire a finding that still stands.
		{"one live advisory beside a withdrawn one is still affected",
			[]domain.VulnerabilityFinding{withdrawnFinding("GO-1"), liveFinding("GO-2")}, domain.FindingsRecordAffected},
		// An enrichment fetch that failed leaves the finding bare, with no retraction
		// timestamp. That must read as live: a lookup that could not read the advisory
		// has not established a withdrawal.
		{"a finding with no advisory read is live, not withdrawn",
			[]domain.VulnerabilityFinding{{ID: "GO-1"}}, domain.FindingsRecordAffected},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := domain.DetermineFindingsAxis(tc.findings); got != tc.want {
				t.Fatalf("DetermineFindingsAxis() = %q, want %q", got, tc.want)
			}
		})
	}
}

// TestSeal_WithdrawnAdvisoryDoesNotSealAsAffected is the ticket's acceptance
// criterion at the seal: a record whose only matched advisory is retracted must
// not carry an Affected verdict on any of its three status fields, and must not
// carry Clean either — the retraction has to be named.
func TestSeal_WithdrawnAdvisoryDoesNotSealAsAffected(t *testing.T) {
	t.Parallel()

	// The writer states the coverage it established and leaves the findings axis and
	// the summary to the seal, which is what the coordinate-match producer does.
	rec := sampleRecord(t)
	rec.OverallStatus = ""
	rec.CoverageStatus = domain.CoverageAnalysed
	rec.FindingsStatus = ""
	rec.Findings = []domain.VulnerabilityFinding{withdrawnFinding("GO-2026-4923")}

	sealed, err := domain.VulnerabilityRecordHasher{}.SetContentHash(rec)
	if err != nil {
		t.Fatalf("SetContentHash: %v", err)
	}
	if sealed.FindingsStatus != domain.FindingsRecordWithdrawn {
		t.Errorf("findings axis = %q, want %q", sealed.FindingsStatus, domain.FindingsRecordWithdrawn)
	}
	if sealed.OverallStatus != domain.StatusWithdrawn {
		t.Errorf("summary = %q, want %q — Clean would make the retraction indistinguishable from an advisory that never applied",
			sealed.OverallStatus, domain.StatusWithdrawn)
	}
	if sealed.CoverageStatus != domain.CoverageAnalysed {
		t.Errorf("coverage axis = %q, want %q: a retraction can only be known for a module whose advisory set was read",
			sealed.CoverageStatus, domain.CoverageAnalysed)
	}
	// The retained finding is the historical fact the ticket requires. Dropping it
	// would leave the record saying Withdrawn with nothing to say what was.
	if len(sealed.Findings) != 1 || sealed.Findings[0].ID != "GO-2026-4923" {
		t.Errorf("findings = %v, want the retracted advisory retained as a historical fact", sealed.Findings)
	}
}

// TestSeal_WithdrawnFieldIsHashTransparentForLiveFindings is what lets the fix
// ship without a migration over the stored blobs: WithdrawnAt carries omitzero,
// so a record whose findings are all live encodes and hashes exactly as it did
// before the field existed, and every stored record still verifies.
func TestSeal_WithdrawnFieldIsHashTransparentForLiveFindings(t *testing.T) {
	t.Parallel()

	rec := sampleRecord(t)
	rec.Findings = []domain.VulnerabilityFinding{liveFinding("GO-1")}
	sealed, err := domain.VulnerabilityRecordHasher{}.SetContentHash(rec)
	if err != nil {
		t.Fatalf("SetContentHash: %v", err)
	}
	encoded, err := domain.VulnerabilityRecordHasher{}.Marshal(sealed)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	if got := string(encoded); contains(got, "withdrawn_at") {
		t.Errorf("encoding names withdrawn_at for a live finding, so it is not hash-transparent: %s", got)
	}
}

// TestRecordAxes_HealsAStatedAffectedOverAWithdrawnSet covers the read leg for a
// record written by a generation that could not express the retraction: the axis
// it stored is preferred, so history reads as what that generation concluded, and
// only a record that states no axis is healed from its findings.
func TestRecordAxes_HealsAStatedAffectedOverAWithdrawnSet(t *testing.T) {
	t.Parallel()

	stated := domain.VulnerabilityRecord{
		OverallStatus:  domain.StatusAffected,
		CoverageStatus: domain.CoverageAnalysed,
		FindingsStatus: domain.FindingsRecordAffected,
		Findings:       []domain.VulnerabilityFinding{withdrawnFinding("GO-2026-4923")},
	}
	if _, findings := domain.RecordAxes(stated); findings != domain.FindingsRecordAffected {
		t.Errorf("findings axis = %q, want the stored %q: a stated axis is what that generation concluded",
			findings, domain.FindingsRecordAffected)
	}

	unstated := domain.VulnerabilityRecord{
		OverallStatus: domain.StatusAffected,
		Findings:      []domain.VulnerabilityFinding{withdrawnFinding("GO-2026-4923")},
	}
	if _, findings := domain.RecordAxes(unstated); findings != domain.FindingsRecordWithdrawn {
		t.Errorf("findings axis = %q, want %q: with no axis stored the findings are the evidence, not the word",
			findings, domain.FindingsRecordWithdrawn)
	}
}

func contains(haystack, needle string) bool {
	for i := 0; i+len(needle) <= len(haystack); i++ {
		if haystack[i:i+len(needle)] == needle {
			return true
		}
	}
	return false
}
