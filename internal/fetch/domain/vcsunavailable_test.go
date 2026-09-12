package domain_test

import (
	"strings"
	"testing"
	"time"

	domain2 "github.com/eitanity/kanonarion/internal/fetch/domain"
	"github.com/eitanity/kanonarion/internal/fetch/fetchtest"
)

// TestRecordIsCacheable_VCSLeg pins the other half of the cache-eligibility
// rule: a record whose git leg could not run describes the host that measured,
// not the module, so it must not be served back. A check that ran and disagreed
// and a module with no VCS anchor at all are real answers about the module and
// stay cacheable exactly as before.
func TestRecordIsCacheable_VCSLeg(t *testing.T) {
	cases := []struct {
		name   string
		status domain2.VerificationStatus
		leg    domain2.LegProvenance
		want   bool
	}{
		{"cross-verified", domain2.Verified, domain2.LegRechecked, true},
		{"check ran and disagreed, or found no anchor", domain2.VerifiedBySumDBOnly, domain2.LegRechecked, true},
		{"leg carried forward", domain2.Verified, domain2.LegInherited, true},
		{"--skip-vcs-verify: no leg", domain2.VerifiedBySumDBOnly, domain2.LegAbsent, true},
		{"host had no git", domain2.VerifiedBySumDBOnly, domain2.LegUnavailable, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			source := ""
			if tc.leg == domain2.LegInherited {
				source = "sha256:" + strings.Repeat("a", 64)
			}
			r := fetchtest.Record(t, fetchtest.Status(tc.status), fetchtest.VCSCheck(tc.leg, source))
			if got := domain2.RecordIsCacheable(r); got != tc.want {
				t.Errorf("RecordIsCacheable() = %v, want %v", got, tc.want)
			}
		})
	}
}

// TestNewFactRecordCarriesUnavailableVCSLeg guards the projection from the
// aggregate onto the record. Drop it there and the host fault is persisted as a
// cacheable fact about the module with every other test still passing.
func TestNewFactRecordCarriesUnavailableVCSLeg(t *testing.T) {
	r := domain2.NewFactRecord(domain2.FetchedModule{
		VerificationStatus: domain2.VerifiedBySumDBOnly,
		SumDBCheck:         domain2.LegRechecked,
		VCSCheck:           domain2.LegUnavailable,
	})
	if r.VCSCheck != string(domain2.LegUnavailable) {
		t.Fatalf("VCSCheck = %q, want %q", r.VCSCheck, domain2.LegUnavailable)
	}
	if domain2.RecordIsCacheable(r) {
		t.Error("a record whose git leg could not run is cacheable: the host fault is permanent again")
	}
}

// TestUnavailableVCSLegIsHashCovered proves the value is tamper-evident on the
// same terms as SumDBLookupFailed: rewriting it to "rechecked" must break the
// content hash, or the record could be silently promoted back to a cache hit.
func TestUnavailableVCSLegIsHashCovered(t *testing.T) {
	h := domain2.CanonicalHasher{}
	r := sampleRecord()
	r.VCSCheck = string(domain2.LegUnavailable)
	sealed, err := h.SetContentHash(r)
	if err != nil {
		t.Fatalf("SetContentHash: %v", err)
	}
	if err := h.VerifyContentHash(sealed); err != nil {
		t.Fatalf("VerifyContentHash on an untouched record: %v", err)
	}

	tampered := sealed
	tampered.VCSCheck = string(domain2.LegRechecked)
	if err := h.VerifyContentHash(tampered); err == nil {
		t.Error("rewriting the VCS leg left the content hash valid: the leg is outside the hash")
	}
}

// TestUnsetVCSLegKeepsLegacyHash is the migration guard. vcs_check is omitempty
// and the new value is only ever written by a run that attempted the check, so
// every record already in the store must hash to exactly what it hashed to
// before — otherwise a bug fix invalidates the whole ledger.
func TestUnsetVCSLegKeepsLegacyHash(t *testing.T) {
	h := domain2.CanonicalHasher{}
	sealed, err := h.SetContentHash(sampleRecord())
	if err != nil {
		t.Fatalf("SetContentHash: %v", err)
	}
	const legacyHash = "sha256:665d38c6fa170026fc7a338dff9aa0baba534f3b73001e1d2b3fc08b0859525f"
	if sealed.ContentHash != legacyHash {
		t.Errorf("ContentHash = %q, want the pre-field hash %q: the canonical bytes of a record that "+
			"carries no VCS leg changed, invalidating every record already persisted",
			sealed.ContentHash, legacyHash)
	}
	marshalled, err := h.Marshal(sealed)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	if strings.Contains(string(marshalled), "vcs_check") {
		t.Errorf("canonical JSON carries vcs_check when unset: %s", marshalled)
	}
}

// TestUnavailableVCSLegRoundTrips keeps the value on the serialised record, so a
// re-read reproduces the cache decision rather than re-serving the downgrade.
func TestUnavailableVCSLegRoundTrips(t *testing.T) {
	h := domain2.CanonicalHasher{}
	r := sampleRecord()
	r.VCSCheck = string(domain2.LegUnavailable)
	sealed, err := h.SetContentHash(r)
	if err != nil {
		t.Fatalf("SetContentHash: %v", err)
	}
	data, err := h.Marshal(sealed)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	back, err := h.Unmarshal(data)
	if err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if back.VCSCheck != string(domain2.LegUnavailable) {
		t.Errorf("VCSCheck = %q after the canonical round trip, want %q", back.VCSCheck, domain2.LegUnavailable)
	}
	if domain2.RecordIsCacheable(back) {
		t.Error("round-tripped record became cacheable again")
	}
	if err := h.VerifyContentHash(back); err != nil {
		t.Errorf("VerifyContentHash after round trip: %v", err)
	}
}

// TestVCSEvidenceOf_Unavailable keeps the coverage report from counting a host
// fault as evidence either way: it is neither a check this run performed nor a
// measured absence of anchor for the module.
func TestVCSEvidenceOf_Unavailable(t *testing.T) {
	legs := domain2.RecordLegs(fetchtest.Record(t,
		fetchtest.SumDBCheck(domain2.LegRechecked, ""),
		fetchtest.VCSCheck(domain2.LegUnavailable, "")))
	if got := domain2.VCSEvidenceOf(legs); got != domain2.VCSUnavailable {
		t.Errorf("VCSEvidenceOf = %v, want VCSUnavailable", got)
	}
	c := domain2.VerificationCoverageOf([]domain2.CoverageObservation{
		{Bucket: domain2.BucketChecksumDBOnly, Legs: legs, Recorded: true},
	})
	if c.VCSUnavailable != 1 || c.VCSRechecked != 0 || c.VCSNever != 0 {
		t.Errorf("coverage = %+v, want the module counted only as VCS-unavailable", c)
	}
}

// TestComposeKeepsEstablishedLegOverUnavailable guards the composed view: a
// later run on a host without git establishes nothing, so it must not displace
// the cross-verification evidence the ledger already holds.
func TestComposeKeepsEstablishedLegOverUnavailable(t *testing.T) {
	earlier := fetchtest.Record(t,
		fetchtest.Status(domain2.Verified),
		fetchtest.SumDBCheck(domain2.LegRechecked, ""),
		fetchtest.VCSCheck(domain2.LegRechecked, ""),
		fetchtest.FetchedAt(sampleRecord().FetchedAt))
	later := fetchtest.Record(t,
		fetchtest.Status(domain2.VerifiedBySumDBOnly),
		fetchtest.SumDBCheck(domain2.LegRechecked, ""),
		fetchtest.VCSCheck(domain2.LegUnavailable, ""),
		fetchtest.FetchedAt(sampleRecord().FetchedAt.Add(24*time.Hour)))

	c, err := domain2.Compose([]domain2.FactRecord{earlier, later})
	if err != nil {
		t.Fatalf("Compose: %v", err)
	}
	if got := domain2.VCSEvidenceOf(c.Legs); got != domain2.VCSRechecked {
		t.Errorf("composed VCS evidence = %v, want VCSRechecked: the run without git erased the evidence", got)
	}
	if c.VerificationStatus != string(domain2.Verified) {
		t.Errorf("served status = %q, want Verified: the ineligible record was served", c.VerificationStatus)
	}
}
