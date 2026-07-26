package domain_test

import (
	"strings"
	"testing"

	domain2 "github.com/eitanity/kanonarion/internal/fetch/domain"
	"github.com/eitanity/kanonarion/internal/fetch/fetchtest"
)

// TestRecordIsCacheable pins the cache-eligibility rule the fetch use case
// reads: a record whose checksum-database lookup failed describes an unreliable
// measurement, so serving it back would make one transient failure permanent.
// Every other record — including one whose sumdb answer was a settled policy
// answer — stays cacheable exactly as before.
func TestRecordIsCacheable(t *testing.T) {
	cases := []struct {
		name              string
		status            domain2.VerificationStatus
		sumDBLookupFailed bool
		want              bool
	}{
		{"verified", domain2.Verified, false, true},
		{"verified by sumdb only", domain2.VerifiedBySumDBOnly, false, true},
		{"policy: no sumdb entry", domain2.UnverifiedNoSumDB, false, true},
		{"policy: GOSUMDB off, go.sum covered it", domain2.VerifiedByGoSum, false, true},
		{"hash mismatch is a real finding", domain2.UnverifiedHashMismatch, false, true},
		{"failed lookup, downgraded", domain2.UnverifiedNoSumDB, true, false},
		{"failed lookup, go.sum masked it", domain2.VerifiedByGoSum, true, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := fetchtest.Record(t, fetchtest.Status(tc.status), fetchtest.SumDBLookupFailed(tc.sumDBLookupFailed))
			if got := domain2.RecordIsCacheable(r); got != tc.want {
				t.Errorf("RecordIsCacheable() = %v, want %v", got, tc.want)
			}
		})
	}
}

// TestNewFactRecordCarriesSumDBLookupFailed guards the projection: if the flag is
// dropped between the aggregate and the record, the downgrade is persisted as
// cacheable and the bug is back with every test above still passing.
func TestNewFactRecordCarriesSumDBLookupFailed(t *testing.T) {
	for _, failed := range []bool{true, false} {
		m := domain2.FetchedModule{
			VerificationStatus: domain2.UnverifiedNoSumDB,
			SumDBLookupFailed:  failed,
		}
		r := domain2.NewFactRecord(m)
		if r.SumDBLookupFailed != failed {
			t.Errorf("SumDBLookupFailed = %v, want %v", r.SumDBLookupFailed, failed)
		}
		if domain2.RecordIsCacheable(r) == failed {
			t.Errorf("IsCacheable() = %v for SumDBLookupFailed=%v", domain2.RecordIsCacheable(r), failed)
		}
	}
}

// TestSumDBLookupFailedIsHashCovered proves the flag is tamper-evident: flipping
// it on a persisted record must break the content hash, or the read gate would
// silently accept a promoted record.
func TestSumDBLookupFailedIsHashCovered(t *testing.T) {
	h := domain2.CanonicalHasher{}
	r := sampleRecord()
	r.SumDBLookupFailed = true
	sealed, err := h.SetContentHash(r)
	if err != nil {
		t.Fatalf("SetContentHash: %v", err)
	}
	if err := h.VerifyContentHash(sealed); err != nil {
		t.Fatalf("VerifyContentHash on an untouched record: %v", err)
	}

	tampered := sealed
	tampered.SumDBLookupFailed = false
	if err := h.VerifyContentHash(tampered); err == nil {
		t.Error("clearing SumDBLookupFailed left the content hash valid: the flag is outside the hash")
	}
}

// TestSumDBLookupFailedFalseKeepsLegacyHash is the migration guard. The field is
// omitempty, so a record whose lookup did not fail must hash to exactly what it
// hashed to before the field existed — otherwise every record already in the
// store fails its tamper check and the whole cache is invalidated by a bug fix.
func TestSumDBLookupFailedFalseKeepsLegacyHash(t *testing.T) {
	h := domain2.CanonicalHasher{}

	sealed, err := h.SetContentHash(sampleRecord())
	if err != nil {
		t.Fatalf("SetContentHash: %v", err)
	}
	// This is the hash a pre-field kanonarion computed for sampleRecord(): the
	// canonical bytes omit sumdb_lookup_failed entirely when it is false.
	const legacyHash = "sha256:665d38c6fa170026fc7a338dff9aa0baba534f3b73001e1d2b3fc08b0859525f"
	if sealed.ContentHash != legacyHash {
		t.Errorf("ContentHash = %q, want the pre-field hash %q: adding the field changed the canonical bytes "+
			"of a record that never failed a lookup, invalidating every record already persisted",
			sealed.ContentHash, legacyHash)
	}

	marshalled, err := h.Marshal(sealed)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	if got := string(marshalled); strings.Contains(got, "sumdb_lookup_failed") {
		t.Errorf("canonical JSON carries sumdb_lookup_failed when false: %s", got)
	}
}

// TestSumDBLookupFailedRoundTrips keeps the flag on the serialised record so a
// re-read from the audit log reproduces the cache decision.
func TestSumDBLookupFailedRoundTrips(t *testing.T) {
	h := domain2.CanonicalHasher{}
	r := sampleRecord()
	r.SumDBLookupFailed = true
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
	if !back.SumDBLookupFailed {
		t.Error("SumDBLookupFailed lost in the canonical round trip")
	}
	if domain2.RecordIsCacheable(back) {
		t.Error("round-tripped record became cacheable again")
	}
	if err := h.VerifyContentHash(back); err != nil {
		t.Errorf("VerifyContentHash after round trip: %v", err)
	}
}
