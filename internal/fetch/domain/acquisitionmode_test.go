package domain_test

import (
	"strings"
	"testing"

	domain2 "github.com/eitanity/kanonarion/internal/fetch/domain"
	"github.com/eitanity/kanonarion/internal/fetch/fetchtest"
)

// strengthOrder is the documented ranking, strongest first. The tests below
// derive every expectation from this list rather than restating pair-by-pair
// verdicts, so a change to the order is a one-line change here and an immediate
// failure if the implementation disagrees.
var strengthOrder = [][]domain2.VerificationStatus{
	{domain2.Verified},
	{domain2.VerifiedBySumDBOnly},
	{domain2.VerifiedByGoSum},
	{domain2.LocalSource},
	// Equal-lowest: every Unverified* status, the empty status, and anything this
	// build does not recognise.
	{
		domain2.UnverifiedNoSumDB,
		domain2.UnverifiedMissingOrigin,
		domain2.UnverifiedHashMismatch,
		domain2.UnverifiedGoModInconsistent,
		domain2.UnverifiedNoVCS,
		domain2.UnverifiedVCSToolMissing,
		"",
		"SomeStatusFromANewerBuild",
	},
}

// rank returns the index of s in strengthOrder (lower is stronger).
func rank(t *testing.T, s domain2.VerificationStatus) int {
	t.Helper()
	for i, tier := range strengthOrder {
		for _, candidate := range tier {
			if candidate == s {
				return i
			}
		}
	}
	t.Fatalf("status %q is missing from strengthOrder: a new status must be ranked deliberately, "+
		"not fall through to a default", s)
	return 0
}

// allStatuses flattens strengthOrder.
func allStatuses() []domain2.VerificationStatus {
	var out []domain2.VerificationStatus
	for _, tier := range strengthOrder {
		out = append(out, tier...)
	}
	return out
}

// TestReplacementWeakensAnchor_EveryStatusPair is the guard for the overwrite
// rule: for every (existing, incoming) pair, a strictly weaker incoming record is
// a weakening (and so must not be written over the stronger one), while an
// equal-or-stronger one is not (so a genuine re-verification and a status upgrade
// still land). Before the guard, a --from-modcache run's VerifiedBySumDBOnly
// record replaced a network run's Verified record in place and took its portable
// blob handle with it.
func TestReplacementWeakensAnchor_EveryStatusPair(t *testing.T) {
	statuses := allStatuses()
	for _, existing := range statuses {
		for _, incoming := range statuses {
			existingRank, incomingRank := rank(t, existing), rank(t, incoming)
			// Lower rank index means stronger, so "incoming is weaker" is a HIGHER index.
			want := incomingRank > existingRank
			got := domain2.ReplacementWeakensAnchor(
				fetchtest.Record(t, fetchtest.Status(existing)),
				fetchtest.Record(t, fetchtest.Status(incoming)),
			)
			if got != want {
				t.Errorf("ReplacementWeakensAnchor(existing=%q, incoming=%q) = %v, want %v",
					existing, incoming, got, want)
			}
		}
	}
}

// TestReplacementWeakensAnchor_EqualIsNotAWeakening pins the case the fix must
// not break: re-measuring a module in the same mode overwrites as before, so a
// refreshed record, a re-signed record, and a corrected detail all still land.
func TestReplacementWeakensAnchor_EqualIsNotAWeakening(t *testing.T) {
	for _, s := range allStatuses() {
		r := fetchtest.Record(t, fetchtest.Status(s))
		if domain2.ReplacementWeakensAnchor(r, r) {
			t.Errorf("re-measuring %q as %q was treated as a weakening: same-mode refreshes would stop landing", s, s)
		}
	}
}

// TestUnknownStatusNeverOutranksAVerifiedAnchor is the fail-closed half of the
// ranking: a status this build does not recognise — a foreign record, a
// malformed one, or one written by a newer pipeline — must rank equal-lowest, so
// it can never displace a record anchored to the transparency log.
func TestUnknownStatusNeverOutranksAVerifiedAnchor(t *testing.T) {
	for _, unknown := range []domain2.VerificationStatus{"", "Verified ", "verified", "TotallyNewStatus"} {
		weakens := domain2.ReplacementWeakensAnchor(
			fetchtest.Record(t, fetchtest.Status(domain2.Verified)),
			fetchtest.Record(t, fetchtest.Status(unknown)),
		)
		if !weakens {
			t.Errorf("an unrecognised status %q was allowed to replace Verified", unknown)
		}
	}
}

// TestNewFactRecordCarriesAcquisitionMode guards the projection from the
// aggregate onto the record: dropped here, the persisted record cannot say which
// blob store resolves its ContentLocation and the log cannot name the mode that
// wrote it.
func TestNewFactRecordCarriesAcquisitionMode(t *testing.T) {
	for _, mode := range []domain2.AcquisitionMode{
		domain2.AcquisitionProxy, domain2.AcquisitionModcache, domain2.AcquisitionLocal, "",
	} {
		r := domain2.NewFactRecord(domain2.FetchedModule{AcquisitionMode: mode})
		if r.AcquisitionMode != string(mode) {
			t.Errorf("AcquisitionMode = %q, want %q", r.AcquisitionMode, mode)
		}
	}
}

// TestAcquisitionModeIsHashCovered proves the field is tamper-evident: rewriting
// a record's mode must break its content hash, or a modcache-written record could
// be relabelled as a proxy one and its mode-locked handle would be trusted by a
// run that cannot read it.
func TestAcquisitionModeIsHashCovered(t *testing.T) {
	h := domain2.CanonicalHasher{}
	r := sampleRecord()
	r.AcquisitionMode = string(domain2.AcquisitionModcache)
	sealed, err := h.SetContentHash(r)
	if err != nil {
		t.Fatalf("SetContentHash: %v", err)
	}
	if err := h.VerifyContentHash(sealed); err != nil {
		t.Fatalf("VerifyContentHash on an untouched record: %v", err)
	}

	tampered := sealed
	tampered.AcquisitionMode = string(domain2.AcquisitionProxy)
	if err := h.VerifyContentHash(tampered); err == nil {
		t.Error("rewriting AcquisitionMode left the content hash valid: the field is outside the hash")
	}
}

// TestAcquisitionModeAbsentKeepsPreFieldHash is the migration guard. The field is
// omitempty, so a record written before it existed — 6629 of them in the
// maintainer's store — must hash to exactly what it hashed to before, or the
// tamper check rejects the whole store on upgrade.
//
// The constant is the hash a pre-field build computed for sampleRecord(); it is
// deliberately a literal, not a value recomputed by this build's code.
func TestAcquisitionModeAbsentKeepsPreFieldHash(t *testing.T) {
	h := domain2.CanonicalHasher{}
	sealed, err := h.SetContentHash(sampleRecord())
	if err != nil {
		t.Fatalf("SetContentHash: %v", err)
	}
	const preFieldHash = "sha256:665d38c6fa170026fc7a338dff9aa0baba534f3b73001e1d2b3fc08b0859525f"
	if sealed.ContentHash != preFieldHash {
		t.Errorf("ContentHash = %q, want the pre-field hash %q: adding acquisition_mode changed the canonical "+
			"bytes of a record that does not carry one, invalidating every record already persisted",
			sealed.ContentHash, preFieldHash)
	}

	marshalled, err := h.Marshal(sealed)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	if strings.Contains(string(marshalled), "acquisition_mode") {
		t.Errorf("canonical JSON carries acquisition_mode when unset: %s", marshalled)
	}
}

// TestAcquisitionModeRoundTrips keeps the mode on the serialised record, so a
// record read back from an airgap bundle still says which store can produce its
// bytes.
func TestAcquisitionModeRoundTrips(t *testing.T) {
	h := domain2.CanonicalHasher{}
	r := sampleRecord()
	r.AcquisitionMode = string(domain2.AcquisitionModcache)
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
	if back.AcquisitionMode != string(domain2.AcquisitionModcache) {
		t.Errorf("AcquisitionMode = %q after round trip, want %q", back.AcquisitionMode, domain2.AcquisitionModcache)
	}
	if err := h.VerifyContentHash(back); err != nil {
		t.Errorf("VerifyContentHash after round trip: %v", err)
	}
}
