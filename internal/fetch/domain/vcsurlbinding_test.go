package domain_test

import (
	"strings"
	"testing"

	domain2 "github.com/eitanity/kanonarion/internal/fetch/domain"
)

// TestNewFactRecordCarriesVCSURLBinding guards the projection from the aggregate
// onto the record. Dropped here, the measurement would know which clone URL its
// git leg reproduced from and the persisted record would not, which is the gap
// the field exists to close.
func TestNewFactRecordCarriesVCSURLBinding(t *testing.T) {
	t.Parallel()

	for _, binding := range []domain2.VCSURLBinding{
		domain2.VCSURLBindingCoordinateDerived,
		domain2.VCSURLBindingProxyNamed,
		domain2.VCSURLBindingAbsent,
	} {
		r := domain2.NewFactRecord(domain2.FetchedModule{VCSURLBinding: binding})
		if r.VCSURLBinding != string(binding) {
			t.Errorf("VCSURLBinding = %q, want %q", r.VCSURLBinding, binding)
		}
	}
}

// TestVCSURLBindingIsHashCovered proves the attribution is tamper-evident.
// Without this, the weaker binding could be rewritten as the stronger one on a
// record that still verified — which would be worse than not recording it at
// all, because a reader would believe the rewritten value.
func TestVCSURLBindingIsHashCovered(t *testing.T) {
	t.Parallel()

	h := domain2.CanonicalHasher{}
	r := sampleRecord()
	r.VCSURLBinding = string(domain2.VCSURLBindingProxyNamed)
	sealed, err := h.SetContentHash(r)
	if err != nil {
		t.Fatalf("SetContentHash: %v", err)
	}
	if err := h.VerifyContentHash(sealed); err != nil {
		t.Fatalf("VerifyContentHash on an untouched record: %v", err)
	}

	promoted := sealed
	promoted.VCSURLBinding = string(domain2.VCSURLBindingCoordinateDerived)
	if err := h.VerifyContentHash(promoted); err == nil {
		t.Error("rewriting a proxy-named binding as coordinate-derived left the content hash valid: " +
			"the weaker assurance could be relabelled as the stronger one undetected")
	}
}

// TestVCSURLBindingAbsentKeepsPreFieldHash is the migration guard. The field is
// omitempty, so a record written before it existed must hash to exactly what it
// hashed to before, or every record already in a store fails its integrity check
// on upgrade and the read path — which fails closed — reports the whole store as
// unreadable.
//
// The constant is the hash a pre-field build computed for sampleRecord(). It is
// deliberately a literal rather than a value this build recomputes.
func TestVCSURLBindingAbsentKeepsPreFieldHash(t *testing.T) {
	t.Parallel()

	h := domain2.CanonicalHasher{}
	sealed, err := h.SetContentHash(sampleRecord())
	if err != nil {
		t.Fatalf("SetContentHash: %v", err)
	}
	const preFieldHash = "sha256:665d38c6fa170026fc7a338dff9aa0baba534f3b73001e1d2b3fc08b0859525f"
	if sealed.ContentHash != preFieldHash {
		t.Errorf("ContentHash = %q, want the pre-field hash %q: adding vcs_url_binding changed the canonical "+
			"bytes of a record that does not carry one, invalidating every record already persisted",
			sealed.ContentHash, preFieldHash)
	}

	marshalled, err := h.Marshal(sealed)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	if strings.Contains(string(marshalled), "vcs_url_binding") {
		t.Errorf("canonical JSON carries vcs_url_binding when unset: %s", marshalled)
	}
}

// TestVCSURLBindingRoundTrips keeps the attribution on the serialised record, so
// a record read back from an airgap bundle still says which binding produced its
// VCS leg.
func TestVCSURLBindingRoundTrips(t *testing.T) {
	t.Parallel()

	h := domain2.CanonicalHasher{}
	r := sampleRecord()
	r.VCSURLBinding = string(domain2.VCSURLBindingProxyNamed)
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
	if back.VCSURLBinding != string(domain2.VCSURLBindingProxyNamed) {
		t.Errorf("VCSURLBinding = %q after round trip, want %q", back.VCSURLBinding, domain2.VCSURLBindingProxyNamed)
	}
	if err := h.VerifyContentHash(back); err != nil {
		t.Errorf("VerifyContentHash after round trip: %v", err)
	}
}

// TestBucketForFetchRecord_SplitsOnlyTheStrongestClass pins the mapping. The
// binding refines cross-verification and nothing else: every other status either
// ran no VCS leg or established nothing with it, so there is no clone URL to
// attribute and qualifying those classes would invent a distinction.
func TestBucketForFetchRecord_SplitsOnlyTheStrongestClass(t *testing.T) {
	t.Parallel()

	everyBinding := []domain2.VCSURLBinding{
		domain2.VCSURLBindingAbsent,
		domain2.VCSURLBindingCoordinateDerived,
		domain2.VCSURLBindingProxyNamed,
		"a-binding-from-a-newer-build",
	}

	for _, status := range []domain2.VerificationStatus{
		domain2.VerifiedBySumDBOnly, domain2.VerifiedByGoSum, domain2.LocalSource,
		domain2.UnverifiedNoSumDB, domain2.UnverifiedMissingOrigin, domain2.UnverifiedHashMismatch,
		domain2.UnverifiedGoModInconsistent, domain2.UnverifiedNoVCS, domain2.UnverifiedVCSToolMissing,
		"SomeStatusFromANewerBuild",
	} {
		want := domain2.BucketForVerification(status)
		for _, binding := range everyBinding {
			if got := domain2.BucketForFetchRecord(status, binding); got != want {
				t.Errorf("BucketForFetchRecord(%q, %q) = %v, want %v (the binding must not move a non-cross-verified status)",
					status, binding, got, want)
			}
		}
	}

	for binding, want := range map[domain2.VCSURLBinding]domain2.VerificationBucket{
		domain2.VCSURLBindingCoordinateDerived: domain2.BucketCrossVerifiedModulePathURL,
		domain2.VCSURLBindingProxyNamed:        domain2.BucketCrossVerifiedProxyNamedURL,
		// Absent and unrecognised both stay in the unqualified class: neither
		// may be presented as the stronger binding, which would overstate the
		// assurance — the one direction this report must never err in.
		domain2.VCSURLBindingAbsent:    domain2.BucketCrossVerified,
		"a-binding-from-a-newer-build": domain2.BucketCrossVerified,
	} {
		if got := domain2.BucketForFetchRecord(domain2.Verified, binding); got != want {
			t.Errorf("BucketForFetchRecord(Verified, %q) = %v, want %v", binding, got, want)
		}
	}
}

// TestBucketNamesAreDistinct guards the reader-facing vocabulary: the three
// cross-verified classes must not render as the same words, or the split exists
// in the counts and not in the report anybody reads.
func TestBucketNamesAreDistinct(t *testing.T) {
	t.Parallel()

	seen := map[string]domain2.VerificationBucket{}
	for _, b := range []domain2.VerificationBucket{
		domain2.BucketCrossVerified,
		domain2.BucketCrossVerifiedModulePathURL,
		domain2.BucketCrossVerifiedProxyNamedURL,
		domain2.BucketChecksumDBOnly,
		domain2.BucketGoSumOnly,
		domain2.BucketUnverified,
		domain2.BucketLocalSource,
		domain2.BucketUnrecorded,
		domain2.BucketUnrecognised,
	} {
		name := b.String()
		if prior, dup := seen[name]; dup {
			t.Errorf("buckets %v and %v both render as %q", prior, b, name)
		}
		seen[name] = b
	}
}

// TestVerificationCoverageOf_BindingSplitSumsToTheTotal is the control this
// change is measured against. Splitting the cross-verified class must move no
// module out of it: the three sub-counts sum to CrossVerified, and the collapse
// verdict is unchanged.
func TestVerificationCoverageOf_BindingSplitSumsToTheTotal(t *testing.T) {
	t.Parallel()

	crossVerified := func(b domain2.VCSURLBinding) domain2.CoverageObservation {
		return domain2.CoverageObservation{
			Bucket:   domain2.BucketForFetchRecord(domain2.Verified, b),
			Legs:     []domain2.ValidationLeg{{Kind: domain2.LegVCS, Provenance: domain2.LegRechecked}},
			Recorded: true,
		}
	}
	var obs []domain2.CoverageObservation
	for range 5 {
		obs = append(obs, crossVerified(domain2.VCSURLBindingCoordinateDerived))
	}
	for range 3 {
		obs = append(obs, crossVerified(domain2.VCSURLBindingProxyNamed))
	}
	for range 2 {
		obs = append(obs, crossVerified(domain2.VCSURLBindingAbsent))
	}
	obs = append(obs, domain2.CoverageObservation{Bucket: domain2.BucketChecksumDBOnly, Recorded: true})

	c := domain2.VerificationCoverageOf(obs)

	if c.CrossVerified != 10 {
		t.Errorf("CrossVerified = %d, want 10: the split moved a module out of the cross-verified total", c.CrossVerified)
	}
	if c.CrossVerifiedModulePathURL != 5 {
		t.Errorf("CrossVerifiedModulePathURL = %d, want 5", c.CrossVerifiedModulePathURL)
	}
	if c.CrossVerifiedProxyNamedURL != 3 {
		t.Errorf("CrossVerifiedProxyNamedURL = %d, want 3", c.CrossVerifiedProxyNamedURL)
	}
	if c.CrossVerifiedBindingUnrecorded != 2 {
		t.Errorf("CrossVerifiedBindingUnrecorded = %d, want 2", c.CrossVerifiedBindingUnrecorded)
	}
	if sum := c.CrossVerifiedModulePathURL + c.CrossVerifiedProxyNamedURL + c.CrossVerifiedBindingUnrecorded; sum != c.CrossVerified {
		t.Errorf("the binding counts sum to %d but CrossVerified is %d: they no longer partition the class", sum, c.CrossVerified)
	}
	if c.Total != 11 || c.ChecksumDBOnly != 1 {
		t.Errorf("Total = %d, ChecksumDBOnly = %d, want 11 and 1", c.Total, c.ChecksumDBOnly)
	}
	if c.IsCollapsed() {
		t.Error("IsCollapsed() = true on a graph with ten cross-verified modules")
	}
}

// TestVerificationCoverageOf_CollapseStillFiresWhenAttributed keeps the collapse
// verdict reading the rollup. A graph whose cross-verification is entirely
// proxy-named is not collapsed — it has an anchor — and a graph with none is,
// whatever the bindings would have been.
func TestVerificationCoverageOf_CollapseStillFiresWhenAttributed(t *testing.T) {
	t.Parallel()

	proxyOnly := domain2.VerificationCoverageOf([]domain2.CoverageObservation{
		{Bucket: domain2.BucketCrossVerifiedProxyNamedURL, Recorded: true},
		{Bucket: domain2.BucketChecksumDBOnly, Recorded: true},
	})
	if proxyOnly.IsCollapsed() {
		t.Error("a graph cross-verified against proxy-named URLs was reported as collapsed: " +
			"the binding is an attribution, not a downgrade")
	}
	if proxyOnly.CrossVerified != 1 {
		t.Errorf("CrossVerified = %d, want 1", proxyOnly.CrossVerified)
	}

	none := domain2.VerificationCoverageOf([]domain2.CoverageObservation{
		{Bucket: domain2.BucketChecksumDBOnly, Recorded: true},
	})
	if !none.IsCollapsed() {
		t.Error("IsCollapsed() = false on a graph with no cross-verification at all")
	}
}
