package domain

import "testing"

// The buckets must partition the total. A coverage figure whose classes do not
// add up cannot answer "how much of this graph is anchored", and the direction
// the arithmetic would fail in — a module quietly missing from every class —
// makes a graph look better covered than it is.
func TestVerificationCoverage_BucketsPartitionTheTotal(t *testing.T) {
	obs := []CoverageObservation{
		{Bucket: BucketCrossVerified, Recorded: true},
		{Bucket: BucketCrossVerified, Recorded: true},
		{Bucket: BucketChecksumDBOnly, Recorded: true},
		{Bucket: BucketGoSumOnly, Recorded: true},
		{Bucket: BucketUnverified, Recorded: true},
		{Bucket: BucketLocalSource, Recorded: true},
		{Bucket: BucketUnrecognised, Recorded: true},
		{}, // no measurement found
	}
	c := VerificationCoverageOf(obs)

	if c.Total != len(obs) {
		t.Fatalf("Total=%d, want %d", c.Total, len(obs))
	}
	sum := c.CrossVerified + c.ChecksumDBOnly + c.GoSumOnly + c.Unverified +
		c.LocalSource + c.Unrecorded + c.Unrecognised
	if sum != c.Total {
		t.Errorf("buckets sum to %d but Total is %d — a module fell out of every class: %+v", sum, c.Total, c)
	}
	if c.CrossVerified != 2 || c.Unrecorded != 1 || c.Unrecognised != 1 {
		t.Errorf("unexpected counts: %+v", c)
	}
}

// A status this mapping has never heard of must land in its own class, not be
// folded into one it may not belong to. Overstating assurance is the one
// direction this report must never err in.
func TestBucketForVerification_UnknownStatusIsNotAssurance(t *testing.T) {
	if got := BucketForVerification(VerificationStatus("SomeFutureStatus")); got != BucketUnrecognised {
		t.Errorf("unknown status bucketed as %v, want BucketUnrecognised", got)
	}
	// Every Unverified* status is a gap, whatever its reason.
	for _, s := range []VerificationStatus{
		UnverifiedNoSumDB, UnverifiedMissingOrigin, UnverifiedHashMismatch,
		UnverifiedGoModInconsistent, UnverifiedNoVCS, UnverifiedVCSToolMissing,
	} {
		if got := BucketForVerification(s); got != BucketUnverified {
			t.Errorf("%s bucketed as %v, want BucketUnverified", s, got)
		}
	}
	for s, want := range map[VerificationStatus]VerificationBucket{
		Verified:            BucketCrossVerified,
		VerifiedBySumDBOnly: BucketChecksumDBOnly,
		VerifiedByGoSum:     BucketGoSumOnly,
		LocalSource:         BucketLocalSource,
	} {
		if got := BucketForVerification(s); got != want {
			t.Errorf("%s bucketed as %v, want %v", s, got, want)
		}
	}
}

// The distinction the fetch ledger exists to draw, and the one this report must
// not blur: a record with no legs cannot speak to cross-verification, which is a
// different claim from a record that could have recorded a VCS leg and has none.
// Conflating them makes a store of pre-ledger records look like a collapse.
func TestVCSEvidenceOf_NotMeasuredIsNotNever(t *testing.T) {
	if got := VCSEvidenceOf(nil); got != VCSNotMeasured {
		t.Errorf("a legless record reported %v, want VCSNotMeasured — it predates the ledger and cannot say", got)
	}
	// Legs present, but none of them the VCS check: a genuine absence.
	sumdbOnly := []ValidationLeg{{Kind: LegSumDB, Provenance: LegRechecked}}
	if got := VCSEvidenceOf(sumdbOnly); got != VCSNever {
		t.Errorf("a record with legs and no VCS leg reported %v, want VCSNever", got)
	}
	for _, tc := range []struct {
		prov LegProvenance
		want VCSEvidence
	}{
		{LegRechecked, VCSRechecked},
		{LegInherited, VCSInherited},
	} {
		legs := []ValidationLeg{{Kind: LegVCS, Provenance: tc.prov}}
		if got := VCSEvidenceOf(legs); got != tc.want {
			t.Errorf("VCS leg %q reported %v, want %v", tc.prov, got, tc.want)
		}
	}
}

// An inherited VCS leg is evidence, not a gap. A --skip-vcs --force run carries
// the leg forward naming the record it came from, so reporting such a module as
// never cross-verified would understate the assurance and make a deliberate skip
// look like a collapse.
func TestVerificationCoverage_InheritedIsEvidence(t *testing.T) {
	c := VerificationCoverageOf([]CoverageObservation{
		{Bucket: BucketChecksumDBOnly, Recorded: true, Legs: []ValidationLeg{
			{Kind: LegVCS, Provenance: LegInherited, Source: "sha256:earlier"},
		}},
	})
	if c.VCSInherited != 1 || c.VCSNever != 0 {
		t.Errorf("inherited leg counted as a gap: %+v", c)
	}
}

// Local source has no remote artefact, so it is neither assurance nor a gap on
// either axis. Counting it would make every project walk report a shortfall for
// its own main module on every run.
func TestVerificationCoverage_LocalSourceIsNeitherAssuranceNorGap(t *testing.T) {
	c := VerificationCoverageOf([]CoverageObservation{
		{Bucket: BucketCrossVerified, Recorded: true, Legs: []ValidationLeg{{Kind: LegVCS, Provenance: LegRechecked}}},
		{Bucket: BucketLocalSource, Recorded: true},
	})
	if c.CrossVerifiable() != 1 {
		t.Errorf("CrossVerifiable=%d, want 1: local source is not a module cross-verification applies to", c.CrossVerifiable())
	}
	if c.VCSNotMeasured != 0 || c.VCSNever != 0 {
		t.Errorf("local source counted in the ledger tally: %+v", c)
	}
	if c.IsCollapsed() {
		t.Error("a graph whose only cross-verifiable module IS cross-verified is not collapsed")
	}
}

// The condition the whole report exists to surface: every module degraded to a
// weaker anchor, with the status column populated and a zero exit code.
func TestVerificationCoverage_IsCollapsed(t *testing.T) {
	collapsed := VerificationCoverageOf([]CoverageObservation{
		{Bucket: BucketChecksumDBOnly, Recorded: true},
		{Bucket: BucketChecksumDBOnly, Recorded: true},
	})
	if !collapsed.IsCollapsed() {
		t.Error("a graph with no VCS anchor anywhere must report as collapsed")
	}

	// An empty graph, and a graph with nothing to cross-verify, are not
	// collapses — there was no assurance to lose.
	if VerificationCoverageOf(nil).IsCollapsed() {
		t.Error("an empty graph is not a collapse")
	}
	localOnly := VerificationCoverageOf([]CoverageObservation{{Bucket: BucketLocalSource, Recorded: true}})
	if localOnly.IsCollapsed() {
		t.Error("a graph of only local source is not a collapse")
	}
}

// The bucket names are the reader-facing vocabulary of the coverage line, so
// they are pinned as output rather than left to whatever the switch happens to
// return. Every bucket must name itself: a bucket that fell through to the
// default would report a real class as "unrecognised status" and read as a
// measurement failure rather than as the class it is.
func TestVerificationBucket_String(t *testing.T) {
	for bucket, want := range map[VerificationBucket]string{
		BucketCrossVerified:  "cross-verified (checksum db + VCS)",
		BucketChecksumDBOnly: "checksum database only",
		BucketGoSumOnly:      "local go.sum only",
		BucketUnverified:     "unverified",
		BucketLocalSource:    "local source (nothing to verify)",
		BucketUnrecorded:     "no fetch record",
		BucketUnrecognised:   "unrecognised status",
	} {
		if got := bucket.String(); got != want {
			t.Errorf("bucket %d = %q, want %q", int(bucket), got, want)
		}
	}

	// A value from outside the enum is the safety net, not a panic.
	if got := VerificationBucket(99).String(); got != "unrecognised status" {
		t.Errorf("out-of-range bucket = %q, want the safety net", got)
	}
}

// An explicitly absent VCS leg is the same claim as no VCS leg at all: the
// ledger was written, could have recorded one, and did not. RecordLegs never
// emits LegAbsent today, but a composed or hand-built set can, and it must not
// fall through to the not-measured class — that would report a genuine gap as
// "the record cannot say".
func TestVCSEvidenceOf_AbsentLegIsNever(t *testing.T) {
	got := VCSEvidenceOf([]ValidationLeg{
		{Kind: LegSumDB, Provenance: LegRechecked},
		{Kind: LegVCS, Provenance: LegAbsent},
	})
	if got != VCSNever {
		t.Errorf("VCSEvidenceOf = %v, want VCSNever: an absent leg is a measured absence, not an unmeasured one", got)
	}
}

// The buckets must keep partitioning the total. BucketUnrecorded is not
// reachable from a status today — an absent record is handled before the
// switch — but the arm exists so the sum still holds if the mapping ever
// changes, and an arm nothing exercises is an arm nothing protects.
func TestVerificationCoverageOf_RecordedUnrecordedBucketStillCounts(t *testing.T) {
	c := VerificationCoverageOf([]CoverageObservation{
		{Bucket: BucketUnrecorded, Recorded: true},
	})
	if c.Total != 1 {
		t.Fatalf("Total = %d, want 1", c.Total)
	}
	if c.Unrecorded != 1 {
		t.Errorf("Unrecorded = %d, want 1: the bucket must be counted, not dropped", c.Unrecorded)
	}
	if sum := c.CrossVerified + c.ChecksumDBOnly + c.GoSumOnly + c.Unverified +
		c.LocalSource + c.Unrecorded + c.Unrecognised; sum != c.Total {
		t.Errorf("buckets sum to %d but Total is %d: they no longer partition the graph", sum, c.Total)
	}
}

// VCSNever is the class that matters most — the only one where no
// cross-verification evidence exists at all — so it is counted explicitly
// rather than inferred from the others.
func TestVerificationCoverageOf_CountsVCSNever(t *testing.T) {
	c := VerificationCoverageOf([]CoverageObservation{
		{
			Bucket:   BucketChecksumDBOnly,
			Recorded: true,
			Legs:     []ValidationLeg{{Kind: LegSumDB, Provenance: LegRechecked}},
		},
	})
	if c.VCSNever != 1 {
		t.Errorf("VCSNever = %d, want 1: a record with legs and no VCS leg is a measured absence", c.VCSNever)
	}
	if c.VCSNotMeasured != 0 {
		t.Errorf("VCSNotMeasured = %d, want 0: this record carries legs, so it can speak to the question", c.VCSNotMeasured)
	}
}
