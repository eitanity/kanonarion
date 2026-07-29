package domain

// VerificationBucket is the coverage class a module's verification status falls
// into. The statuses are a detailed vocabulary — nine of them and growing — and
// a coverage figure needs a handful of classes a reader can hold in their head,
// so the mapping is stated once here rather than re-derived by each caller.
type VerificationBucket int

const (
	// BucketUnrecognised is the zero value and the safety net: a status this
	// mapping has never heard of lands here rather than being folded into a
	// class it may not belong to. A coverage report that quietly counted an
	// unknown status as verified would overstate assurance, which is the one
	// direction this report must never err in.
	BucketUnrecognised VerificationBucket = iota

	// BucketCrossVerified is the strongest assurance: the zip matched both the
	// checksum database and the content extracted from its git commit.
	BucketCrossVerified

	// BucketChecksumDBOnly is authentic with respect to the transparency log,
	// with no VCS anchor. This is the class a whole-graph collapse lands in.
	BucketChecksumDBOnly

	// BucketGoSumOnly matched a local go.sum with no live checksum-database
	// query — a positive offline signal, weaker than the log itself.
	BucketGoSumOnly

	// BucketUnverified covers every Unverified* status: no anchor was
	// established, whatever the reason. The reasons differ in what to do about
	// them and not in how much assurance they carry, which is what a coverage
	// figure measures.
	BucketUnverified

	// BucketLocalSource is a module built from a local source tree — the main
	// module, a local-path replace. There is no remote artefact to cross-verify,
	// so it is neither assurance nor a gap, and folding it into either would
	// make every project walk misreport itself.
	BucketLocalSource

	// BucketUnrecorded is a module in the graph with no fetch record at all: a
	// node that was never fetched, or was fetched under a different pipeline
	// version. Absence of a measurement, not a failed one.
	BucketUnrecorded
)

// String names the bucket for display. The names are the reader-facing
// vocabulary of the coverage line and are deliberately plainer than the status
// constants they aggregate.
func (b VerificationBucket) String() string {
	switch b {
	case BucketCrossVerified:
		return "cross-verified (checksum db + VCS)"
	case BucketChecksumDBOnly:
		return "checksum database only"
	case BucketGoSumOnly:
		return "local go.sum only"
	case BucketUnverified:
		return "unverified"
	case BucketLocalSource:
		return "local source (nothing to verify)"
	case BucketUnrecorded:
		return "no fetch record"
	case BucketUnrecognised:
		return "unrecognised status"
	default:
		return "unrecognised status"
	}
}

// BucketForVerification maps a verification status onto its coverage class.
func BucketForVerification(s VerificationStatus) VerificationBucket {
	switch s {
	case Verified:
		return BucketCrossVerified
	case VerifiedBySumDBOnly:
		return BucketChecksumDBOnly
	case VerifiedByGoSum:
		return BucketGoSumOnly
	case UnverifiedNoSumDB, UnverifiedMissingOrigin, UnverifiedHashMismatch,
		UnverifiedGoModInconsistent, UnverifiedNoVCS, UnverifiedVCSToolMissing:
		return BucketUnverified
	case LocalSource:
		return BucketLocalSource
	default:
		return BucketUnrecognised
	}
}

// VCSEvidence is what the fetch ledger says about a module's VCS
// cross-verification, which is a different question from the verification
// status: the status says how strong the assurance is, the evidence says how
// fresh it is and whether this run established it or carried it forward.
type VCSEvidence int

const (
	// VCSNotMeasured is the zero value: the record carries no validation legs at
	// all, because it predates the ledger. It is NOT the same as never
	// cross-verified — the check may well have run, the record simply cannot
	// say. Reporting these as a gap would make a store full of pre-ledger
	// records look like a total collapse.
	VCSNotMeasured VCSEvidence = iota

	// VCSRechecked means this measurement performed the VCS check itself.
	VCSRechecked

	// VCSInherited means the result was carried forward from an earlier
	// measurement of the same artefact, which named the record it came from. The
	// module IS backed by cross-verification evidence; this run simply did not
	// re-establish it.
	VCSInherited

	// VCSNever means the record carries legs — so it was written under the
	// ledger and could have recorded a VCS leg — and has none. This is the only
	// class where no cross-verification evidence exists at all, and the one that
	// matters most.
	VCSNever
)

// VCSEvidenceOf reads a record's validation legs. A record with no legs at all
// cannot speak to the question and reports VCSNotMeasured; a record with legs
// but no VCS leg is a genuine absence.
func VCSEvidenceOf(legs []ValidationLeg) VCSEvidence {
	if len(legs) == 0 {
		return VCSNotMeasured
	}
	for _, l := range legs {
		if l.Kind != LegVCS {
			continue
		}
		switch l.Provenance {
		case LegRechecked:
			return VCSRechecked
		case LegInherited:
			return VCSInherited
		case LegAbsent:
			// RecordLegs never emits one, but a composed or hand-built set
			// might; an absent leg is the same claim as no leg at all.
			return VCSNever
		}
	}
	return VCSNever
}

// CoverageObservation is one module's contribution to the aggregate.
//
// It carries a resolved Bucket rather than a raw status on purpose. Not every
// node in a graph is verified in the fetch stage's vocabulary — the standard
// library has its own, deliberately distinct set (VerifiedGoDevChecksum,
// VerifiedLocalToolchain, …) — and a field typed VerificationStatus invites a
// caller to cast a foreign vocabulary into it, which reads as an unrecognised
// status rather than the assurance the node actually has. Each caller maps its
// own vocabulary; this type only counts classes.
type CoverageObservation struct {
	// Bucket is the coverage class. Ignored when Recorded is false.
	Bucket VerificationBucket
	// Legs are the record's validation legs, empty for a pre-ledger record.
	Legs []ValidationLeg
	// Recorded is false when the graph holds this module but no measurement of
	// it could be found.
	Recorded bool
}

// VerificationCoverage is the aggregate this report exists to make visible: how
// a whole graph was verified, so a collapse of the strongest assurance across
// every module is noticed without reading every row.
//
// The buckets partition the total — every observation lands in exactly one, and
// an unrecognised status lands in its own class rather than vanishing. The VCS
// evidence counts partition the recorded total separately, answering a
// different question: not how strong the assurance is but how fresh, and
// whether the ledger can speak to it at all.
type VerificationCoverage struct {
	Total int

	CrossVerified  int
	ChecksumDBOnly int
	GoSumOnly      int
	Unverified     int
	LocalSource    int
	Unrecorded     int
	Unrecognised   int

	VCSRechecked   int
	VCSInherited   int
	VCSNever       int
	VCSNotMeasured int
}

// VerificationCoverageOf aggregates observations. It names no host and judges no
// proxy: the signal is coverage, and a proxy allowlist would age badly, would
// carry geopolitical content, and would still miss the operational causes —
// a blocked forge, a stale --skip-vcs-verify, a narrow allowed_vcs_hosts — that
// degrade a graph just as completely.
func VerificationCoverageOf(obs []CoverageObservation) VerificationCoverage {
	var c VerificationCoverage
	c.Total = len(obs)
	for _, o := range obs {
		if !o.Recorded {
			c.Unrecorded++
			continue
		}
		switch o.Bucket {
		case BucketCrossVerified:
			c.CrossVerified++
		case BucketChecksumDBOnly:
			c.ChecksumDBOnly++
		case BucketGoSumOnly:
			c.GoSumOnly++
		case BucketUnverified:
			c.Unverified++
		case BucketLocalSource:
			c.LocalSource++
		case BucketUnrecorded:
			// Not reachable from a status — BucketUnrecorded describes an absent
			// record, handled above — but counted rather than dropped so the
			// buckets keep partitioning the total if the mapping ever changes.
			c.Unrecorded++
		case BucketUnrecognised:
			c.Unrecognised++
		}

		// Local source has no remote artefact to cross-verify, so it is not a
		// gap in the ledger's evidence either. Counting it as "not measured"
		// would invite exactly the misreading these classes exist to prevent.
		if o.Bucket == BucketLocalSource {
			continue
		}
		switch VCSEvidenceOf(o.Legs) {
		case VCSRechecked:
			c.VCSRechecked++
		case VCSInherited:
			c.VCSInherited++
		case VCSNever:
			c.VCSNever++
		case VCSNotMeasured:
			c.VCSNotMeasured++
		}
	}
	return c
}

// Recorded is the number of observations backed by a measurement.
//
// It is NOT the denominator the VCS evidence counts partition — those skip local
// source, which has no remote artefact to cross-verify and so is not a gap in
// the ledger's evidence either. CrossVerifiable is that denominator.
func (c VerificationCoverage) Recorded() int {
	return c.Total - c.Unrecorded
}

// CrossVerifiable is the number of modules for which cross-verification is a
// meaningful question: the recorded ones that are not local source. It is the
// honest denominator for "what fraction of this graph has a VCS anchor" —
// against Total, a project walk would report a shortfall for its own main
// module, which has no remote artefact to anchor.
func (c VerificationCoverage) CrossVerifiable() int {
	return c.Recorded() - c.LocalSource
}

// IsCollapsed reports whether cross-verification covered none of a graph that
// had something to cross-verify. This is the condition the report exists to
// surface: every module degraded to a weaker anchor, with the status column
// populated, no warnings raised, and a zero exit code.
func (c VerificationCoverage) IsCollapsed() bool {
	return c.CrossVerifiable() > 0 && c.CrossVerified == 0
}
