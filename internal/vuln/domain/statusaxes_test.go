package domain_test

import (
	"crypto/sha256"
	"encoding/hex"
	"testing"
	"time"

	coordinatetest "github.com/eitanity/kanonarion/internal/coordinate/coordinatetest"
	fetchdomain "github.com/eitanity/kanonarion/internal/fetch/domain"
	"github.com/eitanity/kanonarion/internal/vuln/domain"
)

// TestDetermineRecordOverallStatus_EveryAxisPair pins the whole collapse table,
// not a sample of it. The summary is what every legacy consumer still reads, so
// a pair that collapsed to the wrong word would misreport a verdict to exactly
// the readers who cannot see the axes.
//
// Coverage outranks findings: a record that could not be analysed reports that,
// never a findings word it has no standing to assert.
func TestDetermineRecordOverallStatus_EveryAxisPair(t *testing.T) {
	for _, tc := range []struct {
		name     string
		coverage domain.RecordCoverageStatus
		findings domain.RecordFindingsStatus
		want     domain.VulnerabilityStatus
	}{
		{"analysed and clean is the only all-clear", domain.CoverageAnalysed, domain.FindingsRecordClean, domain.StatusClean},
		{"analysed and affected", domain.CoverageAnalysed, domain.FindingsRecordAffected, domain.StatusAffected},
		{"unscannable reports coverage", domain.CoverageUnscannable, domain.FindingsRecordClean, domain.StatusUnscannable},
		// The pair the collapsed word has no value for: the advisory matched, but
		// coverage failed. The summary must not become Clean, which would read as
		// an all-clear; the findings axis keeps the finding.
		{"unscannable that still matched an advisory", domain.CoverageUnscannable, domain.FindingsRecordAffected, domain.StatusUnscannable},
		{"failed reports coverage", domain.CoverageFailedScan, domain.FindingsRecordClean, domain.StatusScanFailed},
		{"failed that still matched an advisory", domain.CoverageFailedScan, domain.FindingsRecordAffected, domain.StatusScanFailed},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := domain.DetermineRecordOverallStatus(tc.coverage, tc.findings); got != tc.want {
				t.Fatalf("DetermineRecordOverallStatus(%q, %q) = %q, want %q", tc.coverage, tc.findings, got, tc.want)
			}
		})
	}
}

// TestDetermineRecordOverallStatus_UnrecognisedCoverageDoesNotClaimAnalysed
// covers the defensive arm. No such value exists today; the arm guards the
// invariant that an unknown coverage value must never summarise as a verdict
// about a module that was analysed, because that is the one direction in which
// being wrong manufactures a false all-clear.
func TestDetermineRecordOverallStatus_UnrecognisedCoverageDoesNotClaimAnalysed(t *testing.T) {
	got := domain.DetermineRecordOverallStatus(domain.RecordCoverageStatus("SomeFutureCoverage"), domain.FindingsRecordClean)
	if got != domain.StatusScanFailed {
		t.Fatalf("DetermineRecordOverallStatus(unrecognised) = %q, want %q", got, domain.StatusScanFailed)
	}
	if got == domain.StatusClean || got == domain.StatusAffected {
		t.Fatalf("an unrecognised coverage value summarised as an analysed verdict (%q)", got)
	}
}

// TestDetermineRecordCoverageStatus_UnrecognisedIsNotAnalysed is the same guard
// on the projection side: an unknown collapsed status must fall out of the
// analysed population rather than over-claim completeness.
func TestDetermineRecordCoverageStatus_UnrecognisedIsNotAnalysed(t *testing.T) {
	if got := domain.DetermineRecordCoverageStatus(domain.VulnerabilityStatus("SomeFutureStatus")); got != domain.CoverageFailedScan {
		t.Fatalf("DetermineRecordCoverageStatus(unrecognised) = %q, want %q", got, domain.CoverageFailedScan)
	}
}

// TestRecordAxes_PrefersStoredFieldsAndHealsPreSplitRecords pins the read path.
// A record written before the split carries no axes, and the ranking and
// display paths must not see an empty axis they have no rule for — so the pair
// is recovered from the collapsed summary, by the same projection the write
// path applies.
func TestRecordAxes_PrefersStoredFieldsAndHealsPreSplitRecords(t *testing.T) {
	for _, tc := range []struct {
		status   domain.VulnerabilityStatus
		coverage domain.RecordCoverageStatus
		findings domain.RecordFindingsStatus
	}{
		{domain.StatusClean, domain.CoverageAnalysed, domain.FindingsRecordClean},
		{domain.StatusAffected, domain.CoverageAnalysed, domain.FindingsRecordAffected},
		{domain.StatusUnscannable, domain.CoverageUnscannable, domain.FindingsRecordClean},
		{domain.StatusScanFailed, domain.CoverageFailedScan, domain.FindingsRecordClean},
	} {
		t.Run("pre-split "+string(tc.status), func(t *testing.T) {
			r := axisSeedRecord()
			r.OverallStatus = tc.status // axes deliberately left empty
			if c, f := domain.RecordAxes(r); c != tc.coverage || f != tc.findings {
				t.Fatalf("RecordAxes(pre-split %s) = %q/%q, want %q/%q", tc.status, c, f, tc.coverage, tc.findings)
			}
		})
	}

	// Stored fields win over the summary, including the pair the summary cannot
	// express — otherwise the read path would collapse the finding back out.
	t.Run("stored axes are returned verbatim", func(t *testing.T) {
		r := axisSeedRecord()
		r.OverallStatus = domain.StatusScanFailed
		r.CoverageStatus = domain.CoverageFailedScan
		r.FindingsStatus = domain.FindingsRecordAffected
		if c, f := domain.RecordAxes(r); c != domain.CoverageFailedScan || f != domain.FindingsRecordAffected {
			t.Fatalf("RecordAxes(stored) = %q/%q, want the stored pair back", c, f)
		}
	})

	// A half-populated record — possible only from hand-built data — still yields
	// a complete pair rather than one empty axis.
	t.Run("one stored axis, one derived", func(t *testing.T) {
		r := axisSeedRecord()
		r.OverallStatus = domain.StatusAffected
		r.CoverageStatus = domain.CoverageUnscannable
		c, f := domain.RecordAxes(r)
		if c != domain.CoverageUnscannable || f != domain.FindingsRecordAffected {
			t.Fatalf("RecordAxes(half) = %q/%q, want %q/%q", c, f, domain.CoverageUnscannable, domain.FindingsRecordAffected)
		}
	})
}

// TestHashSnapshotContent pins the advisory-database blob's hash recipe: SHA-256
// over the bytes verbatim, "sha256:"-prefixed. The prefix is the project's
// normal form and is deliberately unlike VulnerabilityRecord's bare hex, whose
// recipe is frozen by the records already stored.
func TestHashSnapshotContent(t *testing.T) {
	const body = "advisory database bytes"
	// Written out independently rather than taken from the function's own output.
	sum := sha256.Sum256([]byte(body))
	want := "sha256:" + hex.EncodeToString(sum[:])

	if got := domain.HashSnapshotContent([]byte(body)); got != want {
		t.Fatalf("HashSnapshotContent() = %q, want %q", got, want)
	}
	// Distinct bytes must not share a hash, or the check verifies nothing.
	if domain.HashSnapshotContent([]byte("other bytes")) == want {
		t.Fatal("HashSnapshotContent() collided on distinct inputs")
	}
	// Empty and nil are the same zero-length input and must hash alike, so a
	// snapshot with no body seals deterministically rather than by which caller
	// produced it.
	if domain.HashSnapshotContent(nil) != domain.HashSnapshotContent([]byte{}) {
		t.Fatal("HashSnapshotContent(nil) and HashSnapshotContent(empty) disagree")
	}
}

// axisSeedRecord is a minimal record with no status fields set, so each test
// below states exactly the axes it is about.
func axisSeedRecord() domain.VulnerabilityRecord {
	return domain.VulnerabilityRecord{
		Ecosystem:        fetchdomain.EcosystemGo,
		Coordinate:       coordinatetest.MustNew("github.com/foo/bar", "v1.0.0"),
		DatabaseSnapshot: domain.DatabaseSnapshot{Source: "test", Version: "v1"},
		ScannedAt:        time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC),
		PipelineVersion:  "v1",
	}
}

// TestSetContentHash_PartiallyStatedAxes covers the seal step's mixed case: one
// axis stated and the other left empty.
//
// It is not a hypothetical shape — it is what a caller writes when it wants to
// narrow one axis and leave the other as the summary already implies. The
// unstated axis must fall back to a derivation rather than being sealed as the
// empty string, which no reader has a rule for, and a summary the caller stated
// must survive the narrowing.
func TestSetContentHash_PartiallyStatedAxes(t *testing.T) {
	var h domain.VulnerabilityRecordHasher

	t.Run("findings stated, coverage inferred from the summary", func(t *testing.T) {
		r := axisSeedRecord()
		r.OverallStatus = domain.StatusUnscannable
		r.FindingsStatus = domain.FindingsRecordAffected

		sealed, err := h.SetContentHash(r)
		if err != nil {
			t.Fatalf("SetContentHash(): %v", err)
		}
		if sealed.CoverageStatus != domain.CoverageUnscannable {
			t.Fatalf("coverage = %q, want %q inferred from the summary", sealed.CoverageStatus, domain.CoverageUnscannable)
		}
		if sealed.FindingsStatus != domain.FindingsRecordAffected {
			t.Fatalf("findings = %q, want the caller's %q preserved", sealed.FindingsStatus, domain.FindingsRecordAffected)
		}
		if sealed.OverallStatus != domain.StatusUnscannable {
			t.Fatalf("summary = %q, want %q re-derived from the completed pair", sealed.OverallStatus, domain.StatusUnscannable)
		}
	})

	t.Run("coverage stated, findings inferred from the summary", func(t *testing.T) {
		r := axisSeedRecord()
		r.OverallStatus = domain.StatusAffected
		r.CoverageStatus = domain.CoverageFailedScan

		sealed, err := h.SetContentHash(r)
		if err != nil {
			t.Fatalf("SetContentHash(): %v", err)
		}
		if sealed.FindingsStatus != domain.FindingsRecordAffected {
			t.Fatalf("findings = %q, want %q inferred from the summary", sealed.FindingsStatus, domain.FindingsRecordAffected)
		}
		if sealed.CoverageStatus != domain.CoverageFailedScan {
			t.Fatalf("coverage = %q, want the caller's %q preserved", sealed.CoverageStatus, domain.CoverageFailedScan)
		}
		// The caller narrowed coverage to a failure and still stated Affected. The
		// summary stands: collapsing the pair would report ScanFailed and retire a
		// finding the caller is reporting, and the coverage failure is not lost —
		// it is on the axis, which is why the axis is stored.
		if sealed.OverallStatus != domain.StatusAffected {
			t.Fatalf("summary = %q, want the caller's %q kept — collapsing would retire the finding", sealed.OverallStatus, domain.StatusAffected)
		}
	})

	// Whatever the route in, the sealed record verifies against its own hash.
	t.Run("the sealed record verifies", func(t *testing.T) {
		r := axisSeedRecord()
		r.OverallStatus = domain.StatusAffected
		r.CoverageStatus = domain.CoverageFailedScan

		sealed, err := h.SetContentHash(r)
		if err != nil {
			t.Fatalf("SetContentHash(): %v", err)
		}
		if err := h.VerifyContentHash(sealed); err != nil {
			t.Fatalf("VerifyContentHash(sealed) = %v, want nil", err)
		}
	})
}

// TestSetContentHash_CoverageGapDoesNotRetireAStatedFinding is the shape the
// whole split exists for: an advisory matched by coordinate on a module whose
// source could never be analysed. All three fields must survive the seal exactly
// as the writer stated them.
//
// Collapsing the axes here would report Unscannable, because coverage outranks
// findings in the collapse — correct for ranking, and wrong to write back over
// the summary, since every consumer that reads the single word would stop seeing
// the match. A finding does not decay into a coverage word.
func TestSetContentHash_CoverageGapDoesNotRetireAStatedFinding(t *testing.T) {
	r := axisSeedRecord()
	r.OverallStatus = domain.StatusAffected
	r.CoverageStatus = domain.CoverageUnscannable
	r.FindingsStatus = domain.FindingsRecordAffected

	sealed, err := domain.VulnerabilityRecordHasher{}.SetContentHash(r)
	if err != nil {
		t.Fatalf("SetContentHash(): %v", err)
	}
	if sealed.OverallStatus != domain.StatusAffected {
		t.Fatalf("summary = %q, want %q — the finding must survive the coverage gap", sealed.OverallStatus, domain.StatusAffected)
	}
	if sealed.CoverageStatus != domain.CoverageUnscannable {
		t.Fatalf("coverage = %q, want %q — the gap must survive the finding", sealed.CoverageStatus, domain.CoverageUnscannable)
	}
	if sealed.FindingsStatus != domain.FindingsRecordAffected {
		t.Fatalf("findings = %q, want %q", sealed.FindingsStatus, domain.FindingsRecordAffected)
	}
}

// TestSetContentHash_SummaryIsCollapsedOnlyWhenUnstated pins which side owns the
// summary word: a writer that states it owns it, and one that leaves it empty
// gets the collapse of the axes it did state.
//
// The stated case matters because the summary is what every pre-split consumer
// reads, and the writer is the only party that knows which of the two axes it
// wants that reader to see.
func TestSetContentHash_SummaryIsCollapsedOnlyWhenUnstated(t *testing.T) {
	var h domain.VulnerabilityRecordHasher

	t.Run("unstated summary is collapsed from the axes", func(t *testing.T) {
		r := axisSeedRecord()
		r.OverallStatus = ""
		r.CoverageStatus = domain.CoverageAnalysed
		r.FindingsStatus = domain.FindingsRecordAffected

		sealed, err := h.SetContentHash(r)
		if err != nil {
			t.Fatalf("SetContentHash(): %v", err)
		}
		if sealed.OverallStatus != domain.StatusAffected {
			t.Fatalf("summary = %q, want %q collapsed from the axes", sealed.OverallStatus, domain.StatusAffected)
		}
	})

	t.Run("stated summary is left alone", func(t *testing.T) {
		r := axisSeedRecord()
		r.OverallStatus = domain.StatusClean
		r.CoverageStatus = domain.CoverageUnscannable
		r.FindingsStatus = domain.FindingsRecordClean

		sealed, err := h.SetContentHash(r)
		if err != nil {
			t.Fatalf("SetContentHash(): %v", err)
		}
		// The metadata-only fallback's no-match shape: a coordinate was matched
		// against the advisory database and nothing applied, which is a real
		// findings answer, so the writer keeps Clean as the summary while the
		// coverage axis records that no source was ever analysed.
		if sealed.OverallStatus != domain.StatusClean {
			t.Fatalf("summary = %q, want the writer's %q", sealed.OverallStatus, domain.StatusClean)
		}
		if sealed.CoverageStatus != domain.CoverageUnscannable {
			t.Fatalf("coverage = %q, want %q", sealed.CoverageStatus, domain.CoverageUnscannable)
		}
	})
}

// TestDetermineRecordCoverage_EvidenceBeatsTheCollapsedWord is the correction the
// axes needed: coverage comes from what the record recorded, not from the word it
// summarised with.
//
// The metadata-only fallback is the case that forced it. It records a coverage
// gap AND an advisory match, and the single word can hold only one of them, so it
// holds the match. Projecting coverage off that word answered "Analysed" for a
// module whose source was never read — measured at 74 rows of a working store,
// persisted there by the back-fill that did exactly this projection.
func TestDetermineRecordCoverage_EvidenceBeatsTheCollapsedWord(t *testing.T) {
	for _, tc := range []struct {
		name   string
		record domain.VulnerabilityRecord
		want   domain.RecordCoverageStatus
	}{
		{
			"an advisory matched on a module that could not be analysed",
			domain.VulnerabilityRecord{OverallStatus: domain.StatusAffected, UnscanReason: domain.UnscanReasonVersionNotInToolchain},
			domain.CoverageUnscannable,
		},
		{
			"prose without a reason code is still a coverage gap",
			domain.VulnerabilityRecord{OverallStatus: domain.StatusClean, UnscannableReason: "metadata-only: module not fetched"},
			domain.CoverageUnscannable,
		},
		{
			"an error detail alone is a failed look, not an unanalysable module",
			domain.VulnerabilityRecord{OverallStatus: domain.StatusAffected, ErrorDetail: "govulncheck exited 1"},
			domain.CoverageFailedScan,
		},
		{
			"a named reason outranks an error detail beside it",
			domain.VulnerabilityRecord{OverallStatus: domain.StatusAffected, UnscanReason: domain.UnscanReasonNoGoMod, ErrorDetail: "build failed"},
			domain.CoverageUnscannable,
		},
		{
			"no diagnostic at all: the analysis ran, so the word answers",
			domain.VulnerabilityRecord{OverallStatus: domain.StatusAffected},
			domain.CoverageAnalysed,
		},
		{
			"a clean analysis with no diagnostic",
			domain.VulnerabilityRecord{OverallStatus: domain.StatusClean},
			domain.CoverageAnalysed,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := domain.DetermineRecordCoverage(tc.record); got != tc.want {
				t.Fatalf("DetermineRecordCoverage() = %q, want %q", got, tc.want)
			}
		})
	}
}

// A pre-split record is healed on read by the same rule the write path applies,
// so the 74 mislabelled rows do not come back as Analysed the moment they are
// read through RecordAxes rather than through the corrected column.
func TestRecordAxes_HealsAPreSplitCoverageGapFromItsDiagnostics(t *testing.T) {
	// No axes stored: exactly the shape of a record written before the split.
	rec := domain.VulnerabilityRecord{
		OverallStatus: domain.StatusAffected,
		UnscanReason:  domain.UnscanReasonVersionNotInToolchain,
		Findings:      []domain.VulnerabilityFinding{{ID: "GO-2024-0001"}},
	}
	coverage, findings := domain.RecordAxes(rec)
	if coverage != domain.CoverageUnscannable {
		t.Errorf("coverage = %q, want %q recovered from the reason it recorded", coverage, domain.CoverageUnscannable)
	}
	if findings != domain.FindingsRecordAffected {
		t.Errorf("findings = %q, want %q: the match is still reported", findings, domain.FindingsRecordAffected)
	}
}
