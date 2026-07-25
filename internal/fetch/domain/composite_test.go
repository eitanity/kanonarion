package domain_test

import (
	"testing"
	"time"

	"github.com/eitanity/kanonarion/internal/coordinate"
	"github.com/eitanity/kanonarion/internal/fetch/domain"
	"github.com/eitanity/kanonarion/internal/fetch/fetchtest"
)

var composeCoord = coordinate.ModuleCoordinate{Path: "example.com/mod", Version: "v1.0.0"}

func at(day int) time.Time { return time.Date(2026, 1, day, 12, 0, 0, 0, time.UTC) }

// Composition serves the STRONGEST ELIGIBLE measurement, not the most recent.
//
// This is the relocation of the cache-eligibility rule to the read side. If the
// newest record won, a measurement whose checksum-database lookup failed —
// appended after a good one — would become the answer on every subsequent run
// until an operator forced a re-measurement, which is the downgrade the flag was
// introduced to stop.
func TestCompose_ServesTheStrongestEligibleNotTheNewest(t *testing.T) {
	good := fetchtest.Record(t,
		fetchtest.Coordinate(composeCoord),
		fetchtest.ModuleHash(fetchtest.H1("zip==")),
		fetchtest.Status(domain.Verified),
		fetchtest.FetchedAt(at(1)),
	)
	failedLookup := fetchtest.Record(t,
		fetchtest.Coordinate(composeCoord),
		fetchtest.ModuleHash(fetchtest.H1("zip==")),
		fetchtest.Status(domain.UnverifiedNoSumDB),
		fetchtest.SumDBLookupFailed(true),
		fetchtest.FetchedAt(at(2)), // newer
	)

	got, err := domain.Compose([]domain.FactRecord{good, failedLookup})
	if err != nil {
		t.Fatalf("Compose: %v", err)
	}
	if got.ContentHash != good.ContentHash {
		t.Errorf("served the newest measurement (%q); a failed lookup must never displace a good record",
			got.VerificationStatus)
	}
	if got.MeasurementCount != 2 {
		t.Errorf("MeasurementCount = %d, want 2", got.MeasurementCount)
	}
}

// When no measurement is eligible the strongest ineligible one is still served:
// a store holding only failed-lookup measurements must answer rather than report
// the artefact absent.
func TestCompose_ServesAnIneligibleRecordWhenNoneAreEligible(t *testing.T) {
	weak := fetchtest.Record(t,
		fetchtest.Coordinate(composeCoord),
		fetchtest.ModuleHash(fetchtest.H1("zip==")),
		fetchtest.Status(domain.UnverifiedNoSumDB),
		fetchtest.SumDBLookupFailed(true),
		fetchtest.FetchedAt(at(1)),
	)
	got, err := domain.Compose([]domain.FactRecord{weak})
	if err != nil {
		t.Fatalf("Compose: %v", err)
	}
	if got.ContentHash != weak.ContentHash {
		t.Error("a store holding only ineligible measurements reported no answer at all")
	}
}

// First-seen is the EARLIEST measurement of the artefact, and it is the date
// every other domain reads. Deleting a blob and re-acquiring it must not move
// it: the bytes were first seen when they were first seen.
func TestCompose_FirstFetchedAtIsTheEarliestMeasurement(t *testing.T) {
	first := fetchtest.Record(t,
		fetchtest.Coordinate(composeCoord),
		fetchtest.ModuleHash(fetchtest.H1("zip==")),
		fetchtest.Status(domain.Verified),
		fetchtest.FetchedAt(at(1)),
	)
	reacquired := fetchtest.Record(t,
		fetchtest.Coordinate(composeCoord),
		fetchtest.ModuleHash(fetchtest.H1("zip==")),
		fetchtest.Status(domain.Verified),
		fetchtest.FetchedAt(at(9)),
	)

	got, err := domain.Compose([]domain.FactRecord{first, reacquired})
	if err != nil {
		t.Fatalf("Compose: %v", err)
	}
	if !got.FirstFetchedAt.Equal(at(1)) {
		t.Errorf("FirstFetchedAt = %v, want the earliest measurement %v", got.FirstFetchedAt, at(1))
	}
	if !got.LatestFetchedAt.Equal(at(9)) {
		t.Errorf("LatestFetchedAt = %v, want %v", got.LatestFetchedAt, at(9))
	}
	// The embedded record's own FetchedAt is the served measurement's time, which
	// is deliberately NOT first-seen. A consumer asking "when was this fetched"
	// must read FirstFetchedAt.
	if got.FetchedAt.Equal(got.FirstFetchedAt) && !got.FirstFetchedAt.Equal(got.LatestFetchedAt) {
		t.Error("the embedded FetchedAt was rewritten to first-seen; it must stay the served measurement's own time")
	}
}

// A local coordinate's measurements are a sequence of observations of a changing
// working tree, not competing claims about one pinned artefact, so the LAST one
// is served. Serving any earlier one hands back a state of the tree that no
// longer exists, and an edit made between two runs silently fails to appear.
//
// The measurements deliberately share a timestamp: fetched_at persists at second
// precision, so two runs within one second are indistinguishable by time and the
// ledger's insertion order is the only sequence there is.
func TestCompose_LocalCoordinateServesTheLastMeasurement(t *testing.T) {
	local := coordinate.ModuleCoordinate{Path: "example.com/proj", Version: coordinate.LocalVersion}
	opts := func(hash string) []fetchtest.Option {
		return []fetchtest.Option{
			fetchtest.Coordinate(local),
			fetchtest.ModuleHash(fetchtest.H1(hash)),
			fetchtest.Status(domain.LocalSource),
			fetchtest.FetchedAt(at(1)),
		}
	}
	before := fetchtest.Record(t, opts("tree-before==")...)
	after := fetchtest.Record(t, opts("tree-after==")...)

	got, err := domain.Compose([]domain.FactRecord{before, after})
	if err != nil {
		t.Fatalf("Compose: %v", err)
	}
	if got.ContentHash != after.ContentHash {
		t.Error("a local root served an earlier state of the working tree; an edit between runs would vanish")
	}
	if got.Identity.Hash.Value != "tree-after==" {
		t.Errorf("Identity = %v, want the served measurement's own artefact", got.Identity)
	}
}

// Validation legs are unioned across the composed measurements, so evidence one
// run established is still visible after a later run that did not perform the
// check.
func TestCompose_UnionsValidationLegsAcrossMeasurements(t *testing.T) {
	withVCS := fetchtest.Record(t,
		fetchtest.Coordinate(composeCoord),
		fetchtest.ModuleHash(fetchtest.H1("zip==")),
		fetchtest.Status(domain.Verified),
		fetchtest.FetchedAt(at(1)),
		fetchtest.SumDBCheck(domain.LegRechecked, ""),
		fetchtest.VCSCheck(domain.LegRechecked, ""),
	)
	// A later --skip-vcs measurement records no VCS leg at all.
	skippedVCS := fetchtest.Record(t,
		fetchtest.Coordinate(composeCoord),
		fetchtest.ModuleHash(fetchtest.H1("zip==")),
		fetchtest.Status(domain.Verified),
		fetchtest.FetchedAt(at(2)),
		fetchtest.SumDBCheck(domain.LegRechecked, ""),
	)

	got, err := domain.Compose([]domain.FactRecord{withVCS, skippedVCS})
	if err != nil {
		t.Fatalf("Compose: %v", err)
	}
	kinds := map[domain.ValidationLegKind]domain.ValidationLeg{}
	for _, l := range got.Legs {
		kinds[l.Kind] = l
	}
	if _, ok := kinds[domain.LegVCS]; !ok {
		t.Error("the VCS leg an earlier measurement established was lost; composition must union the evidence")
	}
	if _, ok := kinds[domain.LegSumDB]; !ok {
		t.Error("the sumdb leg is missing from the composition")
	}
}

// A leg no measurement performed is ABSENT, which is a different claim from a
// check that ran and answered negatively.
func TestCompose_AbsentLegIsNotReportedAsANegativeResult(t *testing.T) {
	skipped := fetchtest.Record(t,
		fetchtest.Coordinate(composeCoord),
		fetchtest.ModuleHash(fetchtest.H1("zip==")),
		fetchtest.Status(domain.VerifiedBySumDBOnly),
		fetchtest.FetchedAt(at(1)),
		fetchtest.SumDBCheck(domain.LegRechecked, ""),
	)
	got, err := domain.Compose([]domain.FactRecord{skipped})
	if err != nil {
		t.Fatalf("Compose: %v", err)
	}
	for _, l := range got.Legs {
		if l.Kind == domain.LegVCS {
			t.Errorf("a VCS leg was reported (%q) for a run that never performed the check", l.Provenance)
		}
	}
}

// An inherited leg names the record it came from, so the copy is checkable
// against its source. Without the name, "inherited" is an unfalsifiable claim
// sitting on a tamper-evident record.
func TestCompose_InheritedLegNamesItsSource(t *testing.T) {
	source := fetchtest.Record(t,
		fetchtest.Coordinate(composeCoord),
		fetchtest.ModuleHash(fetchtest.H1("zip==")),
		fetchtest.Status(domain.Verified),
		fetchtest.FetchedAt(at(1)),
		fetchtest.VCSCheck(domain.LegRechecked, ""),
	)
	inheritor := fetchtest.Record(t,
		fetchtest.Coordinate(composeCoord),
		fetchtest.ModuleHash(fetchtest.H1("zip==")),
		fetchtest.Status(domain.Verified),
		fetchtest.FetchedAt(at(2)),
		fetchtest.VCSCheck(domain.LegInherited, source.ContentHash),
	)

	legs := domain.RecordLegs(inheritor)
	if len(legs) != 1 {
		t.Fatalf("RecordLegs returned %d legs, want 1", len(legs))
	}
	if legs[0].Provenance != domain.LegInherited {
		t.Errorf("Provenance = %q, want inherited", legs[0].Provenance)
	}
	if legs[0].Source != source.ContentHash {
		t.Errorf("Source = %q, want the source record's content hash %q", legs[0].Source, source.ContentHash)
	}
}

// A coordinate can hold a go.mod-only measurement AND a full one. Composition
// must serve the FULL record even when the shallower one carries the stronger
// verification anchor.
//
// This was wrong when the ledger first shipped. The ordering ran eligibility ->
// anchor strength -> recency with no term for artefact coverage, so a
// go.mod-only record that happened to carry the stronger status was served while
// the zip sat in the store — and a consumer needing source would re-fetch what
// was already held. The write side had always exempted an artefact upgrade from
// the anchor comparison; the read side did not, so the two disagreed about which
// record was authoritative.
func TestCompose_FullRecordOutranksGoModOnlyEvenWithAWeakerAnchor(t *testing.T) {
	shallow := fetchtest.Record(t,
		fetchtest.Coordinate(composeCoord),
		fetchtest.GoModOnly("m"),
		fetchtest.GoModHash(fetchtest.H1("mod==")),
		fetchtest.Status(domain.VerifiedBySumDBOnly), // the STRONGER anchor
		fetchtest.FetchedAt(at(1)),
	)
	full := fetchtest.Record(t,
		fetchtest.Coordinate(composeCoord),
		fetchtest.ModuleHash(fetchtest.H1("zip==")),
		fetchtest.GoModHash(fetchtest.H1("mod==")),
		fetchtest.Status(domain.VerifiedByGoSum), // weaker anchor, MORE artefact
		fetchtest.FetchedAt(at(2)),
	)

	// Both orderings, so the result cannot depend on which was listed first.
	for _, tc := range []struct {
		name    string
		records []domain.FactRecord
	}{
		{"shallow first", []domain.FactRecord{shallow, full}},
		{"full first", []domain.FactRecord{full, shallow}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := domain.Compose(tc.records)
			if err != nil {
				t.Fatalf("Compose: %v", err)
			}
			if got.IsGoModOnly() {
				t.Error("served the go.mod-only measurement while a full record exists; a consumer needing source would re-fetch bytes already held")
			}
			if got.ContentHash != full.ContentHash {
				t.Errorf("served %q, want the full record %q", got.ContentHash, full.ContentHash)
			}
			// The identity must describe the record actually served, not whichever
			// was listed first — the two depths carry different identities.
			wantID, err := domain.ArtefactIdentityOf(got.FactRecord)
			if err != nil {
				t.Fatalf("ArtefactIdentityOf: %v", err)
			}
			if !got.Identity.Equal(wantID) {
				t.Errorf("Identity = %s, does not describe the served record (%s)", got.Identity, wantID)
			}
			if got.Identity.GoModOnly {
				t.Error("Identity reports go.mod-only while serving a full record")
			}
		})
	}
}

// Compose refuses to answer for no records rather than inventing an empty
// composition: absence is the store's answer, not composition's.
func TestCompose_NoRecordsIsAnError(t *testing.T) {
	if _, err := domain.Compose(nil); err == nil {
		t.Error("composing nothing succeeded; absence is the store's answer, not a composition")
	}
}
