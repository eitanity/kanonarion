package store_test

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/eitanity/kanonarion/internal/coordinate"
	"github.com/eitanity/kanonarion/internal/gotoolchain"
	"github.com/eitanity/kanonarion/internal/local/adapters/vulnfindings/store"
	"github.com/eitanity/kanonarion/internal/local/ports"
	vulndomain "github.com/eitanity/kanonarion/internal/vuln/domain"
	vulnports "github.com/eitanity/kanonarion/internal/vuln/ports"
)

const (
	newestWalk = "01JS0NGARD0000000000000NW1"
	anchorNote = `walk "01JS0NGARD0000000000000NW1" (code scope, frame target-rooted:example.com/app@local)`
)

// upgradedStore is the store after a Go upgrade: the tree's frame holds an
// older record under one toolchain and a newer one under another, and they
// disagree. Only the newer is in the newest walk.
func upgradedStore(t *testing.T, coord coordinate.ModuleCoordinate) *fakeVulnStore {
	t.Helper()
	own := rootedAt(t, probedTree)
	older := record(coord, recordSpec{rooting: own, scannedAt: time.Date(2026, 9, 12, 0, 0, 0, 0, time.UTC)})
	older.Toolchain, older.ContentHash, older.WalkID = gotoolchain.Version("go1.26.5"), "sha256:old", "01JS0NGARD0000000000000OW1"
	older.OverallStatus = vulndomain.StatusClean
	newer := record(coord, recordSpec{
		rooting: own, scannedAt: time.Date(2026, 10, 11, 0, 0, 0, 0, time.UTC),
		findings: []vulndomain.VulnerabilityFinding{reachableFinding("GO-2026-0001", true, own)},
	})
	newer.Toolchain, newer.ContentHash, newer.WalkID = gotoolchain.Version("go1.27.2"), "sha256:new", newestWalk
	newer.OverallStatus = vulndomain.StatusAffected
	return &fakeVulnStore{
		records: map[string][]vulndomain.VulnerabilityRecord{coord.Path(): {older, newer}},
		inWalk:  map[string]map[string][]vulndomain.VulnerabilityRecord{newestWalk: {coord.Path(): {newer}}},
	}
}

func anchoredLoad(t *testing.T, s *fakeVulnStore, anchor store.WalkAnchor, coords ...coordinate.ModuleCoordinate) (ports.FindingSet, error) {
	t.Helper()
	set, err := store.New(s, "v1").WithWalkAnchor(anchor).LoadFindings(context.Background(), coords, probedTree)
	return set, err //nolint:wrapcheck // the test reads it as returned
}

func newestAnchor(t *testing.T) store.WalkAnchor {
	t.Helper()
	return store.WalkAnchor{WalkID: newestWalk, Rooting: rootedAt(t, probedTree), Source: anchorNote}
}

// Composing the whole frame refuses on the two toolchains; seeding from the
// newest walk serves its record and says which walk it was.
func TestLoadFindings_AnchoredSeedReadsOnlyTheNewestWalk(t *testing.T) {
	coord := mustCoord(t, "example.com/dep", "v1.0.0")
	s := upgradedStore(t, coord)

	if _, err := store.New(s, "v1").LoadFindings(context.Background(), []coordinate.ModuleCoordinate{coord}, probedTree); err == nil {
		t.Fatal("the frame-wide seed composed two disagreeing toolchains; the fixture no longer reproduces the refusal")
	}

	set, err := anchoredLoad(t, s, newestAnchor(t), coord)
	if err != nil {
		t.Fatalf("anchored LoadFindings: %v", err)
	}
	if got := set.Findings[coord]; len(got) != 1 || got[0].Reachable == nil || !*got[0].Reachable {
		t.Errorf("findings = %+v, want the newest walk's reachable finding", got)
	}
	if !strings.Contains(set.Restriction, anchorNote) || !strings.Contains(set.Restriction, "records of older walks") {
		t.Errorf("Restriction = %q, want it to name the walk and what it left out", set.Restriction)
	}
}

// A coordinate the newest walk did not scan is uncovered, and the reason says
// which absence it is: held by other walks, superseded, or never scanned.
func TestLoadFindings_AnchoredAbsenceNamesItsReason(t *testing.T) {
	inOld := mustCoord(t, "example.com/dep", "v1.0.0")
	superseded := mustCoord(t, "example.com/stale", "v1.0.0")
	never := mustCoord(t, "example.com/never", "v1.0.0")
	s := upgradedStore(t, inOld)
	s.inWalk = map[string]map[string][]vulndomain.VulnerabilityRecord{newestWalk: {}}
	s.generations = map[string][]vulnports.VulnerabilityRecordGeneration{
		superseded.Path(): {{PipelineVersion: "v0"}},
	}

	set, err := anchoredLoad(t, s, newestAnchor(t), inOld, superseded, never)
	if err != nil {
		t.Fatalf("anchored LoadFindings: %v", err)
	}
	if _, ok := set.NotInSeedWalk[inOld]; !ok {
		t.Errorf("a coordinate other walks scanned is not marked NotInSeedWalk: %+v", set)
	}
	if _, ok := set.SupersededOnly[superseded]; !ok {
		t.Errorf("a superseded-only coordinate is not marked SupersededOnly: %+v", set)
	}
	for _, c := range []coordinate.ModuleCoordinate{superseded, never} {
		if _, ok := set.NotInSeedWalk[c]; ok {
			t.Errorf("%s marked NotInSeedWalk, though no walk holds it at this pipeline version", c)
		}
	}
	if len(set.Scanned) != 0 {
		t.Errorf("Scanned = %v, want nothing: the newest walk holds no record", set.Scanned)
	}
}

// Unanchored, an empty read is never NotInSeedWalk: there is no seed walk.
func TestLoadFindings_UnanchoredAbsenceIsNeverNotInSeedWalk(t *testing.T) {
	coord := mustCoord(t, "example.com/dep", "v1.0.0")
	set := loadOne(t, &fakeVulnStore{}, coord)
	if len(set.NotInSeedWalk) != 0 {
		t.Errorf("NotInSeedWalk = %v without an anchor", set.NotInSeedWalk)
	}
}

// A walk whose record is gone has no frame; the seed then takes the tree's own
// frame from the walk's records, as the frame-wide seed would.
func TestLoadFindings_FramelessAnchorTakesTheTreesFrame(t *testing.T) {
	coord := mustCoord(t, "example.com/dep", "v1.0.0")
	s := upgradedStore(t, coord)
	other := rootedAt(t, otherConsumer)
	otherRec := record(coord, recordSpec{rooting: other,
		findings: []vulndomain.VulnerabilityFinding{reachableFinding("GO-2026-0002", true, other)}})
	s.inWalk[newestWalk][coord.Path()] = append(s.inWalk[newestWalk][coord.Path()], otherRec)

	set, err := anchoredLoad(t, s, store.WalkAnchor{WalkID: newestWalk, Source: "walk " + newestWalk}, coord)
	if err != nil {
		t.Fatalf("anchored LoadFindings: %v", err)
	}
	if got := set.Findings[coord]; len(got) != 1 || got[0].ID != "GO-2026-0001" {
		t.Errorf("findings = %+v, want the tree's own record and not the other consumer's", got)
	}
}

// A failed in-walk read fails the load, naming the coordinate.
func TestLoadFindings_AnchoredStoreErrorPropagates(t *testing.T) {
	coord := mustCoord(t, "example.com/dep", "v1.0.0")
	s := upgradedStore(t, coord)
	s.err = errors.New("disk on fire")
	if _, err := anchoredLoad(t, s, newestAnchor(t), coord); err == nil || !strings.Contains(err.Error(), coord.String()) {
		t.Errorf("err = %v, want the store error naming %s", err, coord)
	}
}

// A failed or unscannable record that found nothing is not a clean answer: the
// coordinate is not covered. One that found something still carries it, and a
// record stating nothing about coverage is not read as a failure.
func TestLoadFindings_NotAnalysedRecordIsNotCoverage(t *testing.T) {
	failed := mustCoord(t, "example.com/failed", "v1.0.0")
	unscannable := mustCoord(t, "example.com/unscannable", "v1.0.0")
	failedWithFinding := mustCoord(t, "example.com/failedfound", "v1.0.0")
	silent := mustCoord(t, "example.com/silent", "v1.0.0")
	own := rootedAt(t, probedTree)
	mk := func(c coordinate.ModuleCoordinate, status vulndomain.VulnerabilityStatus, findings ...vulndomain.VulnerabilityFinding) vulndomain.VulnerabilityRecord {
		r := record(c, recordSpec{rooting: own, findings: findings})
		r.OverallStatus = status
		return r
	}
	s := &fakeVulnStore{records: map[string][]vulndomain.VulnerabilityRecord{
		failed.Path():            {mk(failed, vulndomain.StatusScanFailed)},
		unscannable.Path():       {mk(unscannable, vulndomain.StatusUnscannable)},
		failedWithFinding.Path(): {mk(failedWithFinding, vulndomain.StatusScanFailed, reachableFinding("GO-2026-0001", true, own))},
		silent.Path():            {mk(silent, "")},
	}}
	set, err := store.New(s, "v1").LoadFindings(context.Background(),
		[]coordinate.ModuleCoordinate{failed, unscannable, failedWithFinding, silent}, probedTree)
	if err != nil {
		t.Fatalf("LoadFindings: %v", err)
	}
	for _, c := range []coordinate.ModuleCoordinate{failed, unscannable} {
		if _, ok := set.NotAnalysed[c]; !ok {
			t.Errorf("%s not marked NotAnalysed", c)
		}
		if _, ok := set.Scanned[c]; ok {
			t.Errorf("%s counted as covered by a scan that did not analyse it", c)
		}
	}
	for _, c := range []coordinate.ModuleCoordinate{failedWithFinding, silent} {
		if _, ok := set.Scanned[c]; !ok {
			t.Errorf("%s not counted as covered", c)
		}
	}
	if len(set.Findings[failedWithFinding]) != 1 {
		t.Errorf("a failed scan's finding was dropped: %+v", set.Findings)
	}
}

// When no walk of the tree has a completed scan, the anchored walk answers for
// nothing, and every empty read says the scan did not complete — never that the
// walk holds no record, nor that the module was superseded or never scanned.
func TestLoadFindings_AnIncompleteScanIsTheReasonForEveryAbsence(t *testing.T) {
	inOld := mustCoord(t, "example.com/dep", "v1.0.0")
	superseded := mustCoord(t, "example.com/stale", "v1.0.0")
	never := mustCoord(t, "example.com/never", "v1.0.0")
	s := upgradedStore(t, inOld)
	s.inWalk = map[string]map[string][]vulndomain.VulnerabilityRecord{newestWalk: {}}
	s.generations = map[string][]vulnports.VulnerabilityRecordGeneration{
		superseded.Path(): {{PipelineVersion: "v0"}},
	}
	anchor := newestAnchor(t)
	anchor.ScanIncomplete = true

	set, err := anchoredLoad(t, s, anchor, inOld, superseded, never)
	if err != nil {
		t.Fatalf("anchored LoadFindings: %v", err)
	}
	for _, c := range []coordinate.ModuleCoordinate{inOld, superseded, never} {
		if _, ok := set.ScanIncomplete[c]; !ok {
			t.Errorf("%s is not marked ScanIncomplete: %+v", c, set)
		}
	}
	if len(set.NotInSeedWalk) != 0 || len(set.SupersededOnly) != 0 {
		t.Errorf("another reason was given beside the incomplete scan: %+v", set)
	}
	if !strings.Contains(set.Restriction, anchorNote) || !strings.Contains(set.Restriction, "did not complete") {
		t.Errorf("Restriction = %q, want it to name the walk and say its scan did not complete", set.Restriction)
	}
}

// A newer walk whose scan did not complete is named in the seed line ahead of
// the walk the seed came from.
func TestLoadFindings_APassedOverWalkIsNamed(t *testing.T) {
	coord := mustCoord(t, "example.com/dep", "v1.0.0")
	s := upgradedStore(t, coord)
	anchor := newestAnchor(t)
	anchor.PassedOver = `walk "01JS0NGARD0000000000000IN1"'s vuln-scan did not complete`

	set, err := anchoredLoad(t, s, anchor, coord)
	if err != nil {
		t.Fatalf("anchored LoadFindings: %v", err)
	}
	if !strings.HasPrefix(set.Restriction, anchor.PassedOver+"; seeded from "+anchorNote) {
		t.Errorf("Restriction = %q, want the passed-over walk then the seed walk", set.Restriction)
	}
	if _, ok := set.Scanned[coord]; !ok {
		t.Errorf("the seed walk's record did not cover %s: %+v", coord, set)
	}
}
