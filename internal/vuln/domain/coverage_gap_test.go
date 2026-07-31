package domain

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/eitanity/kanonarion/internal/coordinate/coordinatetest"
	fetchdomain "github.com/eitanity/kanonarion/internal/fetch/domain"
)

// The tests in this file pin the refusals and last-resort tie-breaks the
// vulnerability domain reaches only on values a healthy pipeline does not
// produce: a snapshot whose retrieval time cannot be encoded, a persisted
// snapshot that cannot be read back, and the rung of the serving order that two
// measurements consult only when they claim the same retrieval instant. They
// live in the internal test package so the value objects can be built without
// routing through vulntest, which imports the package under test.

// gapUnencodableTime is outside the range RFC3339 can spell, so encoding a
// snapshot carrying it fails inside time.Time's own marshaller. It is the one
// real value that makes the never-silent marshal guards on this type answer,
// which is why they are exercised with it rather than with a seam.
var gapUnencodableTime = time.Date(10000, 1, 1, 0, 0, 0, 0, time.UTC)

// gapSnapshot builds a snapshot fixture, failing the test rather than the
// assertion when the fixture itself is invalid.
func gapSnapshot(t *testing.T, source, version string, retrievedAt time.Time) DatabaseSnapshot {
	t.Helper()
	s, err := NewDatabaseSnapshot(source, version, retrievedAt, "")
	if err != nil {
		t.Fatalf("building fixture snapshot %s@%s: %v", source, version, err)
	}
	return s
}

// Two snapshots can claim the same retrieval instant — a store fetched twice
// within one clock reading, or two rows whose time was recorded at coarse
// precision — and when they do, the instant cannot order them. The database's own
// generation label is the only remaining statement about which is later, so it
// decides ahead of the scan time: falling through to recency would let the older
// advisory database win purely because the machine ran it again.
func TestCompose_SnapshotVersionDecidesWhenTheRetrievalInstantCannot(t *testing.T) {
	retrievedAt := time.Date(2026, 7, 1, 12, 0, 0, 0, time.UTC)
	base := func(version string, scannedAt time.Time, hash string) VulnerabilityRecord {
		return VulnerabilityRecord{
			Ecosystem:             fetchdomain.EcosystemGo,
			Coordinate:            coordinatetest.MustNew("example.com/mod", "v1.0.0"),
			CoverageStatus:        CoverageAnalysed,
			FindingsStatus:        FindingsRecordClean,
			OverallStatus:         StatusClean,
			CallGraphCompleteness: "BUILT_WITH_BODIES",
			DatabaseSnapshot:      gapSnapshot(t, "osv", version, retrievedAt),
			ScannedAt:             scannedAt,
			ContentHash:           hash,
		}
	}
	// The record with the LATER generation label was scanned first, so every rung
	// below the version — recency, then the content hash — would serve the other
	// one. Only the version rung can produce this answer.
	laterGeneration := base("2026-07-02", time.Date(2026, 7, 1, 13, 0, 0, 0, time.UTC), "sha256:zzz")
	earlierGeneration := base("2026-07-01", time.Date(2026, 7, 5, 13, 0, 0, 0, time.UTC), "sha256:aaa")

	for _, tt := range []struct {
		name    string
		records []VulnerabilityRecord
	}{
		{"earlier generation first", []VulnerabilityRecord{earlierGeneration, laterGeneration}},
		{"later generation first", []VulnerabilityRecord{laterGeneration, earlierGeneration}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			got, err := Compose(tt.records)
			if err != nil {
				t.Fatalf("Compose: %v", err)
			}
			if got.ContentHash != laterGeneration.ContentHash {
				t.Errorf("served the record at snapshot version %q, want the later generation %q",
					got.DatabaseSnapshot.Version(), laterGeneration.DatabaseSnapshot.Version())
			}
		})
	}
}

// A run whose bytes cannot be encoded is reported, never persisted as a partial
// blob. The run's seal is computed over exactly these bytes, so a marshal that
// failed and was ignored would leave the store holding a run whose content hash
// describes something other than its contents — an unverifiable row that reads
// back as a genuine scan of a walk.
func TestWalkScanRunHasher_Marshal_ReportsAnUnencodableRun(t *testing.T) {
	run := WalkScanRun{
		ID:       "run-1",
		WalkID:   "walk-1",
		Snapshot: gapSnapshot(t, "osv", "2026-07-01", gapUnencodableTime),
	}

	got, err := WalkScanRunHasher{}.Marshal(run)
	if err == nil {
		t.Fatalf("Marshal encoded a run whose snapshot carries an unrepresentable retrieval time: %s", got)
	}
	if !strings.Contains(err.Error(), "walk scan run") {
		t.Errorf("error = %q, want it to name the walk scan run it was marshalling", err.Error())
	}
	if got != nil {
		t.Errorf("Marshal returned %d bytes alongside its error; a failed encoding has no bytes to persist", len(got))
	}
}

// A snapshot whose retrieval time cannot be spelled is reported by the snapshot's
// own marshaller, naming the snapshot. Two records and a walk run embed this
// value and seal themselves over its bytes, so an encoding failure that answered
// with an empty object would silently narrow every one of them to a snapshot that
// names no database.
func TestDatabaseSnapshot_MarshalJSON_ReportsAnUnrepresentableRetrievalTime(t *testing.T) {
	s := gapSnapshot(t, "osv", "2026-07-01", gapUnencodableTime)

	got, err := s.MarshalJSON()
	if err == nil {
		t.Fatalf("MarshalJSON encoded an unrepresentable retrieval time as %s", got)
	}
	if !strings.Contains(err.Error(), "osv") {
		t.Errorf("error = %q, want it to name the snapshot it was marshalling", err.Error())
	}
}

// Bytes that are not a snapshot object are an error rather than a zero snapshot.
// UnmarshalJSON deliberately admits the zero snapshot for records written before
// the invariants existed, which is exactly why unreadable bytes must not also
// land there: a corrupt column would then be indistinguishable from a scan that
// legitimately recorded no database.
func TestDatabaseSnapshot_UnmarshalJSON_RejectsBytesThatAreNotASnapshot(t *testing.T) {
	var s DatabaseSnapshot
	if err := json.Unmarshal([]byte(`"osv@2026-07-01"`), &s); err == nil {
		t.Fatalf("UnmarshalJSON accepted a bare string and produced %+v", s)
	} else if !strings.Contains(err.Error(), "database snapshot") {
		t.Errorf("error = %q, want it to name what it was unmarshalling", err.Error())
	}
}

// Sealing is the store's statement about the bytes it holds, so a hash it could
// not have produced is refused rather than stored. A snapshot carrying a hash no
// reader can recompute the shape of is not evidence of anything, and it would sit
// on the record as though it were.
func TestDatabaseSnapshot_WithContentHash_RefusesAHashItCouldNotHaveWritten(t *testing.T) {
	s := gapSnapshot(t, "osv", "2026-07-01", time.Date(2026, 7, 1, 12, 0, 0, 0, time.UTC))

	for _, malformed := range []string{
		"deadbeef",                          // no algorithm label
		"sha256:nothex",                     // labelled, wrong shape
		"sha256:" + strings.Repeat("z", 64), // right length, not hex
	} {
		got, err := s.WithContentHash(malformed)
		if err == nil {
			t.Errorf("WithContentHash(%q) sealed the snapshot as %s", malformed, got)
			continue
		}
		if !strings.Contains(err.Error(), "content hash") {
			t.Errorf("WithContentHash(%q) error = %v, want it to name the content hash", malformed, err)
		}
		if got.ContentHash() != "" {
			t.Errorf("WithContentHash(%q) returned a snapshot sealed against %q after refusing it", malformed, got.ContentHash())
		}
	}
}

// The zero snapshot's own spelling is the empty string, and String has to render
// it as one. ParseDatabaseSnapshot reads back exactly what String emits and
// refuses the empty string with ErrZeroSnapshot, so any other rendering — a bare
// separator run, say — would round-trip the value that names nothing into
// something the parser treats as a malformed database instead.
func TestDatabaseSnapshot_String_TheZeroSnapshotRendersAsTheEmptyString(t *testing.T) {
	if got := (DatabaseSnapshot{}).String(); got != "" {
		t.Errorf("String() = %q for the zero snapshot, want the empty string", got)
	}
	// A snapshot missing either half names nothing either, and renders the same.
	if got := (DatabaseSnapshot{version: "2026-07-01"}).String(); got != "" {
		t.Errorf("String() = %q for a snapshot naming no database, want the empty string", got)
	}
}

// A reachability answer that does not say what produced it cannot be weighed
// against another one, so the analyser has to be readable as "stated" or "not
// stated" rather than compared against the empty string at each call site. The
// unrecorded value means "not recorded", never "no analysis".
func TestReachabilityAnalyser_IsRecorded(t *testing.T) {
	tests := []struct {
		analyser ReachabilityAnalyser
		want     bool
	}{
		{AnalyserUnrecorded, false},
		{AnalyserGovulncheck, true},
		{AnalyserCallGraphBFS, true},
		{ReachabilityAnalyser("some-future-instrument"), true},
	}
	for _, tt := range tests {
		if got := tt.analyser.IsRecorded(); got != tt.want {
			t.Errorf("ReachabilityAnalyser(%q).IsRecorded() = %v, want %v", string(tt.analyser), got, tt.want)
		}
	}
}

// Withdrawn is a findings word, and it reports a MATCHED advisory. Projecting it
// onto Clean would retire the retraction along with the finding: the record
// carrying the reason a module stopped being affected would be ranked with the
// records that never matched anything, and composition would stop serving the one
// row that can explain the transition.
func TestDetermineRecordFindingsStatus_WithdrawnReportsAMatchedAdvisory(t *testing.T) {
	tests := []struct {
		status VulnerabilityStatus
		want   RecordFindingsStatus
	}{
		{StatusAffected, FindingsRecordAffected},
		{StatusWithdrawn, FindingsRecordWithdrawn},
		{StatusClean, FindingsRecordClean},
		{StatusUnscannable, FindingsRecordClean},
		{StatusScanFailed, FindingsRecordClean},
	}
	for _, tt := range tests {
		if got := DetermineRecordFindingsStatus(tt.status); got != tt.want {
			t.Errorf("DetermineRecordFindingsStatus(%q) = %q, want %q", tt.status, got, tt.want)
		}
	}
	// The projection is what reportsAdvisory reads, and that is the rung serving
	// order consults first, so a Withdrawn record must rank with the findings.
	if !reportsAdvisory(DetermineRecordFindingsStatus(StatusWithdrawn)) {
		t.Error("a withdrawn record does not report a matched advisory; the row holding the retraction would rank below records that matched nothing")
	}
}

// An empty analysis surface ladders to fetched rather than reading as a third
// state. Every record written before the field existed came from a run that
// resolved from fetched artefacts — nothing consumed a vendored tree — so
// "fetched" is what those bytes mean, and an "unrecorded" bucket would invite a
// reader to treat a known regime as an unknown one.
func TestRecordAnalysisSurface_AnUnrecordedSurfaceLaddersToFetched(t *testing.T) {
	tests := []struct {
		name  string
		field AnalysisSurface
		want  AnalysisSurface
	}{
		{"written before the field existed", "", AnalysisSurfaceFetched},
		{"stated fetched", AnalysisSurfaceFetched, AnalysisSurfaceFetched},
		{"stated vendored", AnalysisSurfaceVendored, AnalysisSurfaceVendored},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := RecordAnalysisSurface(VulnerabilityRecord{AnalysisSurface: tt.field})
			if got != tt.want {
				t.Errorf("RecordAnalysisSurface(%q) = %q, want %q", tt.field, got, tt.want)
			}
		})
	}
}

// The recency rung of the serving order — reached only when two records agree
// on eligibility, findings, coverage, graph completeness, and BOTH halves of the
// snapshot (its retrieval instant and its generation label). It is the last rung
// that carries a measurement; below it only the content hash remains, and that
// orders bytes rather than answers. A store re-scanned against one pinned
// snapshot lands here on every coordinate, so it is the rung that decides what
// most readers are served.
func TestCompose_ScannedAtDecidesWhenTheSnapshotIsIdentical(t *testing.T) {
	retrievedAt := time.Date(2026, 7, 1, 12, 0, 0, 0, time.UTC)
	base := func(scannedAt time.Time, hash string) VulnerabilityRecord {
		return VulnerabilityRecord{
			Ecosystem:             fetchdomain.EcosystemGo,
			Coordinate:            coordinatetest.MustNew("example.com/mod", "v1.0.0"),
			CoverageStatus:        CoverageAnalysed,
			FindingsStatus:        FindingsRecordClean,
			OverallStatus:         StatusClean,
			CallGraphCompleteness: "BUILT_WITH_BODIES",
			DatabaseSnapshot:      gapSnapshot(t, "osv", "2026-07-01", retrievedAt),
			ScannedAt:             scannedAt,
			ContentHash:           hash,
		}
	}
	// The newer scan carries the content hash that sorts LAST, so the rung below
	// recency would serve the other one. Only the recency rung produces this
	// answer.
	newer := base(time.Date(2026, 7, 5, 13, 0, 0, 0, time.UTC), "sha256:zzz")
	older := base(time.Date(2026, 7, 1, 13, 0, 0, 0, time.UTC), "sha256:aaa")

	for _, tt := range []struct {
		name    string
		records []VulnerabilityRecord
	}{
		{"older first", []VulnerabilityRecord{older, newer}},
		{"newer first", []VulnerabilityRecord{newer, older}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			got, err := Compose(tt.records)
			if err != nil {
				t.Fatalf("Compose: %v", err)
			}
			if got.ContentHash != newer.ContentHash {
				t.Errorf("served the record scanned at %s, want the newer scan at %s",
					got.ScannedAt, newer.ScannedAt)
			}
		})
	}
}

// A seal that excludes a field is stating that the field is not part of the
// record's identity, and the two hashers make opposite statements. The record
// hasher excludes first_scanned_at — a re-measurement that agrees must hash
// identically, and the instant a coordinate was FIRST seen is a property of the
// store's history rather than of the measurement. The run hasher excludes
// nothing.
//
// Neither list is exercised by any other test in this package, and a silently
// emptied one would not fail a single assertion: every record would still seal,
// and the drift would surface only as records that stop verifying against
// generations written before the change.
func TestSealExcludes_TheTwoHashersMakeOppositeStatements(t *testing.T) {
	rec := VulnerabilityRecordHasher{}.SealExcludes()
	if len(rec) != 1 || rec[0] != "first_scanned_at" {
		t.Errorf("VulnerabilityRecordHasher.SealExcludes() = %v, want exactly [first_scanned_at]", rec)
	}
	if run := (WalkScanRunHasher{}).SealExcludes(); run != nil {
		t.Errorf("WalkScanRunHasher.SealExcludes() = %v, want nil: a run seals over every field", run)
	}
}

// The unrecorded analyser renders as "not recorded" rather than as a blank. An
// empty field reads as a missing value in every column it lands in; "not
// recorded" is the fact, and it is the one this String must not lose — the
// answers it labels are exactly those written before the instrument was
// recorded at all.
func TestReachabilityAnalyser_String_NamesTheUnrecordedCase(t *testing.T) {
	for analyser, want := range map[ReachabilityAnalyser]string{
		AnalyserUnrecorded:   "not recorded",
		AnalyserGovulncheck:  string(AnalyserGovulncheck),
		AnalyserCallGraphBFS: string(AnalyserCallGraphBFS),
	} {
		if got := analyser.String(); got != want {
			t.Errorf("ReachabilityAnalyser(%q).String() = %q, want %q", string(analyser), got, want)
		}
	}
}

// "Requested and failed" and "never requested" are the same absence in the
// record — a nil Reachable — and they are not the same fact. Only the note tells
// them apart, and a reader that assumed the second sends an operator who DID ask
// for reachability to ask again, burying the failure the note exists to surface.
func TestReachabilityAttemptFailed_SeparatesAFailedAskFromNoAskAtAll(t *testing.T) {
	answered := &ReachabilityResult{IsReachable: false, Confidence: ConfidenceHigh}
	for _, tt := range []struct {
		name    string
		finding VulnerabilityFinding
		want    bool
	}{
		{
			name:    "requested and failed",
			finding: VulnerabilityFinding{ReachabilityNote: "call graph could not be loaded"},
			want:    true,
		},
		{
			name:    "never requested",
			finding: VulnerabilityFinding{},
		},
		{
			name:    "requested and answered",
			finding: VulnerabilityFinding{Reachable: answered},
		},
		{
			// An answer that also carries a note is an answer. The note explains
			// something about the attempt; it does not retract the result.
			name:    "answered despite a note",
			finding: VulnerabilityFinding{Reachable: answered, ReachabilityNote: "partial graph"},
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.finding.ReachabilityAttemptFailed(); got != tt.want {
				t.Errorf("ReachabilityAttemptFailed() = %v, want %v", got, tt.want)
			}
		})
	}
}
