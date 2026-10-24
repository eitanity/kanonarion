package domain_test

import (
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/eitanity/kanonarion/internal/coordinate"
	"github.com/eitanity/kanonarion/internal/vuln/domain"
)

const tlID = "GO-2026-0001"

var tlBase = time.Date(2026, 8, 1, 0, 0, 0, 0, time.UTC)

func tlSnap(t *testing.T, version, hash string) domain.DatabaseSnapshot {
	t.Helper()
	s, err := domain.NewDatabaseSnapshot("vuln.go.dev", version, tlBase, hash)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func tlCoord(t *testing.T, path string) coordinate.ModuleCoordinate {
	t.Helper()
	c, err := coordinate.NewModuleCoordinate(path, "v1.0.0")
	if err != nil {
		t.Fatal(err)
	}
	return c
}

type tlRow struct {
	minute   int
	pipeline string
	snap     domain.DatabaseSnapshot
	coverage domain.RecordCoverageStatus
	frame    domain.Rooting
	findings []domain.VulnerabilityFinding
}

func tlRecords(t *testing.T, path string, rows ...tlRow) []domain.VulnerabilityRecord {
	t.Helper()
	out := make([]domain.VulnerabilityRecord, 0, len(rows))
	for _, r := range rows {
		cov := r.coverage
		if cov == "" {
			cov = domain.CoverageAnalysed
		}
		frame := r.frame
		if frame == "" {
			frame = domain.RootingIsolated
		}
		out = append(out, domain.VulnerabilityRecord{
			Coordinate: tlCoord(t, path), Rooting: frame, PipelineVersion: r.pipeline,
			DatabaseSnapshot: r.snap, CoverageStatus: cov, Findings: r.findings,
			ScannedAt:   tlBase.Add(time.Duration(r.minute) * time.Minute),
			ContentHash: fmt.Sprintf("sha256:%s-%04d", path, r.minute),
		})
	}
	return out
}

func tlReach(reachable bool) domain.VulnerabilityFinding {
	return domain.VulnerabilityFinding{ID: tlID, Reachable: &domain.ReachabilityResult{IsReachable: reachable, Confidence: domain.ConfidenceHigh}}
}

func tlNoReach() domain.VulnerabilityFinding { return domain.VulnerabilityFinding{ID: tlID} }

func tlWithdrawn() domain.VulnerabilityFinding {
	return domain.VulnerabilityFinding{ID: tlID, WithdrawnAt: withdrawnAt}
}

// tlCheck answers held/lists from fixed values and fails the test when told it
// must not be consulted.
func tlCheck(t *testing.T, held, lists, forbid bool) domain.SnapshotAdvisoryCheck {
	t.Helper()
	return func(domain.DatabaseSnapshot, string) (bool, bool, error) {
		if forbid {
			t.Error("the snapshot check was consulted")
		}
		return held, lists, nil
	}
}

func oneTimeline(t *testing.T, recs []domain.VulnerabilityRecord, check domain.SnapshotAdvisoryCheck) domain.FindingTimeline {
	t.Helper()
	tls, err := domain.BuildFindingTimelines(tlID, recs, check)
	if err != nil {
		t.Fatal(err)
	}
	if len(tls) != 1 {
		t.Fatalf("got %d timelines, want 1", len(tls))
	}
	return tls[0]
}

// Every reason, and the precedence between them, is decided by the pair alone.
func TestBuildFindingTimelines_ReasonPrecedence(t *testing.T) {
	t.Parallel()
	a := tlSnap(t, "2026-08-01T00:00:00Z", "sha256:"+strings.Repeat("a", 64))
	unsealed := tlSnap(t, "2026-07-01T00:00:00Z", "")
	nr := []domain.VulnerabilityFinding(nil)
	for _, tc := range []struct {
		name        string
		earlier     tlRow
		later       tlRow
		check       domain.SnapshotAdvisoryCheck
		want        domain.TimelineReason
		withdrawnAt time.Time
	}{
		{"withdrawn", tlRow{findings: nr}, tlRow{findings: []domain.VulnerabilityFinding{tlWithdrawn()}}, nil, domain.ReasonWithdrawn, withdrawnAt},
		{"withdrawn beats coverage-lost", tlRow{findings: nr}, tlRow{coverage: domain.CoverageFailedScan, findings: []domain.VulnerabilityFinding{tlWithdrawn()}}, nil, domain.ReasonWithdrawn, withdrawnAt},
		{"reachability-corrected", tlRow{findings: []domain.VulnerabilityFinding{tlReach(true)}}, tlRow{findings: []domain.VulnerabilityFinding{tlReach(false)}}, nil, domain.ReasonReachabilityCorrected, time.Time{}},
		{"coverage-lost beats reachability-corrected: Failed", tlRow{findings: []domain.VulnerabilityFinding{tlReach(true)}}, tlRow{coverage: domain.CoverageFailedScan, findings: []domain.VulnerabilityFinding{tlNoReach()}}, nil, domain.ReasonCoverageLost, time.Time{}},
		{"coverage-lost beats reachability-corrected: Unscannable", tlRow{findings: []domain.VulnerabilityFinding{tlReach(true)}}, tlRow{coverage: domain.CoverageUnscannable, findings: []domain.VulnerabilityFinding{tlNoReach()}}, nil, domain.ReasonCoverageLost, time.Time{}},
		{"coverage-lost", tlRow{findings: []domain.VulnerabilityFinding{tlReach(true)}}, tlRow{coverage: domain.CoverageFailedScan, findings: nr}, nil, domain.ReasonCoverageLost, time.Time{}},
		{"coverage-lost beats advisory-added", tlRow{snap: a, findings: nr}, tlRow{coverage: domain.CoverageFailedScan, findings: []domain.VulnerabilityFinding{tlNoReach()}}, tlCheck(t, true, false, true), domain.ReasonCoverageLost, time.Time{}},
		{"advisory-added: earlier snapshot held and does not list it", tlRow{snap: a, findings: nr}, tlRow{findings: []domain.VulnerabilityFinding{tlReach(true)}}, tlCheck(t, true, false, false), domain.ReasonAdvisoryAdded, time.Time{}},
		{"unattributed: earlier snapshot held and lists it", tlRow{snap: a, findings: nr}, tlRow{findings: []domain.VulnerabilityFinding{tlReach(true)}}, tlCheck(t, true, true, false), domain.ReasonUnattributed, time.Time{}},
		{"unattributed: earlier snapshot not held", tlRow{snap: a, findings: nr}, tlRow{findings: []domain.VulnerabilityFinding{tlReach(true)}}, tlCheck(t, false, false, false), domain.ReasonUnattributed, time.Time{}},
		{"unattributed: earlier snapshot names no hash", tlRow{snap: unsealed, findings: nr}, tlRow{findings: []domain.VulnerabilityFinding{tlReach(true)}}, tlCheck(t, true, false, true), domain.ReasonUnattributed, time.Time{}},
		{"unattributed: earlier record names no snapshot", tlRow{findings: nr}, tlRow{findings: []domain.VulnerabilityFinding{tlReach(true)}}, tlCheck(t, true, false, true), domain.ReasonUnattributed, time.Time{}},
		{"unattributed: reported to not reported, analysed", tlRow{findings: []domain.VulnerabilityFinding{tlReach(true)}}, tlRow{findings: nr}, nil, domain.ReasonUnattributed, time.Time{}},
		{"unattributed: withdrawn to reported", tlRow{findings: []domain.VulnerabilityFinding{tlWithdrawn()}}, tlRow{findings: []domain.VulnerabilityFinding{tlReach(true)}}, nil, domain.ReasonUnattributed, time.Time{}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			tc.earlier.minute, tc.later.minute = 1, 2
			tc.earlier.pipeline, tc.later.pipeline = "v1", "v1"
			tl := oneTimeline(t, tlRecords(t, "example.com/m", tc.earlier, tc.later), tc.check)
			if len(tl.Entries) != 1 {
				t.Fatalf("got %d entries, want 1: %+v", len(tl.Entries), tl.Entries)
			}
			e := tl.Entries[0]
			if e.Kind != domain.TimelineChange || e.Reason != tc.want || !e.WithdrawnAt.Equal(tc.withdrawnAt) {
				t.Errorf("got %s/%s withdrawn_at %v, want change/%s %v", e.Kind, e.Reason, e.WithdrawnAt, tc.want, tc.withdrawnAt)
			}
		})
	}
}

// Consecutive records in one state are one entry, whatever their number.
func TestBuildFindingTimelines_CollapsesRepeats(t *testing.T) {
	t.Parallel()
	r := []domain.VulnerabilityFinding{tlReach(true)}
	tl := oneTimeline(t, tlRecords(t, "example.com/m",
		tlRow{minute: 1, pipeline: "v1", findings: r}, tlRow{minute: 2, pipeline: "v1", findings: r},
		tlRow{minute: 3, pipeline: "v1", findings: r}, tlRow{minute: 4, pipeline: "v1"},
		tlRow{minute: 5, pipeline: "v1"}), nil)
	if tl.RecordCount != 5 || len(tl.Entries) != 1 || tl.State.String() != "not reported" {
		t.Fatalf("got %d records, %d entries, state %s; want 5, 1, not reported", tl.RecordCount, len(tl.Entries), tl.State)
	}
	if got := tl.Entries[0].FromRecord.ScannedAt; !got.Equal(tlBase.Add(3 * time.Minute)) {
		t.Errorf("from record %v, want the third record", got)
	}
	nl := tl.NoLongerReported
	if nl == nil || !nl.Established || nl.Reason != domain.ReasonUnattributed || !nl.Record.ScannedAt.Equal(tlBase.Add(4*time.Minute)) {
		t.Errorf("no longer reported = %+v, want established at the fourth record", nl)
	}
}

// Two frames are two timelines: a not-reported record in one frame never pairs
// with a reported one in another, and a frame that never carries the advisory
// is not listed.
func TestBuildFindingTimelines_FrameBoundary(t *testing.T) {
	t.Parallel()
	r := []domain.VulnerabilityFinding{tlReach(true)}
	x, y, z := domain.Rooting("target-rooted:x@local"), domain.Rooting("target-rooted:y@local"), domain.Rooting("target-rooted:z@local")
	recs := tlRecords(t, "example.com/b",
		tlRow{minute: 1, pipeline: "v1", frame: x}, tlRow{minute: 2, pipeline: "v1", frame: y, findings: r},
		tlRow{minute: 3, pipeline: "v1", frame: x}, tlRow{minute: 4, pipeline: "v1", frame: y, findings: r},
		tlRow{minute: 5, pipeline: "v1", frame: z})
	recs = append(recs, tlRecords(t, "example.com/a", tlRow{minute: 6, pipeline: "v1", frame: x, findings: r})...)
	tls, err := domain.BuildFindingTimelines(tlID, recs, nil)
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, tl := range tls {
		got = append(got, fmt.Sprintf("%s %s %d %d", tl.Coordinate.Path(), tl.Rooting, tl.RecordCount, len(tl.Entries)))
	}
	want := []string{"example.com/a target-rooted:x@local 1 0", "example.com/b target-rooted:y@local 2 0"}
	if fmt.Sprint(got) != fmt.Sprint(want) {
		t.Errorf("got %q, want %q", got, want)
	}
}

// A pair across pipeline versions is annotated, never a change, and sets
// neither boundary.
func TestBuildFindingTimelines_GenerationDisagreement(t *testing.T) {
	t.Parallel()
	tl := oneTimeline(t, tlRecords(t, "example.com/m",
		tlRow{minute: 1, pipeline: "v1"},
		tlRow{minute: 2, pipeline: "v2", findings: []domain.VulnerabilityFinding{tlReach(false)}},
		tlRow{minute: 3, pipeline: "v3"}), tlCheck(t, true, false, true))
	if len(tl.Entries) != 2 {
		t.Fatalf("got %d entries, want 2", len(tl.Entries))
	}
	for _, e := range tl.Entries {
		if e.Kind != domain.TimelineGenerationDisagreement || e.Reason != "" {
			t.Errorf("entry %+v, want a generation-disagreement with no reason", e)
		}
	}
	if fr := tl.FirstReported; fr == nil || !fr.AtOrBefore || fr.Previous != nil {
		t.Errorf("first reported = %+v, want at or before", fr)
	}
	if nl := tl.NoLongerReported; nl == nil || nl.Established || nl.EntryKind != domain.TimelineGenerationDisagreement {
		t.Errorf("no longer reported = %+v, want not established, by a generation disagreement", nl)
	}
}

// The earliest live report is "at or before" its record unless an analysed
// record of the same generation, just before it, did not report it.
func TestBuildFindingTimelines_FirstReported(t *testing.T) {
	t.Parallel()
	r := []domain.VulnerabilityFinding{tlReach(true)}
	for _, tc := range []struct {
		name       string
		rows       []tlRow
		atOrBefore bool
		previous   bool
	}{
		{"earliest record reports it", []tlRow{{minute: 1, pipeline: "v1", findings: r}}, true, false},
		{"analysed predecessor of the same generation", []tlRow{{minute: 1, pipeline: "v1"}, {minute: 2, pipeline: "v1", findings: r}}, false, true},
		{"failed predecessor bounds nothing", []tlRow{{minute: 1, pipeline: "v1", coverage: domain.CoverageFailedScan}, {minute: 2, pipeline: "v1", findings: r}}, true, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			fr := oneTimeline(t, tlRecords(t, "example.com/m", tc.rows...), tlCheck(t, false, false, false)).FirstReported
			if fr == nil || fr.AtOrBefore != tc.atOrBefore || (fr.Previous != nil) != tc.previous {
				t.Errorf("first reported = %+v, want at_or_before %v, previous %v", fr, tc.atOrBefore, tc.previous)
			}
		})
	}
	withdrawnOnly := oneTimeline(t, tlRecords(t, "example.com/m", tlRow{minute: 1, pipeline: "v1", findings: []domain.VulnerabilityFinding{tlWithdrawn()}}), nil)
	if withdrawnOnly.FirstReported != nil || withdrawnOnly.NoLongerReported != nil {
		t.Errorf("a withdrawn-only stream reports boundaries: %+v", withdrawnOnly)
	}
}

// A coverage loss ends the reports without establishing that they ended.
func TestBuildFindingTimelines_CoverageLostIsNotNoLongerReported(t *testing.T) {
	t.Parallel()
	tl := oneTimeline(t, tlRecords(t, "example.com/m",
		tlRow{minute: 1, pipeline: "v1", findings: []domain.VulnerabilityFinding{tlReach(true)}},
		tlRow{minute: 2, pipeline: "v1", coverage: domain.CoverageFailedScan}), nil)
	if nl := tl.NoLongerReported; nl == nil || nl.Established || nl.Reason != domain.ReasonCoverageLost {
		t.Errorf("no longer reported = %+v, want not established, coverage-lost", nl)
	}
}

func TestBuildFindingTimelines_SnapshotCheckErrorStops(t *testing.T) {
	t.Parallel()
	boom := errors.New("index unreadable")
	_, err := domain.BuildFindingTimelines(tlID, tlRecords(t, "example.com/m",
		tlRow{minute: 1, pipeline: "v1", snap: tlSnap(t, "2026-08-01T00:00:00Z", "sha256:"+strings.Repeat("a", 64))},
		tlRow{minute: 2, pipeline: "v1", findings: []domain.VulnerabilityFinding{tlReach(true)}}),
		func(domain.DatabaseSnapshot, string) (bool, bool, error) { return false, false, boom })
	if !errors.Is(err, boom) {
		t.Fatalf("err = %v, want the check's error", err)
	}
}

// An alias names the advisory, a live match outranks a withdrawn one in the
// same record, and records scanned at the same instant order by content hash.
func TestBuildFindingTimelines_MatchingAndOrder(t *testing.T) {
	t.Parallel()
	alias := domain.VulnerabilityFinding{ID: "GO-OTHER", Aliases: []string{tlID}, Reachable: &domain.ReachabilityResult{IsReachable: true, Confidence: domain.ConfidenceHigh}}
	recs := tlRecords(t, "example.com/m",
		tlRow{minute: 1, pipeline: "v1", findings: []domain.VulnerabilityFinding{{ID: "GO-UNRELATED"}, tlWithdrawn(), tlWithdrawn(), alias}},
		tlRow{minute: 2, pipeline: "v1", findings: []domain.VulnerabilityFinding{tlWithdrawn(), tlWithdrawn()}})
	tied := recs[1]
	tied.ContentHash = "sha256:0"
	tied.ScannedAt = recs[0].ScannedAt
	tl := oneTimeline(t, []domain.VulnerabilityRecord{recs[0], tied}, nil)
	if tl.State.String() != "reported (reachable)" || len(tl.Entries) != 1 || tl.Entries[0].From.String() != "withdrawn" {
		t.Errorf("got state %s entries %+v; want the tied record ordered first, withdrawn -> reported (reachable)", tl.State, tl.Entries)
	}
}

func TestTimelineState_String(t *testing.T) {
	t.Parallel()
	nd := domain.StateNotAnalysed
	for want, s := range map[string]domain.TimelineState{
		"not reported":            {Kind: domain.TimelineNotReported},
		"withdrawn":               {Kind: domain.TimelineWithdrawn},
		"reported (not_analysed)": {Kind: domain.TimelineReported, Reachability: &nd},
	} {
		if got := s.String(); got != want {
			t.Errorf("String() = %q, want %q", got, want)
		}
	}
}
