package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/eitanity/kanonarion/internal/cli/testfakes"
	"github.com/eitanity/kanonarion/internal/coordinate"
	vuldomain "github.com/eitanity/kanonarion/internal/vuln/domain"
	"github.com/eitanity/kanonarion/internal/vuln/vulntest"
)

const timelineID = "GO-2026-0002"

var (
	timelineT0     = time.Date(2026, 8, 1, 0, 0, 0, 0, time.UTC)
	timelineOldDB  = vulntest.MustSealOver("vuln.go.dev", "2026-07-01T00:00:00Z", timelineT0, []byte("old"))
	timelineNewDB  = vulntest.MustSealOver("vuln.go.dev", "2026-08-01T00:00:00Z", timelineT0, []byte("new"))
	timelineFrameA = vuldomain.Rooting("target-rooted:a@local")
)

func timelineRec(coord coordinate.ModuleCoordinate, minute int, pipeline string, snap vuldomain.DatabaseSnapshot,
	coverage vuldomain.RecordCoverageStatus, findings ...vuldomain.VulnerabilityFinding,
) vuldomain.VulnerabilityRecord {
	return vuldomain.VulnerabilityRecord{
		Coordinate: coord, Rooting: timelineFrameA, PipelineVersion: pipeline, DatabaseSnapshot: snap,
		CoverageStatus: coverage, Findings: findings, ScannedAt: timelineT0.Add(time.Duration(minute) * time.Minute),
		ContentHash: fmt.Sprintf("sha256:%s-%02d", coord.Path(), minute),
	}
}

func timelineReached(reachable bool) vuldomain.VulnerabilityFinding {
	return vuldomain.VulnerabilityFinding{ID: timelineID, Reachable: &vuldomain.ReachabilityResult{IsReachable: reachable, Confidence: vuldomain.ConfidenceHigh}}
}

// timelineFixture is one coordinate whose stream exercises a change of each
// kind the text prints, and a second whose records never change. The query
// computes timelines; the CLI only prints them.
func timelineFixture(t *testing.T) *testfakes.FakeQueryVuln {
	t.Helper()
	m := mustVulnCoord(t, "example.com/m", "v1.0.0")
	q := mustVulnCoord(t, "example.com/q", "v1.0.0")
	withdrawn := vuldomain.VulnerabilityFinding{ID: timelineID, WithdrawnAt: time.Date(2026, 8, 18, 20, 22, 49, 0, time.UTC)}
	a := vuldomain.CoverageAnalysed
	recs := []vuldomain.VulnerabilityRecord{
		timelineRec(m, 1, "v1", timelineOldDB, a),
		timelineRec(m, 2, "v1", timelineNewDB, a, timelineReached(true)),
		timelineRec(m, 3, "v2", timelineNewDB, a),
		timelineRec(m, 4, "v2", timelineNewDB, a, timelineReached(true)),
		timelineRec(m, 5, "v2", timelineNewDB, a, timelineReached(false)),
		timelineRec(m, 6, "v2", timelineNewDB, a, withdrawn),
		timelineRec(m, 7, "v2", timelineNewDB, vuldomain.CoverageFailedScan),
		timelineRec(q, 1, "v1", timelineNewDB, a, timelineReached(false)),
	}
	tls, err := vuldomain.BuildFindingTimelines(timelineID, recs, listsOnly)
	if err != nil {
		t.Fatal(err)
	}
	uc := testfakes.NewFakeQueryVuln()
	uc.SetTimelines(tls)
	return uc
}

// listsOnly answers the snapshot check as a store holding only the old
// snapshot, which does not list the advisory.
func listsOnly(s vuldomain.DatabaseSnapshot, _ string) (bool, bool, error) {
	return s.Equal(timelineOldDB), false, nil
}

func TestRunVulnTimeline_Text(t *testing.T) {
	var buf bytes.Buffer
	if err := runVulnTimeline(context.Background(), timelineID, "", false, timelineFixture(t), &buf); err != nil {
		t.Fatal(err)
	}
	want := `example.com/m@v1.0.0  frame target-rooted:a@local  7 record(s)
  first reported: 2026-08-01T00:02:00Z; the analysed record of 2026-08-01T00:01:00Z did not report it
  2026-08-01T00:02:00Z             advisory-added           not reported -> reported (reachable)  pipeline=v1
  2026-08-01T00:03:00Z             generation-disagreement  reported (reachable) -> not reported  pipeline v1 -> v2, not a change
  2026-08-01T00:04:00Z             unattributed             not reported -> reported (reachable)  pipeline=v2
  2026-08-01T00:05:00Z             reachability-corrected   reported (reachable) -> reported (not_reachable)  pipeline=v2
  2026-08-01T00:06:00Z             withdrawn                reported (not_reachable) -> withdrawn  pipeline=v2 withdrawn_at=2026-08-18T20:22:49Z
  2026-08-01T00:07:00Z             coverage-lost            withdrawn -> not reported  pipeline=v2 coverage=Failed, nothing analysed
  no longer reported: 2026-08-01T00:06:00Z (withdrawn)
example.com/q@v1.0.0  frame target-rooted:a@local  no change of state in 1 record(s): reported (not_reachable), first reported at or before 2026-08-01T00:01:00Z
`
	if buf.String() != want {
		t.Errorf("got:\n%s\nwant:\n%s", buf.String(), want)
	}
}

func TestRunVulnTimeline_JSONCarriesTheEntries(t *testing.T) {
	var buf bytes.Buffer
	if err := runVulnTimeline(context.Background(), timelineID, "", true, timelineFixture(t), &buf); err != nil {
		t.Fatal(err)
	}
	var doc struct {
		FindingID string `json:"finding_id"`
		Timelines []struct {
			RecordCount int `json:"record_count"`
			Entries     []struct {
				Kind   string `json:"kind"`
				Reason string `json:"reason"`
			} `json:"entries"`
		} `json:"timelines"`
	}
	if err := json.Unmarshal(buf.Bytes(), &doc); err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, e := range doc.Timelines[0].Entries {
		got = append(got, e.Kind+"/"+e.Reason)
	}
	want := "change/advisory-added generation-disagreement/ change/unattributed change/reachability-corrected change/withdrawn change/coverage-lost"
	if doc.FindingID != timelineID || len(doc.Timelines) != 2 || strings.Join(got, " ") != want {
		t.Errorf("got %s %d timelines %q; want %s 2 %q", doc.FindingID, len(doc.Timelines), got, timelineID, want)
	}
}

func TestRunVulnTimeline_NoModules(t *testing.T) {
	for _, tc := range []struct {
		walk, want string
		json       bool
	}{
		{"", "no modules affected by " + timelineID + "\n", false},
		{"W1", "notice: results restricted to the modules scanned under walk \"W1\"\nno modules in walk W1 affected by " + timelineID + "\n", false},
		{"", "{\n  \"finding_id\": \"" + timelineID + "\",\n  \"timelines\": []\n}\n", true},
	} {
		uc := testfakes.NewFakeQueryVuln()
		var buf bytes.Buffer
		if err := runVulnTimeline(context.Background(), timelineID, tc.walk, tc.json, uc, &buf); err != nil {
			t.Fatal(err)
		}
		if buf.String() != tc.want {
			t.Errorf("got %q, want %q", buf.String(), tc.want)
		}
	}
}

func TestRunVulnTimeline_Errors(t *testing.T) {
	boom := errors.New("boom")
	listFails := testfakes.NewFakeQueryVuln()
	listFails.Err = boom
	if err := runVulnTimeline(context.Background(), timelineID, "", false, listFails, &bytes.Buffer{}); !errors.Is(err, boom) {
		t.Errorf("listing: got %v, want boom", err)
	}
	if err := runVulnTimeline(context.Background(), timelineID, "", true, timelineFixture(t), failingWriter{}); err == nil {
		t.Error("encoding: no error")
	}
}

// The decorator passes the timelines through, and a survivable report with them.
func TestSearchedVulnQuery_FindingTimelinesPassThrough(t *testing.T) {
	inner := timelineFixture(t)
	inner.PartialErr = alteredRecords("example.com/bravo@v2.0.0")
	tls, err := newSearchedVulnQuery(inner, &confirmingSearcher{}).FindingTimelines(context.Background(), timelineID, "W1")
	if _, ok := unreadableRowReport(err); !ok || len(tls) != 2 || inner.ByIDWalkSeen() != "W1" {
		t.Errorf("got %d timelines, %v, walk %q; want 2, the unreadable rows, W1", len(tls), err, inner.ByIDWalkSeen())
	}
	inner.PartialErr = nil
	if _, err := newSearchedVulnQuery(inner, &confirmingSearcher{}).FindingTimelines(context.Background(), timelineID, ""); err != nil {
		t.Errorf("a clean answer returned %v", err)
	}
}

// A row that could not be read is named under the timelines, in both forms.
func TestRunVulnTimeline_NamesUnreadableRows(t *testing.T) {
	uc := timelineFixture(t)
	uc.PartialErr = alteredRecords("example.com/bravo@v2.0.0")
	var text, js bytes.Buffer
	if err := runVulnTimeline(context.Background(), timelineID, "", false, uc, &text); err != nil {
		t.Fatal(err)
	}
	if err := runVulnTimeline(context.Background(), timelineID, "", true, uc, &js); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(text.String(), "a change shown across one may be two") || !strings.Contains(text.String(), "example.com/bravo@v2.0.0") {
		t.Errorf("text does not name the unreadable row:\n%s", text.String())
	}
	if !strings.Contains(js.String(), `"unreadable": [`) {
		t.Errorf("json does not carry the unreadable row:\n%s", js.String())
	}
}

// Generation and coverage end a stream without establishing that it ended.
func TestWriteTimeline_NoLongerReportedNotEstablished(t *testing.T) {
	m := mustVulnCoord(t, "example.com/m", "v1.0.0")
	a := vuldomain.CoverageAnalysed
	for want, recs := range map[string][]vuldomain.VulnerabilityRecord{
		"is another pipeline": {timelineRec(m, 1, "v1", timelineNewDB, a, timelineReached(true)), timelineRec(m, 2, "v2", timelineNewDB, a)},
		"analysed nothing (coverage=Failed)": {timelineRec(m, 1, "v1", timelineNewDB, a, timelineReached(true)),
			timelineRec(m, 2, "v1", timelineNewDB, vuldomain.CoverageFailedScan)},
	} {
		tls, err := vuldomain.BuildFindingTimelines(timelineID, recs, listsOnly)
		if err != nil {
			t.Fatal(err)
		}
		var buf bytes.Buffer
		writeTimeline(&buf, tls[0])
		if !strings.Contains(buf.String(), "no longer reported: not established; the record of 2026-08-01T00:02:00Z "+want) {
			t.Errorf("got:\n%s\nwant a line ending %q", buf.String(), want)
		}
	}
}

func TestVulnByIDCmd_HasTimelineFlag(t *testing.T) {
	if newVulnByIDCmd(&bytes.Buffer{}, &bytes.Buffer{}).Flags().Lookup("timeline") == nil {
		t.Fatal("vuln-by-id has no --timeline flag")
	}
}
