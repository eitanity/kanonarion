package application_test

import (
	"archive/zip"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"strings"
	"testing"
	"testing/iotest"
	"time"

	"github.com/eitanity/kanonarion/internal/adapters/recordseal"
	"github.com/eitanity/kanonarion/internal/coordinate"
	"github.com/eitanity/kanonarion/internal/coordinate/coordinatetest"

	"github.com/eitanity/kanonarion/internal/vuln/application"
	"github.com/eitanity/kanonarion/internal/vuln/domain"
	vulnports "github.com/eitanity/kanonarion/internal/vuln/ports"
	"github.com/eitanity/kanonarion/internal/vuln/vulntest"
)

const tlID = "GO-2026-0002"

var tlT0 = time.Date(2026, 8, 1, 0, 0, 0, 0, time.UTC)

// tlZip is a snapshot body whose index lists ids under one module.
func tlZip(t *testing.T, index string) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	if index != "" {
		w, err := zw.Create("index/modules.json")
		if err != nil {
			t.Fatal(err)
		}
		if _, err := w.Write([]byte(index)); err != nil {
			t.Fatal(err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

// timelineStore answers the four reads the timeline makes; every other method
// is the nil interface and panics if called.
type timelineStore struct {
	vulnports.VulnerabilityStore
	byID       []domain.VulnerabilityRecord
	byIDErr    error
	history    map[string][]domain.VulnerabilityRecord
	historyErr error
	snaps      []domain.DatabaseSnapshot
	snapsErr   error
	blobs      map[string][]byte
	getErr     error
	readBody   io.Reader
	histReads  int
	blobReads  int
}

func (s *timelineStore) ListVulnerabilityRecordsByFindingID(context.Context, string, string) ([]domain.VulnerabilityRecord, error) {
	return s.byID, s.byIDErr
}

func (s *timelineStore) ListCoordinatesByFindingID(context.Context, string, string) ([]coordinate.ModuleCoordinate, error) {
	return coordinatesOf(s.byID), s.byIDErr
}

func (s *timelineStore) ListVulnerabilityRecordsForModuleAllGenerations(_ context.Context, c coordinate.ModuleCoordinate) ([]domain.VulnerabilityRecord, error) {
	s.histReads++
	return s.history[c.String()], s.historyErr
}

func (s *timelineStore) ListDatabaseSnapshots(context.Context) ([]domain.DatabaseSnapshot, error) {
	return s.snaps, s.snapsErr
}

func (s *timelineStore) GetDatabaseSnapshot(_ context.Context, snap domain.DatabaseSnapshot) (io.ReadCloser, error) {
	s.blobReads++
	if s.getErr != nil {
		return nil, s.getErr
	}
	if s.readBody != nil {
		return io.NopCloser(s.readBody), nil
	}
	return io.NopCloser(bytes.NewReader(s.blobs[snap.ContentHash()])), nil
}

func tlRec(c coordinate.ModuleCoordinate, minute int, snap domain.DatabaseSnapshot, findings ...domain.VulnerabilityFinding) domain.VulnerabilityRecord {
	return domain.VulnerabilityRecord{
		Coordinate: c, Rooting: "target-rooted:a@local", PipelineVersion: "v1", DatabaseSnapshot: snap,
		CoverageStatus: domain.CoverageAnalysed, Findings: findings,
		ScannedAt: tlT0.Add(time.Duration(minute) * time.Minute), ContentHash: fmt.Sprintf("sha256:%s-%d", c.Path(), minute),
	}
}

func tlReported() domain.VulnerabilityFinding {
	return domain.VulnerabilityFinding{ID: tlID, Reachable: &domain.ReachabilityResult{IsReachable: true, Confidence: domain.ConfidenceHigh}}
}

// tlFixture holds three coordinates whose earlier snapshot is held without the
// advisory, held with it, and not held: advisory-added, then unattributed twice.
func tlFixture(t *testing.T) *timelineStore {
	t.Helper()
	lacks := tlZip(t, `[{"path":"example.com/x","vulns":[{"id":"GO-2026-0001"}]}]`)
	lists := tlZip(t, `[{"path":"example.com/x","vulns":[{"id":"`+tlID+`"}]}]`)
	snapLacks := vulntest.MustSealOver("vuln.go.dev", "2026-07-01T00:00:00Z", tlT0, lacks)
	snapLists := vulntest.MustSealOver("vuln.go.dev", "2026-07-02T00:00:00Z", tlT0, lists)
	notHeld := vulntest.MustSealOver("vuln.go.dev", "2026-07-03T00:00:00Z", tlT0, []byte("absent"))
	later := vulntest.MustSealOver("vuln.go.dev", "2026-08-01T00:00:00Z", tlT0, []byte("later"))
	s := &timelineStore{
		history: map[string][]domain.VulnerabilityRecord{},
		snaps:   []domain.DatabaseSnapshot{snapLacks, snapLists},
		blobs:   map[string][]byte{snapLacks.ContentHash(): lacks, snapLists.ContentHash(): lists},
	}
	for i, earlier := range []domain.DatabaseSnapshot{snapLacks, snapLists, notHeld} {
		c := coordinatetest.MustNew(fmt.Sprintf("example.com/m%d", i), "v1.0.0")
		recs := []domain.VulnerabilityRecord{tlRec(c, 1, earlier), tlRec(c, 2, later, tlReported()), tlRec(c, 3, later, tlReported())}
		s.history[c.String()] = recs
		// Two records of one coordinate name it once.
		s.byID = append(s.byID, recs[1], recs[2])
	}
	return s
}

func tlReasons(tls []domain.FindingTimeline) string {
	var out []string
	for _, tl := range tls {
		for _, e := range tl.Entries {
			out = append(out, tl.Coordinate.Path()+":"+string(e.Reason))
		}
	}
	return strings.Join(out, " ")
}

// advisory-added rests on the stored bytes of the earlier snapshot: held and
// not listing it. Held and listing it, or not held, is unattributed.
func TestFindingTimelines_AdvisoryAddedReadsTheStoredSnapshot(t *testing.T) {
	s := tlFixture(t)
	tls, err := application.NewQueryVulnUseCase(s).FindingTimelines(context.Background(), tlID, "")
	if err != nil {
		t.Fatal(err)
	}
	want := "example.com/m0:advisory-added example.com/m1:unattributed example.com/m2:unattributed"
	if got := tlReasons(tls); got != want {
		t.Errorf("got %q, want %q", got, want)
	}
	if s.histReads != 3 || s.blobReads != 2 {
		t.Errorf("read %d histories and %d snapshot bodies, want 3 and 2", s.histReads, s.blobReads)
	}
}

var tlDrift = vulnports.UnreadableRow{Kind: vulnports.RowKindRecord, ID: "d", ContentHash: "sha256:d",
	Generation: vulnports.RowGeneration{PipelineVersion: "v9", SnapshotSource: "vuln.go.dev", SnapshotVersion: "s"},
	Reason:     fmt.Errorf("drift: %w", recordseal.ErrGenerationDrift)}

// Rows the listings could not read come back beside the timelines, as one
// report in the store's own terms.
func TestFindingTimelines_ReportsUnreadableRows(t *testing.T) {
	altered := vulnports.UnreadableRow{Kind: vulnports.RowKindRecord, ID: "example.com/bad@v1.0.0", Reason: errors.New("hash mismatch")}
	asideOf := func(rows ...vulnports.UnreadableRow) error {
		var out []recordseal.SetAsideRow
		for _, r := range rows {
			out = append(out, r.SetAside())
		}
		return &recordseal.SetAside{Rows: out}
	}

	s := tlFixture(t)
	s.byIDErr = &vulnports.UnreadableRows{Rows: []vulnports.UnreadableRow{altered}}
	s.historyErr = asideOf(tlDrift)
	tls, err := application.NewQueryVulnUseCase(s).FindingTimelines(context.Background(), tlID, "")
	var unreadable *vulnports.UnreadableRows
	if !errors.As(err, &unreadable) || len(tls) != 3 || len(unreadable.Rows) != 4 ||
		unreadable.Rows[0].ID != altered.ID || unreadable.Rows[1] != tlDrift || unreadable.Rows[3] != tlDrift {
		t.Fatalf("got %d timelines, %v; want 3 beside the altered row then three drift rows", len(tls), err)
	}

	s = tlFixture(t)
	s.historyErr = asideOf(tlDrift)
	_, err = application.NewQueryVulnUseCase(s).FindingTimelines(context.Background(), tlID, "")
	var aside *recordseal.SetAside
	if !errors.As(err, &aside) || len(aside.Rows) != 3 || aside.Rows[0] != tlDrift.SetAside() {
		t.Errorf("all-drift report = %v, want a set-aside naming each drift row as the store did", err)
	}

	run := recordseal.SetAsideRow{Kind: vulnports.SetAsideKindRun, ID: "run-1", Reason: recordseal.ErrGenerationDrift}
	s = tlFixture(t)
	s.byIDErr = &recordseal.SetAside{Rows: []recordseal.SetAsideRow{run}}
	_, err = application.NewQueryVulnUseCase(s).FindingTimelines(context.Background(), tlID, "")
	if !errors.As(err, &aside) || len(aside.Rows) != 1 || aside.Rows[0].Kind != vulnports.SetAsideKindRun {
		t.Errorf("set-aside run = %v, want it kept as a run", err)
	}
}

// Every failure other than unreadable rows ends the answer.
func TestFindingTimelines_Errors(t *testing.T) {
	boom := errors.New("boom")
	nothing := &recordseal.NothingServable{Kind: "vulnerability record", ID: "x", Aside: &recordseal.SetAside{}}
	for name, mutate := range map[string]func(*timelineStore){
		"listing":          func(s *timelineStore) { s.byIDErr = boom },
		"nothing servable": func(s *timelineStore) { s.byIDErr = nothing },
		"history":          func(s *timelineStore) { s.historyErr = boom },
		"snapshot list":    func(s *timelineStore) { s.snapsErr = boom },
		"snapshot read":    func(s *timelineStore) { s.getErr = boom },
		"snapshot body":    func(s *timelineStore) { s.readBody = iotest.ErrReader(boom) },
		"not a zip":        func(s *timelineStore) { s.blobs[s.snaps[0].ContentHash()] = []byte("x") },
		"no index":         func(s *timelineStore) { s.blobs[s.snaps[0].ContentHash()] = tlZip(t, "") },
		"bad index":        func(s *timelineStore) { s.blobs[s.snaps[0].ContentHash()] = tlZip(t, "{") },
	} {
		s := tlFixture(t)
		mutate(s)
		if tls, err := application.NewQueryVulnUseCase(s).FindingTimelines(context.Background(), tlID, ""); err == nil || tls != nil {
			t.Errorf("%s: got %d timelines, %v; want an error and none", name, len(tls), err)
		}
	}
}

// A corrupt zip entry fails the read rather than reading as an empty index.
func TestFindingTimelines_UnreadableIndexEntry(t *testing.T) {
	s := tlFixture(t)
	body := tlZip(t, `[{"path":"example.com/x","vulns":[]}]`)
	// Corrupt the stored entry's CRC so reading it fails after opening.
	i := bytes.Index(body, []byte("PK\x01\x02"))
	body[i+16] ^= 0xff
	s.blobs[s.snaps[0].ContentHash()] = body
	if _, err := application.NewQueryVulnUseCase(s).FindingTimelines(context.Background(), tlID, ""); !errors.Is(err, zip.ErrChecksum) {
		t.Errorf("got %v, want the checksum failure reading the index", err)
	}
}
