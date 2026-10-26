package kanonarion_test

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"code.eitanity.com/kanonarion/internal/adapters/sqlitestore"
	"code.eitanity.com/kanonarion/internal/coordinate"
	"code.eitanity.com/kanonarion/internal/coordinate/coordinatetest"
	vulnsqlite "code.eitanity.com/kanonarion/internal/vuln/adapters/store/sqlite"
	vulnapp "code.eitanity.com/kanonarion/internal/vuln/application"
	vulndomain "code.eitanity.com/kanonarion/internal/vuln/domain"
	"code.eitanity.com/kanonarion/internal/vuln/vulntest"

	"code.eitanity.com/kanonarion/pkg/kanonarion"
)

const timelineAdvisory = "GO-2026-0002"

// timelineFixture is one coordinate per reason, each in its own frame, and the
// snapshot bodies the store holds. The earlier snapshot of "added" is held and
// lacks the advisory; that of "unheld" is not held.
type timelineFixture struct {
	records []kanonarion.VulnerabilityRecord
	held    map[kanonarion.DatabaseSnapshot][]byte
}

func snapshotBody(t *testing.T, ids ...string) []byte {
	t.Helper()
	vulns := make([]map[string]string, 0, len(ids))
	for _, id := range ids {
		vulns = append(vulns, map[string]string{"id": id})
	}
	index, err := json.Marshal([]map[string]any{{"path": "example.com/x", "vulns": vulns}})
	if err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	w, err := zw.Create("index/modules.json")
	if err == nil {
		_, err = w.Write(index)
	}
	if err == nil {
		err = zw.Close()
	}
	if err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func newTimelineFixture(t *testing.T) timelineFixture {
	t.Helper()
	t0 := time.Date(2026, 8, 1, 0, 0, 0, 0, time.UTC)
	lacksBody, listsBody := snapshotBody(t, "GO-2026-0001"), snapshotBody(t, "GO-2026-0001", timelineAdvisory)
	lacks := vulntest.MustSealOver("vuln.go.dev", "2026-07-01T00:00:00Z", t0, lacksBody)
	lists := vulntest.MustSealOver("vuln.go.dev", "2026-08-01T00:00:00Z", t0, listsBody)
	unheld := vulntest.MustSealOver("vuln.go.dev", "2026-07-15T00:00:00Z", t0, []byte("never stored"))

	reported := func(reachable bool) vulndomain.VulnerabilityFinding {
		return vulndomain.VulnerabilityFinding{ID: timelineAdvisory,
			Reachable: &vulndomain.ReachabilityResult{IsReachable: reachable, Confidence: vulndomain.ConfidenceHigh}}
	}
	withdrawn := vulndomain.VulnerabilityFinding{ID: timelineAdvisory, WithdrawnAt: t0.Add(48 * time.Hour)}
	type step struct {
		snap     kanonarion.DatabaseSnapshot
		failed   bool
		findings []vulndomain.VulnerabilityFinding
	}
	streams := map[string][]step{
		"added":     {{snap: lacks}, {snap: lists, findings: []vulndomain.VulnerabilityFinding{reported(true)}}},
		"unheld":    {{snap: unheld}, {snap: lists, findings: []vulndomain.VulnerabilityFinding{reported(true)}}},
		"corrected": {{snap: lists, findings: []vulndomain.VulnerabilityFinding{reported(true)}}, {snap: lists, findings: []vulndomain.VulnerabilityFinding{reported(false)}}},
		"withdrawn": {{snap: lists, findings: []vulndomain.VulnerabilityFinding{reported(true)}}, {snap: lists, findings: []vulndomain.VulnerabilityFinding{withdrawn}}},
		"coverage":  {{snap: lists, findings: []vulndomain.VulnerabilityFinding{reported(true)}}, {snap: lists, failed: true}},
	}
	f := timelineFixture{held: map[kanonarion.DatabaseSnapshot][]byte{lacks: lacksBody, lists: listsBody}}
	for name, steps := range streams {
		c := coordinatetest.MustNew("example.com/"+name, "v1.0.0")
		for i, s := range steps {
			rec := vulndomain.VulnerabilityRecord{
				Ecosystem: "go", Coordinate: c, PipelineVersion: vulnapp.PipelineVersion, DatabaseSnapshot: s.snap,
				Rooting:       vulndomain.TargetRootedAt(coordinatetest.MustNew("example.com/app-"+name, "v1.0.0")),
				OverallStatus: vulndomain.StatusClean, CoverageStatus: vulndomain.CoverageAnalysed,
				Findings: s.findings, ScannedAt: t0.Add(time.Duration(i+1) * time.Hour),
			}
			if len(s.findings) > 0 {
				rec.OverallStatus = vulndomain.StatusAffected
			}
			if s.failed {
				rec.OverallStatus, rec.CoverageStatus, rec.ErrorDetail = vulndomain.StatusScanFailed, vulndomain.CoverageFailedScan, "scan failed"
			}
			sealed, err := vulndomain.VulnerabilityRecordHasher{}.SetContentHash(rec)
			if err != nil {
				t.Fatal(err)
			}
			f.records = append(f.records, sealed)
		}
	}
	return f
}

// wantReasons is the reason each coordinate's one change carries.
var wantReasons = map[string]kanonarion.TimelineReason{
	"example.com/added":     kanonarion.TimelineReasonAdvisoryAdded,
	"example.com/unheld":    kanonarion.TimelineReasonUnattributed,
	"example.com/corrected": kanonarion.TimelineReasonReachabilityCorrected,
	"example.com/withdrawn": kanonarion.TimelineReasonWithdrawn,
	"example.com/coverage":  kanonarion.TimelineReasonCoverageLost,
}

func reasonsOf(t *testing.T, tls []kanonarion.FindingTimeline) map[string]kanonarion.TimelineReason {
	t.Helper()
	got := map[string]kanonarion.TimelineReason{}
	for _, tl := range tls {
		if len(tl.Entries) != 1 || tl.Entries[0].Kind != kanonarion.TimelineChange {
			t.Errorf("%s: %d entries, want one change", tl.Coordinate, len(tl.Entries))
			continue
		}
		got[tl.Coordinate.Path()] = tl.Entries[0].Reason
	}
	return got
}

// sqliteTimelines writes the fixture through the SQLite store's write path and
// reads the timelines through Open.
func sqliteTimelines(t *testing.T, f timelineFixture) []kanonarion.FindingTimeline {
	t.Helper()
	root := t.TempDir()
	_, cleanup, err := kanonarion.Open(root)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if cerr := cleanup(); cerr != nil {
		t.Fatal(cerr)
	}
	db, err := sqlitestore.Open(filepath.Join(root, "mirror.db"), nil, sqlitestore.IntentCreate)
	if err != nil {
		t.Fatal(err)
	}
	store := vulnsqlite.New(db)
	ctx := context.Background()
	for snap, body := range f.held {
		if err := store.PutDatabaseSnapshot(ctx, snap, bytes.NewReader(body)); err != nil {
			t.Fatal(err)
		}
	}
	for _, rec := range f.records {
		if err := store.PutVulnerabilityRecord(ctx, rec); err != nil {
			t.Fatal(err)
		}
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	return openTimelines(t, root)
}

func openTimelines(t *testing.T, root string) []kanonarion.FindingTimeline {
	t.Helper()
	queries, cleanup, err := kanonarion.Open(root)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() {
		if cerr := cleanup(); cerr != nil {
			t.Errorf("closing: %v", cerr)
		}
	})
	tls, err := queries.Vuln.FindingTimelines(context.Background(), timelineAdvisory, "")
	if err != nil {
		t.Fatalf("FindingTimelines: %v", err)
	}
	return tls
}

// A library caller gets every reason through Open, advisory-added only where
// the earlier snapshot is held and does not list the advisory.
func TestOpen_FindingTimelinesGiveEachReason(t *testing.T) {
	got := reasonsOf(t, sqliteTimelines(t, newTimelineFixture(t)))
	if len(got) != len(wantReasons) {
		t.Errorf("got %d timelines, want %d: %v", len(got), len(wantReasons), got)
	}
	for path, want := range wantReasons {
		if got[path] != want {
			t.Errorf("%s: reason %q, want %q", path, got[path], want)
		}
	}
}

// memoryVulns answers the reads the timeline makes from the fixture alone.
type memoryVulns struct {
	kanonarion.VulnerabilityStore
	f timelineFixture
}

func (m memoryVulns) ListVulnerabilityRecordsByFindingID(_ context.Context, id, _ string) ([]kanonarion.VulnerabilityRecord, error) {
	var out []kanonarion.VulnerabilityRecord
	for _, r := range m.f.records {
		if slices.ContainsFunc(r.Findings, func(f vulndomain.VulnerabilityFinding) bool { return f.ID == id }) {
			out = append(out, r)
		}
	}
	return out, nil
}

func (m memoryVulns) ListCoordinatesByFindingID(ctx context.Context, id, walkID string) ([]coordinate.ModuleCoordinate, error) {
	recs, err := m.ListVulnerabilityRecordsByFindingID(ctx, id, walkID)
	var out []coordinate.ModuleCoordinate
	for _, r := range recs {
		if !slices.Contains(out, r.Coordinate) {
			out = append(out, r.Coordinate)
		}
	}
	return out, err
}

func (m memoryVulns) ListVulnerabilityRecordsForModuleAllGenerations(_ context.Context, c coordinate.ModuleCoordinate) ([]kanonarion.VulnerabilityRecord, error) {
	var out []kanonarion.VulnerabilityRecord
	for _, r := range m.f.records {
		if r.Coordinate == c {
			out = append(out, r)
		}
	}
	return out, nil
}

func (m memoryVulns) ListDatabaseSnapshots(context.Context) ([]kanonarion.DatabaseSnapshot, error) {
	out := make([]kanonarion.DatabaseSnapshot, 0, len(m.f.held))
	for s := range m.f.held {
		out = append(out, s)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Version() < out[j].Version() })
	return out, nil
}

func (m memoryVulns) GetDatabaseSnapshot(_ context.Context, s kanonarion.DatabaseSnapshot) (io.ReadCloser, error) {
	return io.NopCloser(bytes.NewReader(m.f.held[s])), nil
}

var (
	registerTimelineBackend sync.Once
	timelineBackendRecords  timelineFixture
)

// A backend registered from outside answers FindingTimelines exactly as SQLite
// does for the same records: the advisory check reads the backend's own store.
func TestOpen_FindingTimelinesSameUnderARegisteredBackend(t *testing.T) {
	f := newTimelineFixture(t)
	timelineBackendRecords = f
	registerTimelineBackend.Do(func() {
		err := kanonarion.RegisterBackend(kanonarion.Backend{
			Name: "timeline-memory",
			Open: func(context.Context, kanonarion.StorageRequest) (*kanonarion.Storage, error) {
				return &kanonarion.Storage{
					Facts: stubFacts{}, Attestations: stubAttestations{}, Audit: stubAudit{}, Blobs: stubBlobs{},
					Walks: stubWalks{}, WalkPresence: stubPresence{}, Licenses: stubLicences{}, Interfaces: stubInterfaces{},
					CallGraphs: stubCallGraphs{}, CallGraphOutcomes: stubOutcomes{}, Examples: stubExamples{},
					Extractions: stubExtractions{}, Vulnerabilities: memoryVulns{f: timelineBackendRecords}, SBOMs: stubSBOMs{},
					Directives: stubDirectives{}, GoDebug: stubGoDebug{}, Vendor: stubVendor{}, FIPS: stubFIPS{},
					Stdlib: stubStdlib{}, Staleness: stubStaleness{}, Native: stubNative{},
				}, nil
			},
		})
		if err != nil {
			t.Fatalf("RegisterBackend: %v", err)
		}
	})
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "config.yaml"), []byte("version: \"3\"\nstorage:\n  backend: timeline-memory\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	memory, sqlite := openTimelines(t, root), sqliteTimelines(t, f)
	mj, merr := json.Marshal(memory)
	sj, serr := json.Marshal(sqlite)
	if merr != nil || serr != nil {
		t.Fatal(merr, serr)
	}
	if !bytes.Equal(mj, sj) {
		t.Errorf("the registered backend's timelines differ from SQLite's:\nmemory %s\nsqlite %s", mj, sj)
	}
	if !strings.Contains(string(mj), string(kanonarion.TimelineReasonAdvisoryAdded)) {
		t.Errorf("no advisory-added under the registered backend: %s", mj)
	}
}

type (
	stubFacts        struct{ kanonarion.FactStore }
	stubAttestations struct{ kanonarion.AttestationStore }
	stubAudit        struct{ kanonarion.AuditSink }
	stubBlobs        struct{ kanonarion.BlobStore }
	stubWalks        struct{ kanonarion.WalkStore }
	stubPresence     struct{ kanonarion.WalkPresence }
	stubLicences     struct{ kanonarion.LicenseStore }
	stubInterfaces   struct{ kanonarion.InterfaceStore }
	stubCallGraphs   struct{ kanonarion.CallGraphStore }
	stubOutcomes     struct {
		kanonarion.CallGraphOutcomeReader
	}
	stubExamples    struct{ kanonarion.ExampleStore }
	stubExtractions struct{ kanonarion.ExtractionStore }
	stubSBOMs       struct{ kanonarion.SBOMStore }
	stubDirectives  struct{ kanonarion.DirectiveStore }
	stubGoDebug     struct{ kanonarion.GoDebugStore }
	stubVendor      struct{ kanonarion.VendorStore }
	stubFIPS        struct{ kanonarion.FIPSStore }
	stubStdlib      struct{ kanonarion.StdlibStore }
	stubStaleness   struct{ kanonarion.StalenessLedger }
	stubNative      struct{ kanonarion.NativeStore }
)
