package application_test

import (
	"context"
	"fmt"
	"io"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/eitanity/kanonarion/internal/coordinate"

	fetchdomain "github.com/eitanity/kanonarion/internal/fetch/domain"
	"github.com/eitanity/kanonarion/internal/fetch/fetchtest"
	fetchports "github.com/eitanity/kanonarion/internal/fetch/ports"
	"github.com/eitanity/kanonarion/internal/vuln/domain"
	"github.com/eitanity/kanonarion/internal/vuln/ports"
	walkdomain "github.com/eitanity/kanonarion/internal/walk/domain"
	walkports "github.com/eitanity/kanonarion/internal/walk/ports"
)

type fakeWalkStore struct {
	mu       sync.Mutex
	walks    map[string]walkdomain.WalkRecord
	errOnGet error
}

func newFakeWalkStore() *fakeWalkStore {
	return &fakeWalkStore{walks: make(map[string]walkdomain.WalkRecord)}
}

func (f *fakeWalkStore) PutWalk(_ context.Context, rec walkdomain.WalkRecord) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.walks[rec.ID] = rec
	return nil
}

func (f *fakeWalkStore) GetWalk(_ context.Context, id string) (walkdomain.WalkRecord, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.errOnGet != nil {
		return walkdomain.WalkRecord{}, f.errOnGet
	}
	rec, ok := f.walks[id]
	if !ok {
		return walkdomain.WalkRecord{}, walkports.ErrWalkNotFound
	}
	return rec, nil
}

func (f *fakeWalkStore) ListWalks(_ context.Context, _ walkports.WalkFilter) ([]walkports.WalkSummary, error) {
	return nil, nil
}

// fakeBlob implements fetchports.BlobStore in memory.
type fakeBlob struct {
	mu   sync.Mutex
	data map[string][]byte
}

func newFakeBlob() *fakeBlob { return &fakeBlob{data: make(map[string][]byte)} }

func (f *fakeBlob) Put(_ context.Context, identity fetchports.BlobIdentity, content io.Reader) error {
	b, err := io.ReadAll(content)
	if err != nil {
		return fmt.Errorf("reading content: %w", err)
	}
	f.mu.Lock()
	f.data[identity.String()] = b
	f.mu.Unlock()
	return nil
}

func (f *fakeBlob) Get(_ context.Context, identity fetchports.BlobIdentity) (io.ReadCloser, error) {
	f.mu.Lock()
	b, ok := f.data[identity.String()]
	f.mu.Unlock()
	if !ok {
		return nil, fmt.Errorf("blob not found: %s", identity)
	}
	return io.NopCloser(strings.NewReader(string(b))), nil
}

func (f *fakeBlob) Exists(_ context.Context, identity fetchports.BlobIdentity) (bool, error) {
	f.mu.Lock()
	_, ok := f.data[identity.String()]
	f.mu.Unlock()
	return ok, nil
}

func (f *fakeBlob) GetPath(_ context.Context, identity fetchports.BlobIdentity) (string, error) {
	f.mu.Lock()
	_, ok := f.data[identity.String()]
	f.mu.Unlock()
	if !ok {
		return "", fmt.Errorf("blob not found: %s", identity)
	}
	return "/fake/path/" + identity.String(), nil
}

// fakeFacts implements fetchports.FactStore in memory.
type fakeFacts struct {
	mu      sync.Mutex
	records map[string]fetchdomain.FactRecord
}

func newFakeFacts() *fakeFacts { return &fakeFacts{records: make(map[string]fetchdomain.FactRecord)} }

func (f *fakeFacts) PutFetchRecord(_ context.Context, sealed fetchdomain.SealedRecord) error {
	if sealed.IsZero() {
		return fetchdomain.ErrUnsealedRecord
	}
	r := sealed.Record()
	key := r.ModulePath + "@" + r.ModuleVersion + "#" + r.PipelineVersion
	f.mu.Lock()
	f.records[key] = r
	f.mu.Unlock()
	return nil
}

func (f *fakeFacts) GetFetchRecord(_ context.Context, coord coordinate.ModuleCoordinate, pv string) (fetchdomain.CompositeRecord, bool, error) {
	key := coord.Path() + "@" + coord.Version() + "#" + pv
	f.mu.Lock()
	r, ok := f.records[key]
	f.mu.Unlock()
	if !ok {
		return fetchdomain.CompositeRecord{}, false, nil
	}
	c, cerr := fetchdomain.Compose([]fetchdomain.FactRecord{r})
	if cerr != nil {
		return fetchdomain.CompositeRecord{}, false, cerr //nolint:wrapcheck // test fake
	}
	return c, true, nil
}

// ComposeFetchRecord answers the coordinate-only composed read, satisfying the
// optional fetchports.FactRecordComposer capability. It folds every record filed
// for the coordinate whatever pipeline version wrote it, exactly as the sqlite
// store does — a fake that consulted one pipeline version here would let a scan
// test go green while production routed the module to a metadata-only verdict.
func (f *fakeFacts) ComposeFetchRecord(_ context.Context, coord coordinate.ModuleCoordinate) (fetchdomain.CompositeRecord, bool, error) {
	if coord.IsZero() {
		return fetchdomain.CompositeRecord{}, false, coordinate.ErrZeroCoordinate
	}
	f.mu.Lock()
	held := make([]fetchdomain.FactRecord, 0, len(f.records))
	for _, r := range f.records {
		held = append(held, r)
	}
	f.mu.Unlock()
	//nolint:wrapcheck // test fake; the helper already names the coordinate
	return fetchtest.ComposeCoordinate(coord, held)
}

// fakeVulnStore is an append-only ledger, like the real store: records holds
// every generation written under a key, and the reads compose over them. A fake
// that kept only the last write would let a test of the append behaviour pass
// without the behaviour existing.
type fakeVulnStore struct {
	mu                 sync.Mutex
	records            map[string][]domain.VulnerabilityRecord
	runs               map[string]domain.WalkScanRun
	runRecords         map[string][]domain.VulnerabilityRecord
	snapshots          map[string][]byte
	latestSnapshot     *domain.DatabaseSnapshot
	errOnPutRun        error
	errOnGetRun        error
	errOnListRecords   error
	errOnListRuns      error
	errOnGetLatestSnap error
	errOnPutSnap       error
	errOnPutRecord     error
	// dropRecordFor is the fault seam for a silently lost verdict: a put for
	// this coordinate reports success and stores nothing, reproducing a module
	// that produces a progress line and leaves no record behind. The zero
	// coordinate never matches a real one, so the seam is off by default.
	dropRecordFor coordinate.ModuleCoordinate
	// errOnPutRecordFor is the fault seam for a REPORTED write failure confined to
	// one coordinate — the shape a real store takes when its conflict clause no
	// longer matches the table, which refuses each write with an error rather than
	// accepting it. Scoping it to one coordinate is what lets a test reach a write
	// leg that only runs after other records have already been stored. Off by
	// default: the zero coordinate never matches a real one.
	errOnPutRecordFor coordinate.ModuleCoordinate
}

func newFakeVulnStore() *fakeVulnStore {
	return &fakeVulnStore{
		records:    make(map[string][]domain.VulnerabilityRecord),
		runs:       make(map[string]domain.WalkScanRun),
		runRecords: make(map[string][]domain.VulnerabilityRecord),
		snapshots:  make(map[string][]byte),
	}
}

// SetRunRecords associates a set of VulnerabilityRecords with a specific scan run ID
// so that ListVulnerabilityRecords returns the correct per-run records in tests.
func (f *fakeVulnStore) SetRunRecords(runID string, records []domain.VulnerabilityRecord) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.runRecords[runID] = records
}

func (f *fakeVulnStore) PutVulnerabilityRecord(_ context.Context, record domain.VulnerabilityRecord) error {
	if record.DatabaseSnapshot.IsZero() {
		return fmt.Errorf("fakeVulnStore.PutVulnerabilityRecord: %w", domain.ErrZeroSnapshot)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.errOnPutRecord != nil {
		return f.errOnPutRecord
	}
	if record.Coordinate == f.errOnPutRecordFor {
		return errStore
	}
	if record.Coordinate == f.dropRecordFor {
		return nil
	}
	key := f.recordKey(record.Coordinate, record.PipelineVersion, record.DatabaseSnapshot)
	for _, existing := range f.records[key] {
		if existing.ContentHash == record.ContentHash {
			// The same measurement written twice, which the real store's conflict
			// clause makes a no-op.
			return nil
		}
	}
	f.records[key] = append(f.records[key], record)
	return nil
}

// served returns the composed record for one key, as the real store's read
// leg does. Tests that want one specific generation read the slice.
func (f *fakeVulnStore) served(key string) (domain.VulnerabilityRecord, bool) {
	gens := f.records[key]
	if len(gens) == 0 {
		return domain.VulnerabilityRecord{}, false
	}
	rec, err := domain.Compose(gens)
	if err != nil {
		return domain.VulnerabilityRecord{}, false
	}
	return rec, true
}

func (f *fakeVulnStore) GetVulnerabilityRecord(_ context.Context, coord coordinate.ModuleCoordinate, pv string, snapshot domain.DatabaseSnapshot) (domain.VulnerabilityRecord, bool, error) {
	if snapshot.IsZero() {
		return domain.VulnerabilityRecord{}, false, fmt.Errorf("fakeVulnStore.GetVulnerabilityRecord: %w", domain.ErrZeroSnapshot)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	rec, ok := f.served(f.recordKey(coord, pv, snapshot))
	return rec, ok, nil
}

func (f *fakeVulnStore) GetVulnerabilityRecordAt(_ context.Context, coord coordinate.ModuleCoordinate, pv string, snapshot domain.DatabaseSnapshot, rooting domain.Rooting) (domain.VulnerabilityRecord, bool, error) {
	if snapshot.IsZero() {
		return domain.VulnerabilityRecord{}, false, fmt.Errorf("fakeVulnStore.GetVulnerabilityRecordAt: %w", domain.ErrZeroSnapshot)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	gens := f.records[f.recordKey(coord, pv, snapshot)]
	if len(gens) == 0 {
		return domain.VulnerabilityRecord{}, false, nil
	}
	rec, ok, err := domain.ComposeAt(gens, rooting)
	return rec, ok, err //nolint:wrapcheck // test fake
}

func (f *fakeVulnStore) HasVulnerabilityRecord(_ context.Context, coord coordinate.ModuleCoordinate, pv string, snapshot domain.DatabaseSnapshot, contentHash string) (bool, error) {
	if snapshot.IsZero() {
		return false, fmt.Errorf("fakeVulnStore.HasVulnerabilityRecord: %w", domain.ErrZeroSnapshot)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, rec := range f.records[f.recordKey(coord, pv, snapshot)] {
		if rec.ContentHash == contentHash {
			return true, nil
		}
	}
	return false, nil
}

func (f *fakeVulnStore) GetLatestVulnerabilityRecord(_ context.Context, coord coordinate.ModuleCoordinate, pv string) (domain.VulnerabilityRecord, bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.composeMatching(func(rec domain.VulnerabilityRecord) bool {
		return rec.Coordinate == coord && rec.PipelineVersion == pv
	})
}

// ListVulnerabilityRecordsForModuleInWalk is the port method: candidates, not an
// answer.
func (f *fakeVulnStore) ListVulnerabilityRecordsForModuleInWalk(_ context.Context, coord coordinate.ModuleCoordinate, pv string, walkID string) ([]domain.VulnerabilityRecord, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []domain.VulnerabilityRecord
	for _, gens := range f.records {
		for _, rec := range gens {
			if rec.Coordinate == coord && rec.PipelineVersion == pv && rec.WalkID == walkID {
				out = append(out, rec)
			}
		}
	}
	return out, nil
}

// GetLatestVulnerabilityRecordForWalk is a read-back convenience for the scan
// tests, which assert what one run wrote. It is not part of the store port: a
// frame-blind pick is not something a production read may ask the store for.
func (f *fakeVulnStore) GetLatestVulnerabilityRecordForWalk(_ context.Context, coord coordinate.ModuleCoordinate, pv string, walkID string) (domain.VulnerabilityRecord, bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.composeMatching(func(rec domain.VulnerabilityRecord) bool {
		return rec.Coordinate == coord && rec.PipelineVersion == pv && rec.WalkID == walkID
	})
}

func (f *fakeVulnStore) composeMatching(keep func(domain.VulnerabilityRecord) bool) (domain.VulnerabilityRecord, bool, error) {
	var matched []domain.VulnerabilityRecord
	for _, gens := range f.records {
		for _, rec := range gens {
			if keep(rec) {
				matched = append(matched, rec)
			}
		}
	}
	if len(matched) == 0 {
		return domain.VulnerabilityRecord{}, false, nil
	}
	rec, err := domain.Compose(matched)
	return rec, err == nil, err //nolint:wrapcheck // test fake
}

func (f *fakeVulnStore) ListVulnerabilityRecordsForModule(_ context.Context, coord coordinate.ModuleCoordinate, pv string) ([]domain.VulnerabilityRecord, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []domain.VulnerabilityRecord
	for _, gens := range f.records {
		for _, rec := range gens {
			if rec.Coordinate == coord && rec.PipelineVersion == pv {
				out = append(out, rec)
			}
		}
	}
	return out, nil
}

func (f *fakeVulnStore) recordKey(coord coordinate.ModuleCoordinate, pv string, snapshot domain.DatabaseSnapshot) string {
	return coord.String() + "|" + pv + "|" + snapshot.Source() + "@" + snapshot.Version()
}

func (f *fakeVulnStore) PutWalkScanRun(_ context.Context, run domain.WalkScanRun) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.errOnPutRun != nil {
		return f.errOnPutRun
	}
	f.runs[run.ID] = run
	return nil
}

// walkScanRunCount reports how many scan runs the store holds. A test asserting
// that a refused scan claimed nothing needs the absence of a run, which no
// read-by-ID can express.
func (f *fakeVulnStore) walkScanRunCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.runs)
}

func (f *fakeVulnStore) GetWalkScanRun(_ context.Context, id string) (domain.WalkScanRun, bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.errOnGetRun != nil {
		return domain.WalkScanRun{}, false, f.errOnGetRun
	}
	run, ok := f.runs[id]
	return run, ok, nil
}

func (f *fakeVulnStore) ListWalkScanRuns(_ context.Context, walkID string) ([]domain.WalkScanRun, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.errOnListRuns != nil {
		return nil, f.errOnListRuns
	}
	var runs []domain.WalkScanRun
	for _, run := range f.runs {
		if run.WalkID == walkID {
			runs = append(runs, run)
		}
	}
	return runs, nil
}

func (f *fakeVulnStore) ListAllWalkScanRuns(_ context.Context) ([]domain.WalkScanRun, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	var runs []domain.WalkScanRun
	for _, run := range f.runs {
		runs = append(runs, run)
	}
	return runs, nil
}

func (f *fakeVulnStore) PutDatabaseSnapshot(_ context.Context, snapshot domain.DatabaseSnapshot, content io.Reader) error {
	if snapshot.IsZero() {
		return fmt.Errorf("fakeVulnStore.PutDatabaseSnapshot: %w", domain.ErrZeroSnapshot)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.errOnPutSnap != nil {
		return f.errOnPutSnap
	}
	data, _ := io.ReadAll(content)
	f.snapshots[snapshot.Source()+"@"+snapshot.Version()] = data
	f.latestSnapshot = &snapshot
	return nil
}

func (f *fakeVulnStore) GetLatestDatabaseSnapshot(_ context.Context) (domain.DatabaseSnapshot, bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.errOnGetLatestSnap != nil {
		return domain.DatabaseSnapshot{}, false, f.errOnGetLatestSnap
	}
	if f.latestSnapshot == nil {
		return domain.DatabaseSnapshot{}, false, nil
	}
	return *f.latestSnapshot, true, nil
}

func (f *fakeVulnStore) GetDatabaseSnapshot(_ context.Context, snapshot domain.DatabaseSnapshot) (io.ReadCloser, error) {
	if snapshot.IsZero() {
		return nil, fmt.Errorf("fakeVulnStore.GetDatabaseSnapshot: %w", domain.ErrZeroSnapshot)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	data, ok := f.snapshots[snapshot.Source()+"@"+snapshot.Version()]
	if !ok {
		return nil, io.EOF
	}
	return io.NopCloser(strings.NewReader(string(data))), nil
}

func (f *fakeVulnStore) ListDatabaseSnapshots(_ context.Context) ([]domain.DatabaseSnapshot, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.latestSnapshot == nil {
		return nil, nil
	}
	return []domain.DatabaseSnapshot{*f.latestSnapshot}, nil
}

func (f *fakeVulnStore) ListVulnerabilityRecordsByFindingID(_ context.Context, findingID, _ string) ([]domain.VulnerabilityRecord, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []domain.VulnerabilityRecord
	for key := range f.records {
		rec, ok := f.served(key)
		if !ok {
			continue
		}
		for _, finding := range rec.Findings {
			if finding.ID == findingID {
				out = append(out, rec)
				break
			}
		}
	}
	return out, nil
}

func (f *fakeVulnStore) ListVulnerabilityRecords(_ context.Context, runID string) ([]domain.VulnerabilityRecord, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.errOnListRecords != nil {
		return nil, f.errOnListRecords
	}
	if recs, ok := f.runRecords[runID]; ok {
		return recs, nil
	}
	out := make([]domain.VulnerabilityRecord, 0, len(f.records))
	for key := range f.records {
		if rec, ok := f.served(key); ok {
			out = append(out, rec)
		}
	}
	return out, nil
}

type fakeScanner struct {
	mu           sync.Mutex
	results      map[string]domain.VulnerabilityRecord
	err          error
	preflightErr error
	// project-rooted scan controls (ScanProject).
	projectFindings map[coordinate.ModuleCoordinate][]domain.VulnerabilityFinding
	projectStatus   domain.VulnerabilityStatus
	projectReason   string
	projectErr      error
	// gotProjectVendored records whether the last ScanProject was asked for the
	// vendored surface, so a test can assert --no-vendor really reached the
	// scanner rather than being dropped on the way.
	gotProjectVendored bool
	// gotProjectDir records the working tree the last ScanProject was pointed at,
	// so a test can assert the directory a walk remembers is the one analysed.
	gotProjectDir string
	// projectSurfaceOverride forces the surface the fake reports back,
	// independently of what was requested — the case where the project on disk
	// cannot supply the surface the caller asked for.
	projectSurfaceOverride domain.AnalysisSurface
	// target-rooted scan controls (ScanTargetModule). targetRooted must be opted
	// into: a coordinate-keyed walk tries the target-rooted path first, and a fake
	// that silently succeeded there would take every isolated-path test off the
	// path it is exercising. Left false, the fake reports the same
	// could-not-analyse fault a real unbuildable target does, so the walk falls
	// back to isolated scanning.
	targetRooted   bool
	targetFindings map[coordinate.ModuleCoordinate][]domain.VulnerabilityFinding
	targetStatus   domain.VulnerabilityStatus
	targetReason   string
	targetErr      error
	gotTargetCoord coordinate.ModuleCoordinate
	gotTargetCache string
	// call counters let tests assert which path a walk took.
	scanCalls    int
	projectCalls int
	targetCalls  int
	// gotModCache records the GOMODCACHE dir the last Scan was invoked with, so a
	// test can assert --from-modcache threaded the real cache dir through.
	gotModCache string
}

func (f *fakeScanner) Preflight(_ context.Context) error { return f.preflightErr }

func (f *fakeScanner) Scan(_ context.Context, req ports.ScanRequest) (domain.VulnerabilityRecord, error) {
	coord, snapshot, goModCache := req.Coordinate, req.Snapshot, req.GoModCache
	if f.err != nil {
		return domain.VulnerabilityRecord{}, f.err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.scanCalls++
	f.gotModCache = goModCache
	res, ok := f.results[coord.String()]
	if !ok {
		return domain.VulnerabilityRecord{
			Coordinate:       coord,
			OverallStatus:    domain.StatusClean,
			DatabaseSnapshot: snapshot,
		}, nil
	}
	res.DatabaseSnapshot = snapshot
	return res, nil
}

// projectFindings, when set, is returned verbatim by ScanProject grouped by
// module; projectStatus overrides the derived Clean/Affected outcome (used to
// exercise genuine-fault paths). projectErr forces an infrastructure error.
func (f *fakeScanner) ScanProject(_ context.Context, req ports.ProjectScanRequest) (domain.ProjectScanResult, error) {
	if f.projectErr != nil {
		return domain.ProjectScanResult{}, f.projectErr
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.projectCalls++
	f.gotProjectVendored = req.Vendored
	f.gotProjectDir = req.ProjectDir
	// The real scanner reports the surface that ran, not the one requested. The
	// fake stands in for a project whose tree can supply what was asked for, so
	// the two agree here; a test that needs them to disagree sets
	// projectSurfaceOverride.
	surface := domain.AnalysisSurfaceFetched
	if req.Vendored {
		surface = domain.AnalysisSurfaceVendored
	}
	if f.projectSurfaceOverride != "" {
		surface = f.projectSurfaceOverride
	}
	if f.projectStatus == domain.StatusUnscannable || f.projectStatus == domain.StatusScanFailed {
		return domain.ProjectScanResult{
			Status:            f.projectStatus,
			UnscannableReason: f.projectReason,
			ErrorDetail:       f.projectReason,
			AnalysisSurface:   surface,
		}, nil
	}
	status := domain.StatusClean
	if len(f.projectFindings) > 0 {
		status = domain.StatusAffected
	}
	return domain.ProjectScanResult{
		FindingsByModule: f.projectFindings,
		Status:           status,
		AnalysisSurface:  surface,
	}, nil
}

// ScanTargetModule stands in for the target-rooted scan of a coordinate-keyed
// walk. See the targetRooted field for why the default is a fault.
func (f *fakeScanner) ScanTargetModule(_ context.Context, req ports.TargetScanRequest) (domain.ProjectScanResult, error) {
	if f.targetErr != nil {
		return domain.ProjectScanResult{}, f.targetErr
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.targetCalls++
	f.gotTargetCoord = req.Coordinate
	f.gotTargetCache = req.GoModCache
	if !f.targetRooted {
		return domain.ProjectScanResult{
			Status:            domain.StatusUnscannable,
			UnscannableReason: "fake scanner: target-rooted scanning not enabled for this test",
		}, nil
	}
	if f.targetStatus == domain.StatusUnscannable || f.targetStatus == domain.StatusScanFailed {
		return domain.ProjectScanResult{
			Status:            f.targetStatus,
			UnscannableReason: f.targetReason,
			ErrorDetail:       f.targetReason,
		}, nil
	}
	status := domain.StatusClean
	if len(f.targetFindings) > 0 {
		status = domain.StatusAffected
	}
	return domain.ProjectScanResult{FindingsByModule: f.targetFindings, Status: status}, nil
}

func (f *fakeScanner) ScannerMetadata() ports.ScannerMetadata {
	return ports.ScannerMetadata{Name: "fake-scanner", Version: "v1.0.0"}
}

type fakeDatabase struct {
	snapshot    domain.DatabaseSnapshot
	content     string
	vulnerables map[coordinate.ModuleCoordinate][]string
	// findings, when set for a coordinate, is returned verbatim by
	// LookupFindings; otherwise LookupFindings synthesises bare findings from
	// the vulnerables IDs so tests that only populate vulnerables still exercise
	// the metadata path.
	findings map[coordinate.ModuleCoordinate][]domain.VulnerabilityFinding
	err      error
	// errOnLookup fails only LookupFindings, leaving snapshot resolution intact
	// so a test can isolate an unreadable advisory set from an unusable database.
	errOnLookup error
	// snapshotCalls counts fresh-snapshot fetches, so a test can prove a run
	// refused before spending a network round trip.
	snapshotCalls atomic.Int64

	// latestVersion is the generation the fake database publishes. Empty means
	// "whatever snapshot reports", the case where upstream has not moved on; set
	// it to something else to stand for an advanced generation.
	latestVersion string
	// latestVersionErr fails the cheap generation read alone, leaving the full
	// download working, so a test can drive the fail-closed fallback.
	latestVersionErr error
	// latestVersionCalls counts generation reads, so a test can prove the cheap
	// check was made before any body was transferred.
	latestVersionCalls atomic.Int64

	// storedIndex and publishedIndex are what the two advisory-index reads
	// report. A nil publishedIndex means "identical to storedIndex", the case
	// where a new generation changed nothing this walk is judged on.
	storedIndex    ports.AdvisoryIndex
	publishedIndex ports.AdvisoryIndex
	// indexErr fails both index reads, so a test can drive the fail-closed
	// fallthrough into the full download.
	indexErr error
	// indexCalls counts index reads, so a test can prove the comparison was made
	// — or, on the unchanged-generation path, that it never had to be.
	indexCalls atomic.Int64
}

func (f *fakeDatabase) Snapshot(_ context.Context) (domain.DatabaseSnapshot, io.ReadCloser, error) {
	f.snapshotCalls.Add(1)
	if f.err != nil {
		return domain.DatabaseSnapshot{}, nil, f.err
	}
	return f.snapshot, io.NopCloser(strings.NewReader(f.content)), nil
}

func (f *fakeDatabase) LatestVersion(_ context.Context) (string, error) {
	f.latestVersionCalls.Add(1)
	if f.latestVersionErr != nil {
		return "", f.latestVersionErr
	}
	if f.latestVersion != "" {
		return f.latestVersion, nil
	}
	return f.snapshot.Version(), nil
}

func (f *fakeDatabase) SnapshotAdvisoryIndex(_ context.Context, _ domain.DatabaseSnapshot) (ports.AdvisoryIndex, error) {
	f.indexCalls.Add(1)
	if f.indexErr != nil {
		return nil, f.indexErr
	}
	return f.storedIndex, nil
}

func (f *fakeDatabase) PublishedAdvisoryIndex(_ context.Context) (ports.AdvisoryIndex, error) {
	f.indexCalls.Add(1)
	if f.indexErr != nil {
		return nil, f.indexErr
	}
	if f.publishedIndex != nil {
		return f.publishedIndex, nil
	}
	return f.storedIndex, nil
}

func (f *fakeDatabase) GetSnapshot(_ context.Context, identity domain.DatabaseSnapshot) (io.ReadCloser, error) {
	if identity.Version() == f.snapshot.Version() {
		return io.NopCloser(strings.NewReader(f.content)), nil
	}
	return nil, io.EOF
}

func (f *fakeDatabase) CheckVulnerable(_ context.Context, modules []coordinate.ModuleCoordinate) (map[coordinate.ModuleCoordinate][]string, error) {
	if f.err != nil {
		return nil, f.err
	}
	res := make(map[coordinate.ModuleCoordinate][]string)
	for _, m := range modules {
		if vulns, ok := f.vulnerables[m]; ok {
			res[m] = vulns
		}
	}
	return res, nil
}

func (f *fakeDatabase) LookupFindings(_ context.Context, coord coordinate.ModuleCoordinate) ([]domain.VulnerabilityFinding, error) {
	if f.errOnLookup != nil {
		return nil, f.errOnLookup
	}
	if f.err != nil {
		return nil, f.err
	}
	if fs, ok := f.findings[coord]; ok {
		return fs, nil
	}
	var findings []domain.VulnerabilityFinding
	for _, id := range f.vulnerables[coord] {
		findings = append(findings, domain.VulnerabilityFinding{ID: id})
	}
	domain.SortFindings(findings)
	return findings, nil
}

type fixedClock struct{ t time.Time }

func (c fixedClock) Now() time.Time { return c.t }

// callCountingScanner wraps a VulnerabilityScanner and records whether Scan was called.
type callCountingScanner struct {
	inner  ports.VulnerabilityScanner
	called *bool
}

func (s *callCountingScanner) Preflight(ctx context.Context) error {
	if err := s.inner.Preflight(ctx); err != nil {
		return fmt.Errorf("inner preflight: %w", err)
	}
	return nil
}

func (s *callCountingScanner) Scan(ctx context.Context, req ports.ScanRequest) (domain.VulnerabilityRecord, error) {
	*s.called = true
	rec, err := s.inner.Scan(ctx, req)
	if err != nil {
		return domain.VulnerabilityRecord{}, fmt.Errorf("inner scan: %w", err)
	}
	return rec, nil
}

func (s *callCountingScanner) ScanProject(ctx context.Context, req ports.ProjectScanRequest) (domain.ProjectScanResult, error) {
	res, err := s.inner.ScanProject(ctx, req)
	if err != nil {
		return domain.ProjectScanResult{}, fmt.Errorf("inner scan project: %w", err)
	}
	return res, nil
}

func (s *callCountingScanner) ScanTargetModule(ctx context.Context, req ports.TargetScanRequest) (domain.ProjectScanResult, error) {
	res, err := s.inner.ScanTargetModule(ctx, req)
	if err != nil {
		return domain.ProjectScanResult{}, fmt.Errorf("inner scan target: %w", err)
	}
	return res, nil
}

func (s *callCountingScanner) ScannerMetadata() ports.ScannerMetadata {
	return s.inner.ScannerMetadata()
}

// fakeCallGraphLoader implements ports.CallGraphLoader.
// present controls whether Load returns a valid projection or ErrCallGraphNotFound.
type fakeCallGraphLoader struct {
	mu      sync.Mutex
	present bool
	// ineligible makes the stored record one that must not stand in for a fresh
	// analysis — an environment failure. present says a record exists; this says
	// whether it may answer.
	ineligible bool
	loadErr    error
}

func (f *fakeCallGraphLoader) setPresent(v bool) {
	f.mu.Lock()
	f.present = v
	f.mu.Unlock()
}

func (f *fakeCallGraphLoader) Load(_ context.Context, _ coordinate.ModuleCoordinate) (ports.CallGraphProjection, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.loadErr != nil {
		return ports.CallGraphProjection{}, f.loadErr
	}
	if !f.present {
		return ports.CallGraphProjection{}, fmt.Errorf("%w: test coord", ports.ErrCallGraphNotFound)
	}
	return ports.CallGraphProjection{ServableAsCacheHit: !f.ineligible}, nil
}

// fakeCallGraphSpawner implements ports.CallGraphSpawner and records all invocations.
type fakeCallGraphSpawner struct {
	mu     sync.Mutex
	calls  []coordinate.ModuleCoordinate
	err    error
	stderr []byte
	// onSpawn is called just before returning, allowing the test to mutate loader state.
	onSpawn func()
}

func (f *fakeCallGraphSpawner) Spawn(_ context.Context, coord coordinate.ModuleCoordinate, _ bool) ([]byte, error) {
	f.mu.Lock()
	f.calls = append(f.calls, coord)
	onSpawn := f.onSpawn
	f.mu.Unlock()
	if onSpawn != nil {
		onSpawn()
	}
	return f.stderr, f.err
}

func (f *fakeCallGraphSpawner) callCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.calls)
}

// fakeReachabilityAnalyser implements ports.ReachabilityAnalyser and records invocations.
type fakeReachabilityAnalyser struct {
	mu     sync.Mutex
	calls  int
	result domain.ReachabilityResult
	err    error
}

func (f *fakeReachabilityAnalyser) Analyse(_ context.Context, _ coordinate.ModuleCoordinate, _ []ports.SymbolReference, _ ports.CallGraphLoader) (domain.ReachabilityResult, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls++
	return f.result, f.err
}

func (f *fakeReachabilityAnalyser) callCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.calls
}
