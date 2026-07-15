package application_test

import (
	"context"
	"fmt"
	"io"
	"strings"
	"sync"
	"time"

	fetchdomain "github.com/eitanity/kanonarion/internal/fetch/domain"
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
	data map[fetchports.BlobHandle][]byte
}

func newFakeBlob() *fakeBlob { return &fakeBlob{data: make(map[fetchports.BlobHandle][]byte)} }

func (f *fakeBlob) Put(_ context.Context, content io.Reader) (fetchports.BlobHandle, error) {
	b, err := io.ReadAll(content)
	if err != nil {
		return "", fmt.Errorf("reading content: %w", err)
	}
	h := fetchports.BlobHandle("fake:" + string(b))
	f.mu.Lock()
	f.data[h] = b
	f.mu.Unlock()
	return h, nil
}

func (f *fakeBlob) Get(_ context.Context, h fetchports.BlobHandle) (io.ReadCloser, error) {
	f.mu.Lock()
	b, ok := f.data[h]
	f.mu.Unlock()
	if !ok {
		return nil, fmt.Errorf("blob not found: %s", h)
	}
	return io.NopCloser(strings.NewReader(string(b))), nil
}

func (f *fakeBlob) Exists(_ context.Context, h fetchports.BlobHandle) (bool, error) {
	f.mu.Lock()
	_, ok := f.data[h]
	f.mu.Unlock()
	return ok, nil
}

func (f *fakeBlob) GetPath(_ context.Context, h fetchports.BlobHandle) (string, error) {
	f.mu.Lock()
	_, ok := f.data[h]
	f.mu.Unlock()
	if !ok {
		return "", fmt.Errorf("blob not found: %s", h)
	}
	return "/fake/path/" + string(h), nil
}

// fakeFacts implements fetchports.FactStore in memory.
type fakeFacts struct {
	mu      sync.Mutex
	records map[string]fetchdomain.FactRecord
}

func newFakeFacts() *fakeFacts { return &fakeFacts{records: make(map[string]fetchdomain.FactRecord)} }

func (f *fakeFacts) PutFetchRecord(_ context.Context, r fetchdomain.FactRecord) error {
	key := r.ModulePath + "@" + r.ModuleVersion + "#" + r.PipelineVersion
	f.mu.Lock()
	f.records[key] = r
	f.mu.Unlock()
	return nil
}

func (f *fakeFacts) GetFetchRecord(_ context.Context, coord fetchdomain.ModuleCoordinate, pv string) (fetchdomain.FactRecord, bool, error) {
	key := coord.Path + "@" + coord.Version + "#" + pv
	f.mu.Lock()
	r, ok := f.records[key]
	f.mu.Unlock()
	return r, ok, nil
}

type fakeVulnStore struct {
	mu                 sync.Mutex
	records            map[string]domain.VulnerabilityRecord
	runs               map[string]domain.WalkScanRun
	runRecords         map[string][]domain.VulnerabilityRecord
	snapshots          map[string][]byte
	latestSnapshot     *domain.DatabaseSnapshot
	errOnPutRun        error
	errOnGetRun        error
	errOnListRecords   error
	errOnGetLatestSnap error
	errOnPutSnap       error
	errOnPutRecord     error
}

func newFakeVulnStore() *fakeVulnStore {
	return &fakeVulnStore{
		records:    make(map[string]domain.VulnerabilityRecord),
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
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.errOnPutRecord != nil {
		return f.errOnPutRecord
	}
	key := f.recordKey(record.Coordinate, record.PipelineVersion, record.DatabaseSnapshot)
	f.records[key] = record
	return nil
}

func (f *fakeVulnStore) GetVulnerabilityRecord(_ context.Context, coord fetchdomain.ModuleCoordinate, pv string, snapshot domain.DatabaseSnapshot) (domain.VulnerabilityRecord, bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	key := f.recordKey(coord, pv, snapshot)
	rec, ok := f.records[key]
	return rec, ok, nil
}

func (f *fakeVulnStore) GetLatestVulnerabilityRecord(_ context.Context, coord fetchdomain.ModuleCoordinate, pv string) (domain.VulnerabilityRecord, bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, rec := range f.records {
		if rec.Coordinate == coord && rec.PipelineVersion == pv {
			return rec, true, nil
		}
	}
	return domain.VulnerabilityRecord{}, false, nil
}

func (f *fakeVulnStore) GetLatestVulnerabilityRecordForWalk(_ context.Context, coord fetchdomain.ModuleCoordinate, pv string, walkID string) (domain.VulnerabilityRecord, bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, rec := range f.records {
		if rec.Coordinate == coord && rec.PipelineVersion == pv && rec.WalkID == walkID {
			return rec, true, nil
		}
	}
	return domain.VulnerabilityRecord{}, false, nil
}

func (f *fakeVulnStore) ListVulnerabilityRecordsForModule(_ context.Context, coord fetchdomain.ModuleCoordinate, pv string) ([]domain.VulnerabilityRecord, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []domain.VulnerabilityRecord
	for _, rec := range f.records {
		if rec.Coordinate == coord && rec.PipelineVersion == pv {
			out = append(out, rec)
		}
	}
	return out, nil
}

func (f *fakeVulnStore) recordKey(coord fetchdomain.ModuleCoordinate, pv string, snapshot domain.DatabaseSnapshot) string {
	return coord.String() + "|" + pv + "|" + snapshot.Source + "@" + snapshot.Version
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
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.errOnPutSnap != nil {
		return f.errOnPutSnap
	}
	data, _ := io.ReadAll(content)
	f.snapshots[snapshot.Source+"@"+snapshot.Version] = data
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
	f.mu.Lock()
	defer f.mu.Unlock()
	data, ok := f.snapshots[snapshot.Source+"@"+snapshot.Version]
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

func (f *fakeVulnStore) ListVulnerabilityRecordsByFindingID(_ context.Context, findingID string) ([]domain.VulnerabilityRecord, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []domain.VulnerabilityRecord
	for _, rec := range f.records {
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
	for _, rec := range f.records {
		out = append(out, rec)
	}
	return out, nil
}

type fakeScanner struct {
	mu           sync.Mutex
	results      map[string]domain.VulnerabilityRecord
	err          error
	preflightErr error
	// project-rooted scan controls (ScanProject).
	projectFindings map[fetchdomain.ModuleCoordinate][]domain.VulnerabilityFinding
	projectStatus   domain.VulnerabilityStatus
	projectReason   string
	projectErr      error
	// call counters let tests assert which path a walk took.
	scanCalls    int
	projectCalls int
	// gotModCache records the GOMODCACHE dir the last Scan was invoked with, so a
	// test can assert --from-modcache threaded the real cache dir through.
	gotModCache string
}

func (f *fakeScanner) Preflight(_ context.Context) error { return f.preflightErr }

func (f *fakeScanner) Scan(_ context.Context, coord fetchdomain.ModuleCoordinate, _ io.Reader, snapshot domain.DatabaseSnapshot, goModCache string, _ string, _ domain.ScanMode) (domain.VulnerabilityRecord, error) {
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
func (f *fakeScanner) ScanProject(_ context.Context, _ string, _ domain.DatabaseSnapshot, _ string) (domain.ProjectScanResult, error) {
	if f.projectErr != nil {
		return domain.ProjectScanResult{}, f.projectErr
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.projectCalls++
	if f.projectStatus == domain.StatusUnscannable || f.projectStatus == domain.StatusScanFailed {
		return domain.ProjectScanResult{
			Status:            f.projectStatus,
			UnscannableReason: f.projectReason,
			ErrorDetail:       f.projectReason,
		}, nil
	}
	status := domain.StatusClean
	if len(f.projectFindings) > 0 {
		status = domain.StatusAffected
	}
	return domain.ProjectScanResult{FindingsByModule: f.projectFindings, Status: status}, nil
}

func (f *fakeScanner) ScannerMetadata() ports.ScannerMetadata {
	return ports.ScannerMetadata{Name: "fake-scanner", Version: "v1.0.0"}
}

type fakeDatabase struct {
	snapshot    domain.DatabaseSnapshot
	content     string
	vulnerables map[fetchdomain.ModuleCoordinate][]string
	// findings, when set for a coordinate, is returned verbatim by
	// LookupFindings; otherwise LookupFindings synthesises bare findings from
	// the vulnerables IDs so tests that only populate vulnerables still exercise
	// the metadata path.
	findings map[fetchdomain.ModuleCoordinate][]domain.VulnerabilityFinding
	err      error
}

func (f *fakeDatabase) Snapshot(_ context.Context) (domain.DatabaseSnapshot, io.ReadCloser, error) {
	if f.err != nil {
		return domain.DatabaseSnapshot{}, nil, f.err
	}
	return f.snapshot, io.NopCloser(strings.NewReader(f.content)), nil
}

func (f *fakeDatabase) GetSnapshot(_ context.Context, identity domain.DatabaseSnapshot) (io.ReadCloser, error) {
	if identity.Version == f.snapshot.Version {
		return io.NopCloser(strings.NewReader(f.content)), nil
	}
	return nil, io.EOF
}

func (f *fakeDatabase) CheckVulnerable(_ context.Context, modules []fetchdomain.ModuleCoordinate) (map[fetchdomain.ModuleCoordinate][]string, error) {
	if f.err != nil {
		return nil, f.err
	}
	res := make(map[fetchdomain.ModuleCoordinate][]string)
	for _, m := range modules {
		if vulns, ok := f.vulnerables[m]; ok {
			res[m] = vulns
		}
	}
	return res, nil
}

func (f *fakeDatabase) LookupFindings(_ context.Context, coord fetchdomain.ModuleCoordinate) ([]domain.VulnerabilityFinding, error) {
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

func (s *callCountingScanner) Scan(ctx context.Context, coord fetchdomain.ModuleCoordinate, src io.Reader, snap domain.DatabaseSnapshot, goModCache string, dbDir string, scanMode domain.ScanMode) (domain.VulnerabilityRecord, error) {
	*s.called = true
	rec, err := s.inner.Scan(ctx, coord, src, snap, goModCache, dbDir, scanMode)
	if err != nil {
		return domain.VulnerabilityRecord{}, fmt.Errorf("inner scan: %w", err)
	}
	return rec, nil
}

func (s *callCountingScanner) ScanProject(ctx context.Context, dir string, snap domain.DatabaseSnapshot, dbDir string) (domain.ProjectScanResult, error) {
	res, err := s.inner.ScanProject(ctx, dir, snap, dbDir)
	if err != nil {
		return domain.ProjectScanResult{}, fmt.Errorf("inner scan project: %w", err)
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
	loadErr error
}

func (f *fakeCallGraphLoader) setPresent(v bool) {
	f.mu.Lock()
	f.present = v
	f.mu.Unlock()
}

func (f *fakeCallGraphLoader) Load(_ context.Context, _ fetchdomain.ModuleCoordinate) (ports.CallGraphProjection, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.loadErr != nil {
		return ports.CallGraphProjection{}, f.loadErr
	}
	if !f.present {
		return ports.CallGraphProjection{}, fmt.Errorf("%w: test coord", ports.ErrCallGraphNotFound)
	}
	return ports.CallGraphProjection{}, nil
}

// fakeCallGraphSpawner implements ports.CallGraphSpawner and records all invocations.
type fakeCallGraphSpawner struct {
	mu     sync.Mutex
	calls  []fetchdomain.ModuleCoordinate
	err    error
	stderr []byte
	// onSpawn is called just before returning, allowing the test to mutate loader state.
	onSpawn func()
}

func (f *fakeCallGraphSpawner) Spawn(_ context.Context, coord fetchdomain.ModuleCoordinate, _ bool) ([]byte, error) {
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
	mu      sync.Mutex
	calls   int
	result  domain.ReachabilityResult
	err     error
}

func (f *fakeReachabilityAnalyser) Analyse(_ context.Context, _ fetchdomain.ModuleCoordinate, _ []ports.SymbolReference, _ ports.CallGraphLoader) (domain.ReachabilityResult, error) {
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
