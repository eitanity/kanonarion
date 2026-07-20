package application_test

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"strings"
	"testing"
	"time"

	fetchdomain "github.com/eitanity/kanonarion/internal/fetch/domain"
	licensedomain "github.com/eitanity/kanonarion/internal/license/domain"
	licenseports "github.com/eitanity/kanonarion/internal/license/ports"
	"github.com/eitanity/kanonarion/internal/sbom/application"
	"github.com/eitanity/kanonarion/internal/sbom/domain"
	"github.com/eitanity/kanonarion/internal/sbom/ports"
	vulndomain "github.com/eitanity/kanonarion/internal/vuln/domain"
	walkdomain "github.com/eitanity/kanonarion/internal/walk/domain"
	walkports "github.com/eitanity/kanonarion/internal/walk/ports"
)

// ---- fakes ----

type fakeWalkStore struct {
	walk walkdomain.WalkRecord
	err  error
}

func (f *fakeWalkStore) PutWalk(_ context.Context, _ walkdomain.WalkRecord) error { return nil }
func (f *fakeWalkStore) GetWalk(_ context.Context, _ string) (walkdomain.WalkRecord, error) {
	return f.walk, f.err
}
func (f *fakeWalkStore) ListWalks(_ context.Context, _ walkports.WalkFilter) ([]walkports.WalkSummary, error) {
	return nil, nil
}

// testLicensePipelineVersion is the licence extraction pipeline version used
// in tests; deliberately different from the SBOM pipeline version ("0.3.0")
// so a lookup under the wrong version cannot accidentally succeed.
const testLicensePipelineVersion = "1.0.0"

type fakeLicenseStore struct {
	// records is keyed by coordinate; entries are only served when the lookup
	// names pipelineVersion, mirroring the real store's exact-match semantics.
	records         map[fetchdomain.ModuleCoordinate]licensedomain.LicenseRecord
	pipelineVersion string
	err             error
}

func (f *fakeLicenseStore) PutLicenseRecord(_ context.Context, _ licensedomain.LicenseRecord) error {
	return nil
}
func (f *fakeLicenseStore) GetLicenseRecord(_ context.Context, coord fetchdomain.ModuleCoordinate, pv string) (licensedomain.LicenseRecord, bool, error) {
	if f.err != nil {
		return licensedomain.LicenseRecord{}, false, f.err
	}
	if f.records == nil || pv != f.pipelineVersion {
		return licensedomain.LicenseRecord{}, false, nil
	}
	r, ok := f.records[coord]
	return r, ok, nil
}
func (f *fakeLicenseStore) ListLicenseRecords(_ context.Context, _ licenseports.LicenseFilter) ([]licenseports.LicenseSummary, error) {
	return nil, nil
}

type fakeVulnStore struct {
	run     vulndomain.WalkScanRun
	runOK   bool
	runErr  error
	recs    []vulndomain.VulnerabilityRecord
	recsErr error
}

func (f *fakeVulnStore) PutVulnerabilityRecord(_ context.Context, _ vulndomain.VulnerabilityRecord) error {
	return nil
}
func (f *fakeVulnStore) GetVulnerabilityRecord(_ context.Context, _ fetchdomain.ModuleCoordinate, _ string, _ vulndomain.DatabaseSnapshot) (vulndomain.VulnerabilityRecord, bool, error) {
	return vulndomain.VulnerabilityRecord{}, false, nil
}
func (f *fakeVulnStore) ListVulnerabilityRecordsByFindingID(_ context.Context, _ string) ([]vulndomain.VulnerabilityRecord, error) {
	return nil, nil
}
func (f *fakeVulnStore) ListVulnerabilityRecords(_ context.Context, _ string) ([]vulndomain.VulnerabilityRecord, error) {
	return f.recs, f.recsErr
}
func (f *fakeVulnStore) PutWalkScanRun(_ context.Context, _ vulndomain.WalkScanRun) error {
	return nil
}
func (f *fakeVulnStore) GetWalkScanRun(_ context.Context, _ string) (vulndomain.WalkScanRun, bool, error) {
	return f.run, f.runOK, f.runErr
}
func (f *fakeVulnStore) ListWalkScanRuns(_ context.Context, _ string) ([]vulndomain.WalkScanRun, error) {
	return nil, nil
}
func (f *fakeVulnStore) ListAllWalkScanRuns(_ context.Context) ([]vulndomain.WalkScanRun, error) {
	return nil, nil
}
func (f *fakeVulnStore) PutDatabaseSnapshot(_ context.Context, _ vulndomain.DatabaseSnapshot, _ io.Reader) error {
	return nil
}
func (f *fakeVulnStore) GetDatabaseSnapshot(_ context.Context, _ vulndomain.DatabaseSnapshot) (io.ReadCloser, error) {
	return nil, nil
}
func (f *fakeVulnStore) GetLatestDatabaseSnapshot(_ context.Context) (vulndomain.DatabaseSnapshot, bool, error) {
	return vulndomain.DatabaseSnapshot{}, false, nil
}
func (f *fakeVulnStore) ListDatabaseSnapshots(_ context.Context) ([]vulndomain.DatabaseSnapshot, error) {
	return nil, nil
}
func (f *fakeVulnStore) GetLatestVulnerabilityRecord(_ context.Context, _ fetchdomain.ModuleCoordinate, _ string) (vulndomain.VulnerabilityRecord, bool, error) {
	return vulndomain.VulnerabilityRecord{}, false, nil
}
func (f *fakeVulnStore) GetLatestVulnerabilityRecordForWalk(_ context.Context, _ fetchdomain.ModuleCoordinate, _ string, _ string) (vulndomain.VulnerabilityRecord, bool, error) {
	return vulndomain.VulnerabilityRecord{}, false, nil
}
func (f *fakeVulnStore) ListVulnerabilityRecordsForModule(_ context.Context, _ fetchdomain.ModuleCoordinate, _ string) ([]vulndomain.VulnerabilityRecord, error) {
	return nil, nil
}

type fakeSBOMStore struct {
	cached   domain.SBOMRecord
	cachedOK bool
	findErr  error
	putErr   error
	stored   *domain.SBOMRecord
}

func (f *fakeSBOMStore) FindSBOMRecord(_ context.Context, _ string, _ *string, _ domain.SBOMFormat, _ string) (domain.SBOMRecord, bool, error) {
	return f.cached, f.cachedOK, f.findErr
}
func (f *fakeSBOMStore) PutSBOMRecord(_ context.Context, r domain.SBOMRecord) error {
	f.stored = &r
	return f.putErr
}
func (f *fakeSBOMStore) GetSBOMRecord(_ context.Context, _ string) (domain.SBOMRecord, error) {
	return domain.SBOMRecord{}, ports.ErrSBOMNotFound
}
func (f *fakeSBOMStore) ListSBOMRecords(_ context.Context, _ string) ([]domain.SBOMRecord, error) {
	return nil, nil
}

type fakeSBOMGenerator struct {
	record           domain.SBOMRecord
	err              error
	capturedNodes    []walkdomain.GraphNode
	capturedEdges    []walkdomain.GraphEdge
	capturedLicenses map[fetchdomain.ModuleCoordinate]licensedomain.LicenseRecord
}

func (f *fakeSBOMGenerator) Generate(_ context.Context, walk walkdomain.WalkRecord, licenses map[fetchdomain.ModuleCoordinate]licensedomain.LicenseRecord, _ []vulndomain.VulnerabilityRecord, _ ports.GenerateRequest) (domain.SBOMRecord, error) {
	f.capturedNodes = walk.Graph.Nodes
	f.capturedEdges = walk.Graph.Edges
	f.capturedLicenses = licenses
	return f.record, f.err
}
func (f *fakeSBOMGenerator) GeneratorMetadata() ports.GeneratorMetadata {
	return ports.GeneratorMetadata{Name: "fake", Version: "0.0.1"}
}

type fakeClock struct{}

func (f fakeClock) Now() time.Time { return time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC) }

// ---- helpers ----

func makeWalk(id string) walkdomain.WalkRecord {
	coord, _ := fetchdomain.NewModuleCoordinate("example.com/mod", "v1.0.0")
	return walkdomain.WalkRecord{
		ID: id,
		Graph: walkdomain.Graph{
			Target: coord,
			Nodes:  []walkdomain.GraphNode{{Coordinate: coord}},
		},
	}
}

func makeMultiNodeWalk(id string, coords []fetchdomain.ModuleCoordinate) walkdomain.WalkRecord {
	nodes := make([]walkdomain.GraphNode, len(coords))
	for i, c := range coords {
		nodes[i] = walkdomain.GraphNode{Coordinate: c}
	}
	return walkdomain.WalkRecord{
		ID: id,
		Graph: walkdomain.Graph{
			Target: coords[0],
			Nodes:  nodes,
		},
	}
}

func makeUC(ws *fakeWalkStore, vs *fakeVulnStore, ss *fakeSBOMStore, gen *fakeSBOMGenerator) *application.GenerateSBOMUseCase {
	return makeUCWithLicenses(ws, &fakeLicenseStore{}, vs, ss, gen)
}

func makeUCWithLicenses(ws *fakeWalkStore, ls *fakeLicenseStore, vs *fakeVulnStore, ss *fakeSBOMStore, gen *fakeSBOMGenerator) *application.GenerateSBOMUseCase {
	return application.NewGenerateSBOMUseCase(
		ws,
		ls,
		vs,
		ss,
		gen,
		fakeClock{},
		"0.3.0",
		testLicensePipelineVersion,
		slog.Default(),
	)
}

// ---- tests ----

func TestGenerateSBOM_CacheHit(t *testing.T) {
	cached := domain.SBOMRecord{ID: "sbom-cached", WalkID: "walk-1"}
	ss := &fakeSBOMStore{cached: cached, cachedOK: true}
	uc := makeUC(&fakeWalkStore{}, &fakeVulnStore{}, ss, &fakeSBOMGenerator{})

	got, err := uc.Generate(t.Context(), application.SBOMRequest{WalkID: "walk-1"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got.ID != "sbom-cached" {
		t.Errorf("expected cached record, got %q", got.ID)
	}
}

func TestGenerateSBOM_WalkNotFound(t *testing.T) {
	ws := &fakeWalkStore{err: walkports.ErrWalkNotFound}
	uc := makeUC(ws, &fakeVulnStore{}, &fakeSBOMStore{}, &fakeSBOMGenerator{})

	_, err := uc.Generate(t.Context(), application.SBOMRequest{WalkID: "walk-missing"})
	if err == nil {
		t.Fatal("expected error, got nil")
	}
}

func TestGenerateSBOM_NoVulns(t *testing.T) {
	ws := &fakeWalkStore{walk: makeWalk("walk-1")}
	ss := &fakeSBOMStore{}
	expected := domain.SBOMRecord{ID: "sbom-1", WalkID: "walk-1", Content: []byte(`{}`)}
	gen := &fakeSBOMGenerator{record: expected}
	uc := makeUC(ws, &fakeVulnStore{}, ss, gen)

	got, err := uc.Generate(t.Context(), application.SBOMRequest{WalkID: "walk-1"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got.ID != "sbom-1" {
		t.Errorf("expected sbom-1, got %q", got.ID)
	}
	if ss.stored == nil {
		t.Error("expected record to be persisted")
	}
}

func TestGenerateSBOM_WithScanRun(t *testing.T) {
	ws := &fakeWalkStore{walk: makeWalk("walk-1")}
	scanRunID := "run-1"
	vs := &fakeVulnStore{
		run:   vulndomain.WalkScanRun{ID: "run-1", WalkID: "walk-1"},
		runOK: true,
		recs:  []vulndomain.VulnerabilityRecord{},
	}
	ss := &fakeSBOMStore{}
	expected := domain.SBOMRecord{ID: "sbom-2", WalkID: "walk-1"}
	gen := &fakeSBOMGenerator{record: expected}
	uc := makeUC(ws, vs, ss, gen)

	got, err := uc.Generate(t.Context(), application.SBOMRequest{WalkID: "walk-1", WalkScanRunID: &scanRunID})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got.ID != "sbom-2" {
		t.Errorf("expected sbom-2, got %q", got.ID)
	}
}

func TestGenerateSBOM_ScanRunNotFound(t *testing.T) {
	ws := &fakeWalkStore{walk: makeWalk("walk-1")}
	scanRunID := "run-missing"
	vs := &fakeVulnStore{runOK: false}
	uc := makeUC(ws, vs, &fakeSBOMStore{}, &fakeSBOMGenerator{})

	_, err := uc.Generate(t.Context(), application.SBOMRequest{WalkID: "walk-1", WalkScanRunID: &scanRunID})
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !errors.Is(err, application.ErrWalkScanRunNotFound) {
		t.Errorf("expected ErrWalkScanRunNotFound, got %v", err)
	}
}

func TestGenerateSBOM_Force(t *testing.T) {
	cached := domain.SBOMRecord{ID: "sbom-cached", WalkID: "walk-1"}
	ss := &fakeSBOMStore{cached: cached, cachedOK: true}
	ws := &fakeWalkStore{walk: makeWalk("walk-1")}
	fresh := domain.SBOMRecord{ID: "sbom-fresh", WalkID: "walk-1", Content: []byte(`{}`)}
	gen := &fakeSBOMGenerator{record: fresh}
	uc := makeUC(ws, &fakeVulnStore{}, ss, gen)

	got, err := uc.Generate(t.Context(), application.SBOMRequest{WalkID: "walk-1", Force: true})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got.ID != "sbom-fresh" {
		t.Errorf("expected fresh record when Force=true, got %q", got.ID)
	}
}

// TestGenerateSBOM_AllowList verifies that AllowList restricts components to the
// binary's import closure: only listed modules reach the generator, the cache is
// bypassed, and the scoped result is not persisted.
func TestGenerateSBOM_AllowList(t *testing.T) {
	coordA, _ := fetchdomain.NewModuleCoordinate("example.com/a", "v1.0.0")
	coordB, _ := fetchdomain.NewModuleCoordinate("example.com/b", "v2.0.0")
	coordC, _ := fetchdomain.NewModuleCoordinate("example.com/c", "v3.0.0")

	// Walk has three modules; only A and B are in the binary's import closure.
	ws := &fakeWalkStore{walk: makeMultiNodeWalk("walk-1", []fetchdomain.ModuleCoordinate{coordA, coordB, coordC})}

	// Cache has a hit — AllowList should bypass it.
	cached := domain.SBOMRecord{ID: "sbom-cached", WalkID: "walk-1"}
	ss := &fakeSBOMStore{cached: cached, cachedOK: true}

	gen := &fakeSBOMGenerator{record: domain.SBOMRecord{ID: "sbom-scoped", WalkID: "walk-1", Content: []byte(`{}`)}}
	uc := makeUC(ws, &fakeVulnStore{}, ss, gen)

	_, err := uc.Generate(t.Context(), application.SBOMRequest{
		WalkID:    "walk-1",
		AllowList: []fetchdomain.ModuleCoordinate{coordA, coordB},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Generator must have received only the two allowed nodes.
	if len(gen.capturedNodes) != 2 {
		t.Fatalf("generator received %d nodes, want 2", len(gen.capturedNodes))
	}
	nodeCoords := map[fetchdomain.ModuleCoordinate]bool{}
	for _, n := range gen.capturedNodes {
		nodeCoords[n.Coordinate] = true
	}
	if !nodeCoords[coordA] || !nodeCoords[coordB] {
		t.Errorf("expected nodes A and B, got %v", gen.capturedNodes)
	}
	if nodeCoords[coordC] {
		t.Errorf("node C must be excluded by AllowList")
	}

	// Scoped result must NOT be persisted.
	if ss.stored != nil {
		t.Error("scoped SBOM must not be persisted to the store")
	}
}

// The synthetic stdlib node is a universal build input that no `go list -deps`
// closure reports, so it is never in a --package allow-list. The scoped filter
// must keep it anyway; otherwise a --package SBOM silently omits the standard
// library (and the --stdlib-from-gomod-pinned Go version the release depends on).
func TestGenerateSBOM_AllowListKeepsStdlibNode(t *testing.T) {
	coordA, _ := fetchdomain.NewModuleCoordinate("example.com/a", "v1.0.0")
	stdlib, _ := fetchdomain.NewModuleCoordinate(walkdomain.StdlibModulePath, "v1.22")

	// Walk carries A, the stdlib node, and a root->stdlib edge, mirroring what
	// injectStdlib produces. The allow-list holds only A (stdlib is never listed).
	walk := makeMultiNodeWalk("walk-1", []fetchdomain.ModuleCoordinate{coordA, stdlib})
	walk.Graph.Edges = []walkdomain.GraphEdge{{From: coordA, To: stdlib}}
	ws := &fakeWalkStore{walk: walk}
	gen := &fakeSBOMGenerator{record: domain.SBOMRecord{ID: "sbom-scoped", WalkID: "walk-1", Content: []byte(`{}`)}}
	uc := makeUC(ws, &fakeVulnStore{}, &fakeSBOMStore{}, gen)

	if _, err := uc.Generate(t.Context(), application.SBOMRequest{
		WalkID:    "walk-1",
		AllowList: []fetchdomain.ModuleCoordinate{coordA},
	}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	got := map[fetchdomain.ModuleCoordinate]bool{}
	for _, n := range gen.capturedNodes {
		got[n.Coordinate] = true
	}
	if !got[coordA] {
		t.Errorf("allowed module A must be present, got %v", gen.capturedNodes)
	}
	if !got[stdlib] {
		t.Errorf("stdlib node must survive the allow-list filter, got %v", gen.capturedNodes)
	}
}

// A module-replace-to-fork node is keyed by its replacement coordinate in
// Coordinate, but `go list -deps` reports the dependency at its original
// require coordinate, so the --package allow-list only ever holds the original.
// The scoped filter must keep such a node via its OriginalCoordinate; matching
// only Coordinate silently drops the fork (e.g. mattn/go-sqlite3 =>
// rqlite/go-sqlite3), losing its whole capability and licence surface even
// though it is linked into the binary.
func TestGenerateSBOM_AllowListKeepsReplaceToForkNode(t *testing.T) {
	orig, _ := fetchdomain.NewModuleCoordinate("github.com/mattn/go-sqlite3", "v1.14.44")
	fork, _ := fetchdomain.NewModuleCoordinate("github.com/rqlite/go-sqlite3", "v1.47.0")
	rootDep, _ := fetchdomain.NewModuleCoordinate("example.com/a", "v1.0.0")

	// The graph carries the fork node keyed by its replacement coordinate, with
	// the original require coordinate in OriginalCoordinate, plus an edge from a
	// root dep keyed by the replacement path (how the resolver records edges).
	walk := makeMultiNodeWalk("walk-1", []fetchdomain.ModuleCoordinate{rootDep, fork})
	walk.Graph.Nodes[1].OriginalCoordinate = orig
	walk.Graph.Edges = []walkdomain.GraphEdge{{From: rootDep, To: fork}}
	ws := &fakeWalkStore{walk: walk}
	gen := &fakeSBOMGenerator{record: domain.SBOMRecord{ID: "sbom-scoped", WalkID: "walk-1", Content: []byte(`{}`)}}
	uc := makeUC(ws, &fakeVulnStore{}, &fakeSBOMStore{}, gen)

	// The allow-list holds the ORIGINAL coordinate, as `go list -deps` reports it.
	if _, err := uc.Generate(t.Context(), application.SBOMRequest{
		WalkID:    "walk-1",
		AllowList: []fetchdomain.ModuleCoordinate{rootDep, orig},
	}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	got := map[fetchdomain.ModuleCoordinate]bool{}
	for _, n := range gen.capturedNodes {
		got[n.Coordinate] = true
	}
	if !got[fork] {
		t.Errorf("replace-to-fork node %s must survive the allow-list via its original coordinate, got %v", fork, gen.capturedNodes)
	}
	if len(gen.capturedEdges) != 1 {
		t.Errorf("edge to the retained fork node must survive, got %v", gen.capturedEdges)
	}
}

// Licence records persist under the licence extraction pipeline version, not
// the SBOM's own pipeline version. The lookup must use the former: when the
// two diverge, looking up under the SBOM version misses every record and the
// generated SBOM silently carries no licences.
func TestGenerateSBOM_LooksUpLicencesUnderLicencePipelineVersion(t *testing.T) {
	coord, _ := fetchdomain.NewModuleCoordinate("example.com/mod", "v1.0.0")
	ws := &fakeWalkStore{walk: makeWalk("walk-1")}
	ls := &fakeLicenseStore{
		pipelineVersion: testLicensePipelineVersion,
		records: map[fetchdomain.ModuleCoordinate]licensedomain.LicenseRecord{
			coord: {Coordinate: coord, PrimarySPDX: "MIT", PipelineVersion: testLicensePipelineVersion},
		},
	}
	gen := &fakeSBOMGenerator{record: domain.SBOMRecord{ID: "sbom-1", WalkID: "walk-1"}}

	uc := makeUCWithLicenses(ws, ls, &fakeVulnStore{}, &fakeSBOMStore{}, gen)
	if _, err := uc.Generate(t.Context(), application.SBOMRequest{WalkID: "walk-1"}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	rec, ok := gen.capturedLicenses[coord]
	if !ok {
		t.Fatal("generator received no licence record for the walk's module; lookup used the wrong pipeline version")
	}
	if rec.PrimarySPDX != "MIT" {
		t.Errorf("PrimarySPDX: got %q, want MIT", rec.PrimarySPDX)
	}
}

// A scoped request prunes edges whose endpoints fall outside the allow-list,
// so the generated graph never references a component that was filtered out.
func TestGenerateSBOM_AllowListPrunesDanglingEdges(t *testing.T) {
	coordA, _ := fetchdomain.NewModuleCoordinate("example.com/a", "v1.0.0")
	coordB, _ := fetchdomain.NewModuleCoordinate("example.com/b", "v2.0.0")

	walk := makeMultiNodeWalk("walk-1", []fetchdomain.ModuleCoordinate{coordA, coordB})
	// A depends on B; scoping to {A} must drop both node B and the A->B edge.
	walk.Graph.Edges = []walkdomain.GraphEdge{{From: coordA, To: coordB}}
	ws := &fakeWalkStore{walk: walk}
	gen := &fakeSBOMGenerator{record: domain.SBOMRecord{ID: "sbom-scoped", WalkID: "walk-1", Content: []byte(`{}`)}}
	uc := makeUC(ws, &fakeVulnStore{}, &fakeSBOMStore{}, gen)

	if _, err := uc.Generate(t.Context(), application.SBOMRequest{
		WalkID:    "walk-1",
		AllowList: []fetchdomain.ModuleCoordinate{coordA},
	}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(gen.capturedNodes) != 1 {
		t.Fatalf("generator received %d nodes, want 1 (A only)", len(gen.capturedNodes))
	}
	if len(gen.capturedEdges) != 0 {
		t.Errorf("dangling edge A->B must be pruned, got %v", gen.capturedEdges)
	}
}

// ---- error propagation ----

func TestGenerateSBOM_CacheLookupError(t *testing.T) {
	ss := &fakeSBOMStore{findErr: errors.New("db down")}
	uc := makeUC(&fakeWalkStore{walk: makeWalk("walk-1")}, &fakeVulnStore{}, ss, &fakeSBOMGenerator{})
	_, err := uc.Generate(t.Context(), application.SBOMRequest{WalkID: "walk-1"})
	if err == nil || !strings.Contains(err.Error(), "checking sbom cache") {
		t.Fatalf("want cache-lookup error, got: %v", err)
	}
}

func TestGenerateSBOM_LicenseLoadError(t *testing.T) {
	ls := &fakeLicenseStore{err: errors.New("licence store down")}
	uc := makeUCWithLicenses(&fakeWalkStore{walk: makeWalk("walk-1")}, ls, &fakeVulnStore{}, &fakeSBOMStore{}, &fakeSBOMGenerator{})
	_, err := uc.Generate(t.Context(), application.SBOMRequest{WalkID: "walk-1"})
	if err == nil || !strings.Contains(err.Error(), "loading license") {
		t.Fatalf("want licence-load error, got: %v", err)
	}
}

func TestGenerateSBOM_ScanRunLookupError(t *testing.T) {
	scanRunID := "scan-1"
	vs := &fakeVulnStore{runErr: errors.New("scan run store down")}
	uc := makeUC(&fakeWalkStore{walk: makeWalk("walk-1")}, vs, &fakeSBOMStore{}, &fakeSBOMGenerator{})
	_, err := uc.Generate(t.Context(), application.SBOMRequest{WalkID: "walk-1", WalkScanRunID: &scanRunID})
	if err == nil || !strings.Contains(err.Error(), "loading scan run") {
		t.Fatalf("want scan-run lookup error, got: %v", err)
	}
}

func TestGenerateSBOM_VulnRecordsError(t *testing.T) {
	scanRunID := "scan-1"
	vs := &fakeVulnStore{runOK: true, recsErr: errors.New("vuln records down")}
	uc := makeUC(&fakeWalkStore{walk: makeWalk("walk-1")}, vs, &fakeSBOMStore{}, &fakeSBOMGenerator{})
	_, err := uc.Generate(t.Context(), application.SBOMRequest{WalkID: "walk-1", WalkScanRunID: &scanRunID})
	if err == nil || !strings.Contains(err.Error(), "loading vulnerability records") {
		t.Fatalf("want vuln-records error, got: %v", err)
	}
}

func TestGenerateSBOM_GeneratorError(t *testing.T) {
	gen := &fakeSBOMGenerator{err: errors.New("marshal failed")}
	uc := makeUC(&fakeWalkStore{walk: makeWalk("walk-1")}, &fakeVulnStore{}, &fakeSBOMStore{}, gen)
	_, err := uc.Generate(t.Context(), application.SBOMRequest{WalkID: "walk-1"})
	if err == nil || !strings.Contains(err.Error(), "generating sbom") {
		t.Fatalf("want generator error, got: %v", err)
	}
}

func TestGenerateSBOM_PersistError(t *testing.T) {
	ss := &fakeSBOMStore{putErr: errors.New("disk full")}
	gen := &fakeSBOMGenerator{record: domain.SBOMRecord{ID: "sbom-1", WalkID: "walk-1", Content: []byte(`{}`)}}
	uc := makeUC(&fakeWalkStore{walk: makeWalk("walk-1")}, &fakeVulnStore{}, ss, gen)
	_, err := uc.Generate(t.Context(), application.SBOMRequest{WalkID: "walk-1"})
	if err == nil || !strings.Contains(err.Error(), "persisting sbom record") {
		t.Fatalf("want persist error, got: %v", err)
	}
}
