package application_test

import (
	"context"
	"errors"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/eitanity/kanonarion/internal/coordinate"

	licensedomain "github.com/eitanity/kanonarion/internal/license/domain"
	licenseports "github.com/eitanity/kanonarion/internal/license/ports"
	"github.com/eitanity/kanonarion/internal/sbom/application"
	"github.com/eitanity/kanonarion/internal/sbom/domain"
	"github.com/eitanity/kanonarion/internal/sbom/ports"
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
	records         map[coordinate.ModuleCoordinate]licensedomain.LicenseRecord
	pipelineVersion string
	err             error
}

func (f *fakeLicenseStore) PutLicenseRecord(_ context.Context, _ licensedomain.LicenseRecord) error {
	return nil
}
func (f *fakeLicenseStore) GetLicenseRecord(_ context.Context, coord coordinate.ModuleCoordinate, pv string) (licensedomain.LicenseRecord, bool, error) {
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

type fakeSBOMStore struct {
	cached   domain.SBOMRecord
	cachedOK bool
	findErr  error
	putErr   error
	stored   *domain.SBOMRecord
}

func (f *fakeSBOMStore) FindSBOMRecord(_ context.Context, _ string, _ domain.SBOMFormat, _ string) (domain.SBOMRecord, bool, error) {
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
	capturedLicenses map[coordinate.ModuleCoordinate]licensedomain.LicenseRecord
	capturedReq      ports.GenerateRequest
}

func (f *fakeSBOMGenerator) Generate(_ context.Context, walk walkdomain.WalkRecord, licenses map[coordinate.ModuleCoordinate]licensedomain.LicenseRecord, req ports.GenerateRequest) (domain.SBOMRecord, error) {
	f.capturedReq = req
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
	coord, _ := coordinate.NewModuleCoordinate("example.com/mod", "v1.0.0")
	return walkdomain.WalkRecord{
		ID: id,
		Graph: walkdomain.Graph{
			Target: coord,
			Nodes:  []walkdomain.GraphNode{{Coordinate: coord}},
		},
	}
}

func makeMultiNodeWalk(id string, coords []coordinate.ModuleCoordinate) walkdomain.WalkRecord {
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

func makeUC(ws *fakeWalkStore, ss *fakeSBOMStore, gen *fakeSBOMGenerator) *application.GenerateSBOMUseCase {
	return makeUCWithLicenses(ws, &fakeLicenseStore{}, ss, gen)
}

func makeUCWithLicenses(ws *fakeWalkStore, ls *fakeLicenseStore, ss *fakeSBOMStore, gen *fakeSBOMGenerator) *application.GenerateSBOMUseCase {
	return application.NewGenerateSBOMUseCase(
		ws,
		ls,
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
	uc := makeUC(&fakeWalkStore{}, ss, &fakeSBOMGenerator{})

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
	uc := makeUC(ws, &fakeSBOMStore{}, &fakeSBOMGenerator{})

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
	uc := makeUC(ws, ss, gen)

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

func TestGenerateSBOM_Force(t *testing.T) {
	cached := domain.SBOMRecord{ID: "sbom-cached", WalkID: "walk-1"}
	ss := &fakeSBOMStore{cached: cached, cachedOK: true}
	ws := &fakeWalkStore{walk: makeWalk("walk-1")}
	fresh := domain.SBOMRecord{ID: "sbom-fresh", WalkID: "walk-1", Content: []byte(`{}`)}
	gen := &fakeSBOMGenerator{record: fresh}
	uc := makeUC(ws, ss, gen)

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
	coordA, _ := coordinate.NewModuleCoordinate("example.com/a", "v1.0.0")
	coordB, _ := coordinate.NewModuleCoordinate("example.com/b", "v2.0.0")
	coordC, _ := coordinate.NewModuleCoordinate("example.com/c", "v3.0.0")

	// Walk has three modules; only A and B are in the binary's import closure.
	ws := &fakeWalkStore{walk: makeMultiNodeWalk("walk-1", []coordinate.ModuleCoordinate{coordA, coordB, coordC})}

	// Cache has a hit — AllowList should bypass it.
	cached := domain.SBOMRecord{ID: "sbom-cached", WalkID: "walk-1"}
	ss := &fakeSBOMStore{cached: cached, cachedOK: true}

	gen := &fakeSBOMGenerator{record: domain.SBOMRecord{ID: "sbom-scoped", WalkID: "walk-1", Content: []byte(`{}`)}}
	uc := makeUC(ws, ss, gen)

	_, err := uc.Generate(t.Context(), application.SBOMRequest{
		WalkID:    "walk-1",
		AllowList: []coordinate.ModuleCoordinate{coordA, coordB},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Generator must have received only the two allowed nodes.
	if len(gen.capturedNodes) != 2 {
		t.Fatalf("generator received %d nodes, want 2", len(gen.capturedNodes))
	}
	nodeCoords := map[coordinate.ModuleCoordinate]bool{}
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
	coordA, _ := coordinate.NewModuleCoordinate("example.com/a", "v1.0.0")
	stdlib, _ := coordinate.NewModuleCoordinate(walkdomain.StdlibModulePath, "v1.22")

	// Walk carries A, the stdlib node, and a root->stdlib edge, mirroring what
	// injectStdlib produces. The allow-list holds only A (stdlib is never listed).
	walk := makeMultiNodeWalk("walk-1", []coordinate.ModuleCoordinate{coordA, stdlib})
	walk.Graph.Edges = []walkdomain.GraphEdge{{From: coordA, To: stdlib}}
	ws := &fakeWalkStore{walk: walk}
	gen := &fakeSBOMGenerator{record: domain.SBOMRecord{ID: "sbom-scoped", WalkID: "walk-1", Content: []byte(`{}`)}}
	uc := makeUC(ws, &fakeSBOMStore{}, gen)

	if _, err := uc.Generate(t.Context(), application.SBOMRequest{
		WalkID:    "walk-1",
		AllowList: []coordinate.ModuleCoordinate{coordA},
	}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	got := map[coordinate.ModuleCoordinate]bool{}
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
	orig, _ := coordinate.NewModuleCoordinate("github.com/mattn/go-sqlite3", "v1.14.44")
	fork, _ := coordinate.NewModuleCoordinate("github.com/rqlite/go-sqlite3", "v1.47.0")
	rootDep, _ := coordinate.NewModuleCoordinate("example.com/a", "v1.0.0")

	// The graph carries the fork node keyed by its replacement coordinate, with
	// the original require coordinate in OriginalCoordinate, plus an edge from a
	// root dep keyed by the replacement path (how the resolver records edges).
	walk := makeMultiNodeWalk("walk-1", []coordinate.ModuleCoordinate{rootDep, fork})
	walk.Graph.Nodes[1].OriginalCoordinate = orig
	walk.Graph.Edges = []walkdomain.GraphEdge{{From: rootDep, To: fork}}
	ws := &fakeWalkStore{walk: walk}
	gen := &fakeSBOMGenerator{record: domain.SBOMRecord{ID: "sbom-scoped", WalkID: "walk-1", Content: []byte(`{}`)}}
	uc := makeUC(ws, &fakeSBOMStore{}, gen)

	// The allow-list holds the ORIGINAL coordinate, as `go list -deps` reports it.
	if _, err := uc.Generate(t.Context(), application.SBOMRequest{
		WalkID:    "walk-1",
		AllowList: []coordinate.ModuleCoordinate{rootDep, orig},
	}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	got := map[coordinate.ModuleCoordinate]bool{}
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
	coord, _ := coordinate.NewModuleCoordinate("example.com/mod", "v1.0.0")
	ws := &fakeWalkStore{walk: makeWalk("walk-1")}
	ls := &fakeLicenseStore{
		pipelineVersion: testLicensePipelineVersion,
		records: map[coordinate.ModuleCoordinate]licensedomain.LicenseRecord{
			coord: {Coordinate: coord, PrimarySPDX: "MIT", PipelineVersion: testLicensePipelineVersion},
		},
	}
	gen := &fakeSBOMGenerator{record: domain.SBOMRecord{ID: "sbom-1", WalkID: "walk-1"}}

	uc := makeUCWithLicenses(ws, ls, &fakeSBOMStore{}, gen)
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
	coordA, _ := coordinate.NewModuleCoordinate("example.com/a", "v1.0.0")
	coordB, _ := coordinate.NewModuleCoordinate("example.com/b", "v2.0.0")

	walk := makeMultiNodeWalk("walk-1", []coordinate.ModuleCoordinate{coordA, coordB})
	// A depends on B; scoping to {A} must drop both node B and the A->B edge.
	walk.Graph.Edges = []walkdomain.GraphEdge{{From: coordA, To: coordB}}
	ws := &fakeWalkStore{walk: walk}
	gen := &fakeSBOMGenerator{record: domain.SBOMRecord{ID: "sbom-scoped", WalkID: "walk-1", Content: []byte(`{}`)}}
	uc := makeUC(ws, &fakeSBOMStore{}, gen)

	if _, err := uc.Generate(t.Context(), application.SBOMRequest{
		WalkID:    "walk-1",
		AllowList: []coordinate.ModuleCoordinate{coordA},
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
	uc := makeUC(&fakeWalkStore{walk: makeWalk("walk-1")}, ss, &fakeSBOMGenerator{})
	_, err := uc.Generate(t.Context(), application.SBOMRequest{WalkID: "walk-1"})
	if err == nil || !strings.Contains(err.Error(), "checking sbom cache") {
		t.Fatalf("want cache-lookup error, got: %v", err)
	}
}

func TestGenerateSBOM_LicenseLoadError(t *testing.T) {
	ls := &fakeLicenseStore{err: errors.New("licence store down")}
	uc := makeUCWithLicenses(&fakeWalkStore{walk: makeWalk("walk-1")}, ls, &fakeSBOMStore{}, &fakeSBOMGenerator{})
	_, err := uc.Generate(t.Context(), application.SBOMRequest{WalkID: "walk-1"})
	if err == nil || !strings.Contains(err.Error(), "loading license") {
		t.Fatalf("want licence-load error, got: %v", err)
	}
}

func TestGenerateSBOM_GeneratorError(t *testing.T) {
	gen := &fakeSBOMGenerator{err: errors.New("marshal failed")}
	uc := makeUC(&fakeWalkStore{walk: makeWalk("walk-1")}, &fakeSBOMStore{}, gen)
	_, err := uc.Generate(t.Context(), application.SBOMRequest{WalkID: "walk-1"})
	if err == nil || !strings.Contains(err.Error(), "generating sbom") {
		t.Fatalf("want generator error, got: %v", err)
	}
}

func TestGenerateSBOM_PersistError(t *testing.T) {
	ss := &fakeSBOMStore{putErr: errors.New("disk full")}
	gen := &fakeSBOMGenerator{record: domain.SBOMRecord{ID: "sbom-1", WalkID: "walk-1", Content: []byte(`{}`)}}
	uc := makeUC(&fakeWalkStore{walk: makeWalk("walk-1")}, ss, gen)
	_, err := uc.Generate(t.Context(), application.SBOMRequest{WalkID: "walk-1"})
	if err == nil || !strings.Contains(err.Error(), "persisting sbom record") {
		t.Fatalf("want persist error, got: %v", err)
	}
}

// ---- subject stamp (MainComponentVersion / MainComponentLicense) ----

// A request that names the document's subject is never answered from the
// cache. Serving the stored document would hand back another run's subject
// while silently discarding the one the caller supplied.
func TestGenerateSBOM_SubjectStampBypassesCache(t *testing.T) {
	for _, tc := range []struct {
		name string
		req  application.SBOMRequest
	}{
		{"version", application.SBOMRequest{WalkID: "walk-1", MainComponentVersion: "v1.2.3"}},
		{"licence", application.SBOMRequest{WalkID: "walk-1", MainComponentLicense: "Apache-2.0"}},
		{"both", application.SBOMRequest{WalkID: "walk-1", MainComponentVersion: "v1.2.3", MainComponentLicense: "Apache-2.0"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cached := domain.SBOMRecord{ID: "sbom-cached", WalkID: "walk-1"}
			ss := &fakeSBOMStore{cached: cached, cachedOK: true}
			fresh := domain.SBOMRecord{ID: "sbom-fresh", WalkID: "walk-1", Content: []byte(`{}`)}
			gen := &fakeSBOMGenerator{record: fresh}
			uc := makeUC(&fakeWalkStore{walk: makeWalk("walk-1")}, ss, gen)

			got, err := uc.Generate(t.Context(), tc.req)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got.ID != "sbom-fresh" {
				t.Errorf("a named subject must be generated, not served from cache: got %q", got.ID)
			}
			if gen.capturedReq.MainComponentVersion != tc.req.MainComponentVersion {
				t.Errorf("MainComponentVersion reaching the generator = %q, want %q",
					gen.capturedReq.MainComponentVersion, tc.req.MainComponentVersion)
			}
			if gen.capturedReq.MainComponentLicense != tc.req.MainComponentLicense {
				t.Errorf("MainComponentLicense reaching the generator = %q, want %q",
					gen.capturedReq.MainComponentLicense, tc.req.MainComponentLicense)
			}
		})
	}
}

// The other direction, and the dangerous one: a stamped document must never be
// written to the slot later callers read. If it were, a caller who names no
// subject at all would be handed the stamp of whoever generated last — a
// plausible version that is not theirs, in a distributed artefact.
func TestGenerateSBOM_SubjectStampIsNotPersisted(t *testing.T) {
	for _, tc := range []struct {
		name string
		req  application.SBOMRequest
	}{
		{"version", application.SBOMRequest{WalkID: "walk-1", MainComponentVersion: "v1.2.3"}},
		{"licence", application.SBOMRequest{WalkID: "walk-1", MainComponentLicense: "Apache-2.0"}},
		{"version with force", application.SBOMRequest{WalkID: "walk-1", MainComponentVersion: "v1.2.3", Force: true}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ss := &fakeSBOMStore{}
			gen := &fakeSBOMGenerator{record: domain.SBOMRecord{ID: "sbom-stamped", WalkID: "walk-1", Content: []byte(`{}`)}}
			uc := makeUC(&fakeWalkStore{walk: makeWalk("walk-1")}, ss, gen)

			if _, err := uc.Generate(t.Context(), tc.req); err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if ss.stored != nil {
				t.Errorf("a stamped document must not be stored, got record %q in the store", ss.stored.ID)
			}
		})
	}
}

// The guard is on the stamp, not on the command: a request that names no
// subject still uses the cache and still persists. Without this, closing the
// leak by never caching would go unnoticed.
func TestGenerateSBOM_NoSubjectStampStillCachesAndPersists(t *testing.T) {
	cached := domain.SBOMRecord{ID: "sbom-cached", WalkID: "walk-1"}
	ss := &fakeSBOMStore{cached: cached, cachedOK: true}
	uc := makeUC(&fakeWalkStore{walk: makeWalk("walk-1")}, ss, &fakeSBOMGenerator{})
	got, err := uc.Generate(t.Context(), application.SBOMRequest{WalkID: "walk-1"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got.ID != "sbom-cached" {
		t.Errorf("an unstamped request must still be served from cache, got %q", got.ID)
	}

	ss2 := &fakeSBOMStore{}
	gen := &fakeSBOMGenerator{record: domain.SBOMRecord{ID: "sbom-plain", WalkID: "walk-1", Content: []byte(`{}`)}}
	uc2 := makeUC(&fakeWalkStore{walk: makeWalk("walk-1")}, ss2, gen)
	if _, err := uc2.Generate(t.Context(), application.SBOMRequest{WalkID: "walk-1"}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if ss2.stored == nil {
		t.Error("an unstamped request must still persist its record")
	}
}

// fakeOriginReader answers from a fixed table, or fails.
type fakeOriginReader struct {
	origins map[coordinate.ModuleCoordinate]ports.ModuleOrigin
	err     error
	asked   []coordinate.ModuleCoordinate
}

func (f *fakeOriginReader) ModuleOrigin(
	_ context.Context, coord coordinate.ModuleCoordinate,
) (ports.ModuleOrigin, bool, error) {
	f.asked = append(f.asked, coord)
	if f.err != nil {
		return ports.ModuleOrigin{}, false, f.err
	}
	o, ok := f.origins[coord]
	return o, ok, nil
}

// TestGenerateSBOM_PassesRecordedOriginsForEveryNode verifies every module in the
// walk is asked about, and only the ones with something recorded reach the
// generator. A component's external references are built from this map and from
// nothing else, so a module missing from it asserts no origin.
func TestGenerateSBOM_PassesRecordedOriginsForEveryNode(t *testing.T) {
	withOrigin, _ := coordinate.NewModuleCoordinate("example.com/withorigin", "v1.0.0")
	without, _ := coordinate.NewModuleCoordinate("example.com/without", "v2.0.0")
	walk := makeMultiNodeWalk("walk-origins", []coordinate.ModuleCoordinate{withOrigin, without})
	ws := &fakeWalkStore{walk: walk}
	gen := &fakeSBOMGenerator{record: domain.SBOMRecord{ID: "sbom-1", WalkID: "walk-origins"}}
	origins := &fakeOriginReader{origins: map[coordinate.ModuleCoordinate]ports.ModuleOrigin{
		withOrigin: {VCSURL: "https://example.com/repo", VCSCommit: "abc"},
	}}
	uc := makeUC(ws, &fakeSBOMStore{}, gen).WithModuleOrigins(origins)

	if _, err := uc.Generate(t.Context(), application.SBOMRequest{
		WalkID: "walk-origins", Format: domain.CycloneDX16,
	}); err != nil {
		t.Fatalf("Generate: %v", err)
	}

	if len(origins.asked) != 2 {
		t.Errorf("asked about %d coordinates, want 2 (every node)", len(origins.asked))
	}
	got := gen.capturedReq.ModuleOrigins
	if len(got) != 1 {
		t.Fatalf("ModuleOrigins = %v, want exactly the one with a recorded origin", got)
	}
	if got[withOrigin].VCSURL != "https://example.com/repo" {
		t.Errorf("ModuleOrigins[%s] = %+v", withOrigin, got[withOrigin])
	}
}

// TestGenerateSBOM_OriginReadFailureFailsGeneration verifies a ledger that
// cannot answer stops the document rather than being read as "nothing recorded".
// A document that silently drops the modules it could not read is
// indistinguishable from one where nothing was ever measured.
func TestGenerateSBOM_OriginReadFailureFailsGeneration(t *testing.T) {
	walk := makeWalk("walk-origin-fail")
	ws := &fakeWalkStore{walk: walk}
	gen := &fakeSBOMGenerator{record: domain.SBOMRecord{ID: "sbom-1", WalkID: "walk-origin-fail"}}
	uc := makeUC(ws, &fakeSBOMStore{}, gen).
		WithModuleOrigins(&fakeOriginReader{err: errors.New("ledger disagrees with itself")})

	_, err := uc.Generate(t.Context(), application.SBOMRequest{
		WalkID: "walk-origin-fail", Format: domain.CycloneDX16,
	})
	if err == nil {
		t.Fatal("Generate succeeded; want the read failure reported")
	}
	if !strings.Contains(err.Error(), "ledger disagrees with itself") {
		t.Errorf("err = %v, want it to name the store failure", err)
	}
}
