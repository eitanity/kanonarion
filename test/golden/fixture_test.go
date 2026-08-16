package golden_test

// The hermetic fixture store every command golden is recorded against.
//
// Nothing here reaches the network, the operator's ~/.kanonarion, or the wall
// clock. The store is a real SQLite store built in a temp directory and seeded
// through the same domain seals production writes go through, so a fixture that
// could not be written by the product cannot be recorded by a golden either.
//
// The fixture set is chosen by what the goldens have to be able to EXPRESS, not
// by what is typical. Each of the five shapes below exists because a queued
// change composes several records into one answer, and a store holding one
// record per coordinate composes to the same answer before and after that
// change — which is the detector passing green through the thing it was built
// to see:
//
//   1. example.com/mod@v1.2.0 holds TWO fetch measurements of the same version,
//      re-fetched to different bytes, so a change to how artefact identities
//      compose has two records to disagree about.
//   2. example.com/mod@v1.2.0 is scanned against TWO advisory snapshots, so the
//      snapshot axis composes with the artefact axis rather than being the only
//      axis present.
//   3. vuln-show --history is recorded over that pair; history is where
//      multi-row composition is visible at all, since the point-in-time reads
//      hide it behind selection.
//   4. example.com/shallow@v1.0.0 is held go.mod-only — a verified go.mod and
//      no module zip — so the go.sum classification has a non-uniform value to
//      report instead of one repeated for every module.
//   5. example.com/quiet@v0.9.0 has NO publication date in the staleness
//      ledger. That is the exact shape that regressed unseen, and the fixture
//      exercises the zero rather than avoiding it.
//   6. example.com/mod@v1.2.0 holds TWO call-graph generations at DIFFERENT
//      completeness levels, the weaker one written last. The composed read must
//      serve the built graph rather than the newest one, and a store with one
//      generation per coordinate composes to the same answer before and after a
//      change to that ladder.

import (
	"archive/zip"
	"bytes"
	"context"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/mod/sumdb/dirhash"

	"github.com/eitanity/kanonarion/internal/adapters/blobstore/localfs"
	fetchsqlite "github.com/eitanity/kanonarion/internal/adapters/factstore/sqlite"
	cgsqlite "github.com/eitanity/kanonarion/internal/callgraph/adapters/store/sqlite"
	cgapp "github.com/eitanity/kanonarion/internal/callgraph/application"
	cgdomain "github.com/eitanity/kanonarion/internal/callgraph/domain"
	"github.com/eitanity/kanonarion/internal/coordinate"
	fetchapp "github.com/eitanity/kanonarion/internal/fetch/application"
	fetchdomain "github.com/eitanity/kanonarion/internal/fetch/domain"
	fetchports "github.com/eitanity/kanonarion/internal/fetch/ports"
	licsqlite "github.com/eitanity/kanonarion/internal/license/adapters/store/sqlite"
	licapp "github.com/eitanity/kanonarion/internal/license/application"
	licdomain "github.com/eitanity/kanonarion/internal/license/domain"
	"github.com/eitanity/kanonarion/internal/sqlitestore"
	stalesqlite "github.com/eitanity/kanonarion/internal/staleness/adapters/store/sqlite"
	staledomain "github.com/eitanity/kanonarion/internal/staleness/domain"
	vulnsqlite "github.com/eitanity/kanonarion/internal/vuln/adapters/store/sqlite"
	vulnapp "github.com/eitanity/kanonarion/internal/vuln/application"
	vulndomain "github.com/eitanity/kanonarion/internal/vuln/domain"
	"github.com/eitanity/kanonarion/internal/vuln/vulntest"
	walksqlite "github.com/eitanity/kanonarion/internal/walk/adapters/walks/sqlite"
	walkdomain "github.com/eitanity/kanonarion/internal/walk/domain"
)

// fixtureNow is the instant every golden is recorded at. The CLI's wall clock
// is pinned to it for the whole run (see cli.SetClockForTest), so every age,
// every TTL judgment and every "N days ago" in a recorded output is a function
// of the fixture data alone.
var fixtureNow = time.Date(2026, 3, 1, 0, 0, 0, 0, time.UTC)

// Fixture instants, all derived from fixtureNow or fixed outright so that a
// recorded age never moves.
var (
	fixtureLookedUpAt = fixtureNow.Add(-10 * time.Minute)
	fixtureReleasedAt = time.Date(2025, 6, 1, 0, 0, 0, 0, time.UTC)
	fixtureScannedAt  = time.Date(2026, 1, 15, 9, 0, 0, 0, time.UTC)
	fixtureScannedAt2 = time.Date(2026, 2, 20, 9, 0, 0, 0, time.UTC)
	fixtureWalkAt     = time.Date(2026, 1, 15, 8, 0, 0, 0, time.UTC)
)

const (
	fixtureWalkID = "01ARZ3NDEKTSV4RRFFQ69G5FAV"
	// fixtureWalkID2 names a SECOND walk of the same target: one module dropped
	// out of the graph and another moved version. It exists so walk-diff has two
	// records to compose rather than one record compared with itself, which is
	// the only comparison a single-walk fixture can express.
	fixtureWalkID2    = "01ARZ3NDEKTSV4RRFFQ69G5FAW"
	fixtureScanRunID  = "01JSCANRUN0GOLDEN00000001"
	fixtureScanRunID2 = "01JSCANRUN0GOLDEN00000002"
	// fixtureSnapshotBody stands in for the advisory database bytes. It is
	// hashed into the snapshot seal, so it is content, not decoration.
	fixtureSnapshotBody = `{"fixture":"advisory database"}`
)

// fixtureCoord builds a coordinate or fails the test; a fixture that cannot be
// named is a broken fixture, never a skipped one.
func fixtureCoord(t testing.TB, path, version string) coordinate.ModuleCoordinate {
	t.Helper()
	c, err := coordinate.NewModuleCoordinate(path, version)
	if err != nil {
		t.Fatalf("fixture coordinate %s@%s: %v", path, version, err)
	}
	return c
}

// The coordinates the fixture store is built from.
func fixtureRoot(t testing.TB) coordinate.ModuleCoordinate {
	return fixtureCoord(t, "example.com/app", "v1.0.0")
}
func fixtureMod(t testing.TB) coordinate.ModuleCoordinate {
	return fixtureCoord(t, "example.com/mod", "v1.2.0")
}
func fixtureShallow(t testing.TB) coordinate.ModuleCoordinate {
	return fixtureCoord(t, "example.com/shallow", "v1.0.0")
}

// fixtureClean is the control for the divergent coordinate: ONE measurement,
// verified, scanned and clean. It exists because example.com/mod's two artefact
// identities are a divergence today, so without this the whole recorded set
// would show the failure shape and nothing would hold a copy of the healthy
// one.
func fixtureClean(t testing.TB) coordinate.ModuleCoordinate {
	return fixtureCoord(t, "example.com/clean", "v1.0.0")
}

// fixtureArtefact builds a deterministic module zip for coord. salt varies the
// bytes, which is how one coordinate acquires two artefact identities.
func fixtureArtefact(t testing.TB, coord coordinate.ModuleCoordinate, salt string) ([]byte, fetchdomain.ModuleHash, fetchports.BlobIdentity) {
	t.Helper()
	buf := new(bytes.Buffer)
	zw := zip.NewWriter(buf)
	f, err := zw.Create(coord.Path() + "@" + coord.Version() + "/README")
	if err != nil {
		t.Fatalf("fixture zip entry: %v", err)
	}
	if _, err := f.Write([]byte("zip content for " + coord.String() + " " + salt)); err != nil {
		t.Fatalf("fixture zip write: %v", err)
	}
	if err := zw.Close(); err != nil {
		t.Fatalf("fixture zip close: %v", err)
	}
	content := buf.Bytes()

	tmp := filepath.Join(t.TempDir(), "fixture.zip")
	if err := os.WriteFile(tmp, content, 0o600); err != nil {
		t.Fatalf("fixture zip file: %v", err)
	}
	raw, err := dirhash.HashZip(tmp, dirhash.Hash1)
	if err != nil {
		t.Fatalf("fixture zip hash: %v", err)
	}
	hash, err := fetchdomain.ParseModuleHash(raw)
	if err != nil {
		t.Fatalf("fixture zip hash parse: %v", err)
	}
	identity, err := fetchports.NewBlobIdentity(fetchports.BlobKindZip, hash)
	if err != nil {
		t.Fatalf("fixture blob identity: %v", err)
	}
	return content, hash, identity
}

// seedFetch files one acquired measurement of coord and stores its bytes.
func seedFetch(
	t testing.TB,
	facts *fetchsqlite.Store,
	blobs *localfs.Store,
	coord coordinate.ModuleCoordinate,
	salt string,
	fetchedAt time.Time,
) fetchports.BlobIdentity {
	t.Helper()
	content, hash, identity := fixtureArtefact(t, coord, salt)
	if err := blobs.Put(context.Background(), identity, bytes.NewReader(content)); err != nil {
		t.Fatalf("storing fixture artefact for %s: %v", coord, err)
	}
	sealed, err := fetchdomain.Seal(fetchdomain.FetchedModule{
		Coordinate:         coord,
		ModuleHash:         hash,
		GoModHash:          fixtureGoModHash(t, coord, salt),
		VerificationStatus: fetchdomain.Verified,
		PipelineVersion:    fetchapp.PipelineVersion,
		ContentLocation:    identity.String(),
		GoModLocation:      "gomod:" + coord.Path() + "@" + coord.Version(),
		FetchedAt:          fetchedAt,
		MeasurementKind:    fetchdomain.MeasurementAcquired,
	})
	if err != nil {
		t.Fatalf("sealing fixture fetch record for %s: %v", coord, err)
	}
	if err := facts.PutFetchRecord(context.Background(), sealed); err != nil {
		t.Fatalf("filing fixture fetch record for %s: %v", coord, err)
	}
	return identity
}

// fixtureGoModHash derives a stable, well-formed go.mod hash for a fixture.
func fixtureGoModHash(t testing.TB, coord coordinate.ModuleCoordinate, salt string) fetchdomain.ModuleHash {
	t.Helper()
	raw, err := dirhash.Hash1([]string{coord.Path() + "/go.mod"}, func(string) (io.ReadCloser, error) {
		return readCloser{strings.NewReader("module " + coord.Path() + "\n" + salt + "\n")}, nil
	})
	if err != nil {
		t.Fatalf("fixture go.mod hash: %v", err)
	}
	h, err := fetchdomain.ParseModuleHash(raw)
	if err != nil {
		t.Fatalf("fixture go.mod hash parse: %v", err)
	}
	return h
}

type readCloser struct{ *strings.Reader }

func (readCloser) Close() error { return nil }

// seedGoModOnly files the shallow measurement: a verified go.mod and no module
// zip. It is the fixture a per-finding go.sum classification needs in order to
// report anything other than one uniform value.
func seedGoModOnly(t testing.TB, facts *fetchsqlite.Store, coord coordinate.ModuleCoordinate) {
	t.Helper()
	sealed, err := fetchdomain.Seal(fetchdomain.FetchedModule{
		Coordinate:         coord,
		GoModHash:          fixtureGoModHash(t, coord, "gomod-only"),
		VerificationStatus: fetchdomain.Verified,
		PipelineVersion:    fetchapp.PipelineVersion,
		GoModLocation:      "gomod:" + coord.Path() + "@" + coord.Version(),
		FetchedAt:          fixtureWalkAt,
		MeasurementKind:    fetchdomain.MeasurementAcquired,
	})
	if err != nil {
		t.Fatalf("sealing go.mod-only record for %s: %v", coord, err)
	}
	if err := facts.PutFetchRecord(context.Background(), sealed); err != nil {
		t.Fatalf("filing go.mod-only record for %s: %v", coord, err)
	}
}

// buildFixtureStore builds the whole hermetic store and returns its root.
func buildFixtureStore(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	dbPath := filepath.Join(root, "mirror.db")

	migrations := fetchsqlite.Migrations()
	migrations = append(migrations, walksqlite.Migrations()...)
	migrations = append(migrations, vulnsqlite.Migrations()...)
	migrations = append(migrations, cgsqlite.Migrations()...)
	migrations = append(migrations, licsqlite.Migrations()...)
	migrations = append(migrations, stalesqlite.Migrations()...)

	db, err := sqlitestore.Open(dbPath, migrations)
	if err != nil {
		t.Fatalf("opening fixture store: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })

	facts := fetchsqlite.New(db)
	blobs := localfs.New(root)

	app := fixtureRoot(t)
	mod := fixtureMod(t)
	shallow := fixtureShallow(t)
	clean := fixtureClean(t)

	appIdentity := seedFetch(t, facts, blobs, app, "app", fixtureWalkAt)
	cleanIdentity := seedFetch(t, facts, blobs, clean, "clean", fixtureWalkAt)
	// TWO measurements of one version, re-fetched to different bytes.
	firstIdentity := seedFetch(t, facts, blobs, mod, "first", fixtureWalkAt)
	seedFetch(t, facts, blobs, mod, "refetched", fixtureWalkAt.Add(24*time.Hour))
	seedGoModOnly(t, facts, shallow)

	seedFixtureWalk(t, walksqlite.New(db), app, mod, shallow, clean)
	seedFixtureWalk2(t, walksqlite.New(db), app, clean)
	// The ROOT carries a licence too. license-compat judges a closure against
	// the root's own licence and refuses without one, so a fixture that licensed
	// only the dependencies could record that refusal and nothing else.
	seedFixtureLicense(t, licsqlite.New(db), app, appIdentity, "MIT")
	seedFixtureLicense(t, licsqlite.New(db), mod, firstIdentity, "MIT")
	seedFixtureLicense(t, licsqlite.New(db), clean, cleanIdentity, "Apache-2.0")
	// TWO call-graph generations of one coordinate, at DIFFERENT completeness
	// levels, and the weaker one is written LAST. Composition serves the highest
	// completeness before the most recent, so a store where the newest record is
	// also the best one cannot tell the two rules apart — this ordering is what
	// makes `callgraph-show --history` mark the built graph rather than the
	// latest one, and what makes a change to that ladder show as a diff.
	//
	// Both generations pin the SAME artefact deliberately. Two generations of
	// one version that read different bytes are a divergence, and composition
	// refuses to pick between them rather than ranking them — so pinning the
	// re-fetched identity here would have recorded that refusal and left the
	// completeness ladder, which is what this fixture exists for, untested.
	seedFixtureCallGraph(t, cgsqlite.New(db), mod, firstIdentity,
		cgdomain.CompletenessBuiltWithBodies, fixtureWalkAt, true)
	seedFixtureCallGraph(t, cgsqlite.New(db), mod, firstIdentity,
		cgdomain.CompletenessMetadataOnly, fixtureWalkAt.Add(24*time.Hour), false)
	seedFixtureVuln(t, vulnsqlite.New(db), mod, shallow, clean)
	seedFixtureStaleness(t, stalesqlite.New(db))

	return root
}

func seedFixtureWalk(t *testing.T, store *walksqlite.Store, app, mod, shallow, clean coordinate.ModuleCoordinate) {
	t.Helper()
	graph := walkdomain.Graph{
		Target: app,
		Nodes: []walkdomain.GraphNode{
			{Coordinate: app, ResolutionSource: walkdomain.ResolutionTarget},
			{Coordinate: mod, DirectDependency: true, ResolutionSource: walkdomain.ResolutionMVS},
			{Coordinate: shallow, DirectDependency: false, ResolutionSource: walkdomain.ResolutionMVS},
			{Coordinate: clean, DirectDependency: true, ResolutionSource: walkdomain.ResolutionMVS},
		},
		Edges: []walkdomain.GraphEdge{
			{From: app, To: mod, ConstraintVersion: "v1.2.0"},
			{From: mod, To: shallow, ConstraintVersion: "v1.0.0"},
			{From: app, To: clean, ConstraintVersion: "v1.0.0"},
		},
		ResolvedAt:      fixtureWalkAt,
		PipelineVersion: "1.0.0",
	}
	outcome := walkdomain.WalkOutcome{
		Target: app,
		Graph:  graph,
		PerNodeResults: map[coordinate.ModuleCoordinate]walkdomain.NodeResult{
			app:     {Coordinate: app, Status: walkdomain.NodeSucceeded, DurationMs: 10},
			mod:     {Coordinate: mod, Status: walkdomain.NodeSucceeded, DurationMs: 5},
			shallow: {Coordinate: shallow, Status: walkdomain.NodeSucceeded, DurationMs: 3},
			clean:   {Coordinate: clean, Status: walkdomain.NodeSucceeded, DurationMs: 4},
		},
		StartedAt:     fixtureWalkAt,
		CompletedAt:   fixtureWalkAt.Add(time.Second),
		OverallStatus: walkdomain.WalkSucceeded,
	}
	rec := walkdomain.NewWalkRecord(fixtureWalkID, "fixture", "1.0.0",
		walkdomain.WalkScopeCode, walkdomain.WalkDepthFull, outcome, walkdomain.DefaultDepthPolicy(), "")
	rec, err := walkdomain.WalkRecordHasher{}.SetContentHash(rec)
	if err != nil {
		t.Fatalf("sealing fixture walk: %v", err)
	}
	if err := store.PutWalk(context.Background(), rec); err != nil {
		t.Fatalf("filing fixture walk: %v", err)
	}
}

// seedFixtureWalk2 files the second walk of the same target: example.com/mod is
// gone from the graph and example.com/shallow has moved to v1.1.0. It gives
// walk-diff a real pair — a removal and a version change — instead of a record
// diffed against itself.
func seedFixtureWalk2(t *testing.T, store *walksqlite.Store, app, clean coordinate.ModuleCoordinate) {
	t.Helper()
	shallowNext := fixtureCoord(t, "example.com/shallow", "v1.1.0")
	graph := walkdomain.Graph{
		Target: app,
		Nodes: []walkdomain.GraphNode{
			{Coordinate: app, ResolutionSource: walkdomain.ResolutionTarget},
			{Coordinate: shallowNext, DirectDependency: true, ResolutionSource: walkdomain.ResolutionMVS},
			{Coordinate: clean, DirectDependency: true, ResolutionSource: walkdomain.ResolutionMVS},
		},
		Edges: []walkdomain.GraphEdge{
			{From: app, To: shallowNext, ConstraintVersion: "v1.1.0"},
			{From: app, To: clean, ConstraintVersion: "v1.0.0"},
		},
		ResolvedAt:      fixtureWalkAt.Add(48 * time.Hour),
		PipelineVersion: "1.0.0",
	}
	outcome := walkdomain.WalkOutcome{
		Target: app,
		Graph:  graph,
		PerNodeResults: map[coordinate.ModuleCoordinate]walkdomain.NodeResult{
			app:         {Coordinate: app, Status: walkdomain.NodeSucceeded, DurationMs: 10},
			shallowNext: {Coordinate: shallowNext, Status: walkdomain.NodeSucceeded, DurationMs: 3},
			clean:       {Coordinate: clean, Status: walkdomain.NodeSucceeded, DurationMs: 4},
		},
		StartedAt:     fixtureWalkAt.Add(48 * time.Hour),
		CompletedAt:   fixtureWalkAt.Add(48*time.Hour + time.Second),
		OverallStatus: walkdomain.WalkSucceeded,
	}
	rec := walkdomain.NewWalkRecord(fixtureWalkID2, "fixture", "1.0.0",
		walkdomain.WalkScopeCode, walkdomain.WalkDepthFull, outcome, walkdomain.DefaultDepthPolicy(), "")
	rec, err := walkdomain.WalkRecordHasher{}.SetContentHash(rec)
	if err != nil {
		t.Fatalf("sealing the second fixture walk: %v", err)
	}
	if err := store.PutWalk(context.Background(), rec); err != nil {
		t.Fatalf("filing the second fixture walk: %v", err)
	}
}

// seedFixtureLicense files one licence record. spdx is a parameter because a
// closure in which every module carries the same licence cannot express a
// compatibility judgment: the pairs a compatibility read composes are all
// identical, so a change to how it composes them moves nothing.
func seedFixtureLicense(t *testing.T, store *licsqlite.Store, mod coordinate.ModuleCoordinate, identity fetchports.BlobIdentity, spdx string) {
	t.Helper()
	rec := licdomain.LicenseRecord{
		SchemaVersion:     licdomain.LicenseSchemaVersion,
		Ecosystem:         fetchdomain.EcosystemGo,
		Coordinate:        mod,
		PrimarySPDX:       spdx,
		PrimaryConfidence: 1.0,
		OverallStatus:     licdomain.LicenseStatusDetected,
		LicenseFiles: []licdomain.LicenseFileEntry{
			{Path: "LICENSE", SPDX: spdx, Confidence: 1.0, FileHash: "sha256:" + strings.Repeat("a", 64), FileSize: 1024},
		},
		ExtractedAt:      fixtureWalkAt,
		PipelineVersion:  licapp.PipelineVersion,
		ArtefactIdentity: identity.String(),
	}
	rec.SortFiles()
	sealed, err := licdomain.LicenseRecordHasher{}.SetContentHash(rec)
	if err != nil {
		t.Fatalf("sealing fixture licence: %v", err)
	}
	if err := store.PutLicenseRecord(context.Background(), sealed); err != nil {
		t.Fatalf("filing fixture licence: %v", err)
	}
}

// seedFixtureCallGraph files one call-graph generation for mod. completeness and
// extractedAt make each generation distinguishable; withEdges is false for the
// metadata-only generation, which records the symbols a module declares without
// having read a function body, so it has nodes and no edges.
func seedFixtureCallGraph(
	t *testing.T,
	store *cgsqlite.Store,
	mod coordinate.ModuleCoordinate,
	identity fetchports.BlobIdentity,
	completeness cgdomain.CompletenessLevel,
	extractedAt time.Time,
	withEdges bool,
) {
	t.Helper()
	rec := cgdomain.CallGraphRecord{
		SchemaVersion:  cgdomain.CallGraphSchemaVersion,
		Ecosystem:      fetchdomain.EcosystemGo,
		Coordinate:     mod,
		Algorithm:      cgdomain.AlgorithmCHA,
		OverallStatus:  cgdomain.CallGraphStatusExtracted,
		TestScope:      cgdomain.TestScopeAnalysed,
		ReferenceScope: cgdomain.ReferenceScopeAnalysed,
		Nodes: []cgdomain.CallNode{
			{ID: "example.com/mod.Handle", Package: "example.com/mod", Symbol: "Handle", IsExportedAPI: true},
			{ID: "example.com/mod.Parse", Package: "example.com/mod", Symbol: "Parse", IsExportedAPI: true},
		},
		NodeCount:        2,
		ExtractedAt:      extractedAt,
		PipelineVersion:  cgapp.PipelineVersion,
		Completeness:     completeness,
		AnalysisSource:   cgdomain.AnalysisSourceModuleZip,
		ArtefactIdentity: identity.String(),
	}
	if withEdges {
		rec.Edges = []cgdomain.CallEdge{
			{FromID: "example.com/mod.Handle", ToID: "example.com/mod.Parse", Confidence: cgdomain.ConfidenceDirect},
		}
		rec.EdgeCount = 1
	}
	sealed, err := cgdomain.CallGraphRecordHasher{}.SetContentHash(rec)
	if err != nil {
		t.Fatalf("sealing fixture call graph: %v", err)
	}
	if err := store.PutCallGraphRecord(context.Background(), sealed); err != nil {
		t.Fatalf("filing fixture call graph: %v", err)
	}
}

func seedFixtureVuln(t *testing.T, store *vulnsqlite.Store, mod, shallow, clean coordinate.ModuleCoordinate) {
	t.Helper()
	ctx := context.Background()

	snapOne := vulntest.MustSealOver("govulndb", "v2026-01-10T00-00-00",
		time.Date(2026, 1, 10, 0, 0, 0, 0, time.UTC), []byte(fixtureSnapshotBody))
	snapTwo := vulntest.MustSealOver("govulndb", "v2026-02-14T00-00-00",
		time.Date(2026, 2, 14, 0, 0, 0, 0, time.UTC), []byte(fixtureSnapshotBody+" two"))
	if err := store.PutDatabaseSnapshot(ctx, snapOne, strings.NewReader(fixtureSnapshotBody)); err != nil {
		t.Fatalf("filing fixture snapshot one: %v", err)
	}
	if err := store.PutDatabaseSnapshot(ctx, snapTwo, strings.NewReader(fixtureSnapshotBody+" two")); err != nil {
		t.Fatalf("filing fixture snapshot two: %v", err)
	}

	route := vulndomain.ReachabilityRoute{
		{ModulePath: "example.com/app", Package: "example.com/app", Symbol: "main"},
		{ModulePath: "example.com/mod", ModuleVersion: "v1.2.0", Package: "example.com/mod", Symbol: "Handle"},
		{ModulePath: "example.com/mod", ModuleVersion: "v1.2.0", Package: "example.com/mod", Symbol: "Parse"},
	}
	finding := vulndomain.VulnerabilityFinding{
		ID:              "GO-2026-0001",
		Aliases:         []string{"CVE-2026-00001"},
		Summary:         "example vulnerability in example.com/mod",
		AffectedRange:   "<v1.3.0",
		FixedIn:         "v1.3.0",
		AffectedSymbols: []string{"Parse"},
		Reachable: &vulndomain.ReachabilityResult{
			IsReachable: true,
			Confidence:  vulndomain.ConfidenceHigh,
			Routes:      []vulndomain.ReachabilityRoute{route},
			DerivedBy: vulndomain.ReachabilityDerivation{
				Analyser: vulndomain.AnalyserGovulncheck,
				Fidelity: "source",
			},
		},
		References: []vulndomain.AdvisoryReference{
			{Type: "ADVISORY", URL: "https://example.com/advisories/GO-2026-0001"},
		},
		PublishedAt: time.Date(2026, 1, 5, 0, 0, 0, 0, time.UTC),
		ModifiedAt:  time.Date(2026, 1, 6, 0, 0, 0, 0, time.UTC),
	}

	// The same coordinate against the FIRST snapshot.
	recOne := vulndomain.VulnerabilityRecord{
		Ecosystem:             fetchdomain.EcosystemGo,
		Coordinate:            mod,
		WalkID:                fixtureWalkID,
		OverallStatus:         vulndomain.StatusAffected,
		CoverageStatus:        vulndomain.CoverageAnalysed,
		FindingsStatus:        vulndomain.FindingsRecordAffected,
		DatabaseSnapshot:      snapOne,
		Findings:              []vulndomain.VulnerabilityFinding{finding},
		ScannedAt:             fixtureScannedAt,
		FirstScannedAt:        fixtureScannedAt,
		PipelineVersion:       vulnapp.PipelineVersion,
		CallGraphCompleteness: "BUILT_WITH_BODIES",
		CallGraphAlgorithm:    string(cgdomain.AlgorithmCHA),
		Rooting:               vulndomain.RootingTargetRooted,
		AnalysisSurface:       vulndomain.AnalysisSurfaceFetched,
	}
	// The same coordinate against the SECOND snapshot: a later scan that saw a
	// second advisory, one of which has since been withdrawn upstream.
	withdrawn := finding
	withdrawn.ID = "GO-2026-0002"
	withdrawn.Aliases = []string{"CVE-2026-00002"}
	withdrawn.Summary = "withdrawn advisory for example.com/mod"
	withdrawn.WithdrawnAt = time.Date(2026, 2, 10, 0, 0, 0, 0, time.UTC)
	withdrawn.Reachable = nil
	withdrawn.ReachabilityNote = ""
	recTwo := recOne
	recTwo.DatabaseSnapshot = snapTwo
	recTwo.Findings = []vulndomain.VulnerabilityFinding{finding, withdrawn}
	recTwo.ScannedAt = fixtureScannedAt2

	shallowRec := vulndomain.VulnerabilityRecord{
		Ecosystem:        fetchdomain.EcosystemGo,
		Coordinate:       shallow,
		WalkID:           fixtureWalkID,
		OverallStatus:    vulndomain.StatusUnscannable,
		CoverageStatus:   vulndomain.CoverageUnscannable,
		UnscanReason:     vulndomain.UnscanReasonGoModOnly,
		DatabaseSnapshot: snapTwo,
		ScannedAt:        fixtureScannedAt2,
		FirstScannedAt:   fixtureScannedAt2,
		PipelineVersion:  vulnapp.PipelineVersion,
		Rooting:          vulndomain.RootingTargetRooted,
	}

	cleanRec := vulndomain.VulnerabilityRecord{
		Ecosystem:        fetchdomain.EcosystemGo,
		Coordinate:       clean,
		WalkID:           fixtureWalkID,
		OverallStatus:    vulndomain.StatusClean,
		CoverageStatus:   vulndomain.CoverageAnalysed,
		FindingsStatus:   vulndomain.FindingsRecordClean,
		DatabaseSnapshot: snapTwo,
		ScannedAt:        fixtureScannedAt2,
		FirstScannedAt:   fixtureScannedAt2,
		PipelineVersion:  vulnapp.PipelineVersion,
		Rooting:          vulndomain.RootingTargetRooted,
		AnalysisSurface:  vulndomain.AnalysisSurfaceFetched,
	}

	sealedOne := sealVuln(t, recOne)
	sealedTwo := sealVuln(t, recTwo)
	sealedShallow := sealVuln(t, shallowRec)
	sealedClean := sealVuln(t, cleanRec)
	for _, rec := range []vulndomain.VulnerabilityRecord{sealedOne, sealedTwo, sealedShallow, sealedClean} {
		if err := store.PutVulnerabilityRecord(ctx, rec); err != nil {
			t.Fatalf("filing fixture vulnerability record for %s: %v", rec.Coordinate, err)
		}
	}

	runOne := vulndomain.WalkScanRun{
		ID:               fixtureScanRunID,
		WalkID:           fixtureWalkID,
		Snapshot:         snapOne,
		PerModuleResults: map[coordinate.ModuleCoordinate]string{mod: sealedOne.ContentHash},
		StartedAt:        fixtureScannedAt,
		CompletedAt:      fixtureScannedAt.Add(time.Second),
		OverallStatus:    vulndomain.WalkStatusAffected,
		PipelineVersion:  vulnapp.PipelineVersion,
		Operator:         "fixture",
	}
	runTwo := vulndomain.WalkScanRun{
		ID:       fixtureScanRunID2,
		WalkID:   fixtureWalkID,
		Snapshot: snapTwo,
		PerModuleResults: map[coordinate.ModuleCoordinate]string{
			mod:     sealedTwo.ContentHash,
			shallow: sealedShallow.ContentHash,
			clean:   sealedClean.ContentHash,
		},
		StartedAt:       fixtureScannedAt2,
		CompletedAt:     fixtureScannedAt2.Add(time.Second),
		OverallStatus:   vulndomain.WalkStatusAffected,
		PipelineVersion: vulnapp.PipelineVersion,
		Operator:        "fixture",
	}
	for _, run := range []vulndomain.WalkScanRun{runOne, runTwo} {
		sealed, err := vulndomain.WalkScanRunHasher{}.SetContentHash(run)
		if err != nil {
			t.Fatalf("sealing fixture scan run: %v", err)
		}
		if err := store.PutWalkScanRun(ctx, sealed); err != nil {
			t.Fatalf("filing fixture scan run: %v", err)
		}
	}
}

func sealVuln(t *testing.T, rec vulndomain.VulnerabilityRecord) vulndomain.VulnerabilityRecord {
	t.Helper()
	vulndomain.StampReachabilityRooting(&rec)
	sealed, err := vulndomain.VulnerabilityRecordHasher{}.SetContentHash(rec)
	if err != nil {
		t.Fatalf("sealing fixture vulnerability record: %v", err)
	}
	return sealed
}

// seedFixtureStaleness fills the ledger `latest` reads, so the command answers
// from the store and never opens a socket.
//
// Both rows are FULLY probed — a row whose major probe is unrecorded is not
// reusable, and the resolver would go to the proxy for the missing half.
func seedFixtureStaleness(t *testing.T, store *stalesqlite.Store) {
	t.Helper()
	ctx := context.Background()
	rows := []staledomain.Record{
		{
			ModulePath:        "example.com/mod",
			LatestVersion:     "v1.3.0",
			LatestPublishedAt: fixtureReleasedAt,
			NewerMajor:        staledomain.NewerMajor{Probed: true, FromMajor: 2},
			LookedUpAt:        fixtureLookedUpAt,
		},
		{
			// The module with NO publication date. Everything derived from a
			// date is absent on this row, and that absence is the fixture.
			ModulePath:    "example.com/quiet",
			LatestVersion: "v0.9.0",
			NewerMajor:    staledomain.NewerMajor{Probed: true, FromMajor: 2},
			LookedUpAt:    fixtureLookedUpAt,
		},
	}
	for _, row := range rows {
		if err := store.PutStaleness(ctx, row); err != nil {
			t.Fatalf("filing fixture staleness row for %s: %v", row.ModulePath, err)
		}
	}
}
