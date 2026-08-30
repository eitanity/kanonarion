package cli

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/eitanity/kanonarion/internal/adapters/sqlitestore"
	"github.com/eitanity/kanonarion/internal/coordinate"
	"github.com/eitanity/kanonarion/internal/coordinate/coordinatetest"

	fetchsqlite "github.com/eitanity/kanonarion/internal/adapters/factstore/sqlite"
	fetchapp "github.com/eitanity/kanonarion/internal/fetch/application"
	fetchdomain "github.com/eitanity/kanonarion/internal/fetch/domain"
	"github.com/eitanity/kanonarion/internal/fetch/fetchtest"

	licsqlite "github.com/eitanity/kanonarion/internal/license/adapters/store/sqlite"
	licapp "github.com/eitanity/kanonarion/internal/license/application"
	licdomain "github.com/eitanity/kanonarion/internal/license/domain"

	cgsqlite "github.com/eitanity/kanonarion/internal/callgraph/adapters/store/sqlite"
	cgapp "github.com/eitanity/kanonarion/internal/callgraph/application"
	cgdomain "github.com/eitanity/kanonarion/internal/callgraph/domain"

	ifacesqlite "github.com/eitanity/kanonarion/internal/iface/adapters/store/sqlite"
	ifaceapp "github.com/eitanity/kanonarion/internal/iface/application"
	ifacedomain "github.com/eitanity/kanonarion/internal/iface/domain"

	exsqlite "github.com/eitanity/kanonarion/internal/example/adapters/store/sqlite"
	exapp "github.com/eitanity/kanonarion/internal/example/application"
	exdomain "github.com/eitanity/kanonarion/internal/example/domain"

	extsqlite "github.com/eitanity/kanonarion/internal/extract/adapters/store/sqlite"
	extdomain "github.com/eitanity/kanonarion/internal/extract/domain"

	vulnsqlite "github.com/eitanity/kanonarion/internal/vuln/adapters/store/sqlite"
	vulnapp "github.com/eitanity/kanonarion/internal/vuln/application"
	vulndomain "github.com/eitanity/kanonarion/internal/vuln/domain"
	"github.com/eitanity/kanonarion/internal/vuln/vulntest"

	sbomsqlite "github.com/eitanity/kanonarion/internal/sbom/adapters/store/sqlite"
	sbomdomain "github.com/eitanity/kanonarion/internal/sbom/domain"

	dirsqlite "github.com/eitanity/kanonarion/internal/directive/adapters/store/sqlite"
	dirdomain "github.com/eitanity/kanonarion/internal/directive/domain"

	nativesqlite "github.com/eitanity/kanonarion/internal/native/adapters/store/sqlite"
	nativedomain "github.com/eitanity/kanonarion/internal/native/domain"

	walksqlite "github.com/eitanity/kanonarion/internal/walk/adapters/walks/sqlite"
	walkapp "github.com/eitanity/kanonarion/internal/walk/application"
	walkdomain "github.com/eitanity/kanonarion/internal/walk/domain"
)

// The identifiers the seeded records are keyed by. The cases name them rather
// than repeating literals, so a change to what is seeded cannot leave a case
// asking for a record that is no longer there.
const (
	jsonDocWalkID     = "01JS0NGARD0000000000000WA1"
	jsonDocScanRunID  = "01JS0NGARD0000000000000RN1"
	jsonDocExtractID  = "01JS0NGARD0000000000000EX1"
	jsonDocSBOMID     = "01JS0NGARD0000000000000SB1"
	jsonDocDirScanID  = "01JS0NGARD0000000000000DR1"
	jsonDocFindingID  = "GO-2026-0001"
	jsonDocSnapSource = "govulndb"
	jsonDocSnapshotV  = "v2026-03-01"
	jsonDocSymbol     = "New"
	jsonDocExample    = "ExampleNew"
	jsonDocRootPath   = "example.com/root"
	jsonDocRootCoord  = "example.com/root@v1.0.0"
	jsonDocDepCoord   = "example.com/dep@v1.2.0"
	jsonDocIfaceID    = "example.com/dep.Doer"
	jsonDocNodeID     = "example.com/dep.New"
	jsonDocMethodID   = "example.com/dep.(*Client).Do"
)

var (
	jsonDocRoot = coordinatetest.MustNew(jsonDocRootPath, "v1.0.0")
	jsonDocDep  = coordinatetest.MustNew("example.com/dep", "v1.2.0")
	// One instant for every record, so nothing the guard reads depends on the
	// wall clock.
	jsonDocAt = time.Date(2026, 3, 4, 5, 6, 7, 0, time.UTC)
)

// jsonStdoutFixture is the state the enumerated commands are run against: one
// store holding a record of every kind a read command composes its answer from,
// and one working tree for the commands scoped by a go.mod. Both are built once
// and shared, because the point is to exercise the rendering of an answer, not
// to give each command a private world.
type jsonStdoutFixture struct {
	// storeRoot is passed as --store-root to every case.
	storeRoot string
	// treeDir holds a go.mod and one Go file. The module requires nothing, so
	// the commands scoped by it resolve a build list without leaving the
	// directory — which is what keeps them off the network.
	treeDir string
}

// goMod is the path a --gomod flag names.
func (f jsonStdoutFixture) goMod() string { return filepath.Join(f.treeDir, "go.mod") }

// newJSONStdoutFixture seeds the store and writes the working tree.
//
// The records are written through the production store adapters, sealed by the
// production hashers, so a record shape that stops round-tripping fails here
// rather than being papered over with hand-rolled rows.
func newJSONStdoutFixture(t *testing.T) jsonStdoutFixture {
	t.Helper()
	fx := jsonStdoutFixture{storeRoot: t.TempDir(), treeDir: t.TempDir()}

	if err := os.WriteFile(fx.goMod(), []byte("module example.com/root\n\ngo 1.24\n"), 0o600); err != nil {
		t.Fatalf("writing the fixture go.mod: %v", err)
	}
	if err := os.WriteFile(filepath.Join(fx.treeDir, "root.go"),
		[]byte("package root\n\n// Hello is the one symbol the local analysis has to find.\nfunc Hello() string { return \"hi\" }\n"), 0o600); err != nil {
		t.Fatalf("writing the fixture package: %v", err)
	}

	db, err := sqlitestore.Open(filepath.Join(fx.storeRoot, "mirror.db"), nil, sqlitestore.IntentCreate)
	if err != nil {
		t.Fatalf("opening the fixture store: %v", err)
	}
	defer func() {
		if cerr := db.Close(); cerr != nil {
			t.Errorf("closing the fixture store: %v", cerr)
		}
	}()
	if err := sqlitestore.Apply(db, allMigrations()); err != nil {
		t.Fatalf("migrating the fixture store: %v", err)
	}

	ctx := context.Background()
	seedJSONDocWalk(t, ctx, db)
	seedJSONDocArtefactRecords(t, ctx, db)
	seedJSONDocExtractionRun(t, ctx, db)
	seedJSONDocVulnerabilities(t, ctx, db)
	seedJSONDocReports(t, ctx, db)
	return fx
}

// seedJSONDocWalk writes the walk every walk-scoped command resolves through.
func seedJSONDocWalk(t *testing.T, ctx context.Context, db sqlitestore.DB) {
	t.Helper()
	graph := walkdomain.Graph{
		Target: jsonDocRoot,
		Nodes: []walkdomain.GraphNode{
			{Coordinate: jsonDocRoot, ResolutionSource: walkdomain.ResolutionTarget},
			{Coordinate: jsonDocDep, DirectDependency: true, ResolutionSource: walkdomain.ResolutionMVS},
		},
		Edges:           []walkdomain.GraphEdge{{From: jsonDocRoot, To: jsonDocDep, ConstraintVersion: jsonDocDep.Version()}},
		ResolvedAt:      jsonDocAt,
		PipelineVersion: walkapp.PipelineVersion,
	}
	outcome := walkdomain.WalkOutcome{
		Target: jsonDocRoot,
		Graph:  graph,
		PerNodeResults: map[coordinate.ModuleCoordinate]walkdomain.NodeResult{
			jsonDocRoot: {Coordinate: jsonDocRoot, Status: walkdomain.NodeSucceeded},
			jsonDocDep:  {Coordinate: jsonDocDep, Status: walkdomain.NodeSucceeded},
		},
		StartedAt:     jsonDocAt,
		CompletedAt:   jsonDocAt.Add(time.Second),
		OverallStatus: walkdomain.WalkSucceeded,
	}
	rec := walkdomain.NewWalkRecord(jsonDocWalkID, "guard", walkapp.PipelineVersion,
		walkdomain.WalkScopeCode, walkdomain.WalkDepthFull, outcome, walkdomain.DefaultDepthPolicy(), "")
	rec, err := walkdomain.WalkRecordHasher{}.SetContentHash(rec)
	if err != nil {
		t.Fatalf("sealing the walk record: %v", err)
	}
	if err := walksqlite.New(db).PutWalk(ctx, rec); err != nil {
		t.Fatalf("seeding the walk: %v", err)
	}
}

// seedJSONDocArtefactRecords writes, for both modules of the walk, the per-
// artefact records: the fetch fact, the licence, the exported interface, the
// call graph and the examples.
func seedJSONDocArtefactRecords(t *testing.T, ctx context.Context, db sqlitestore.DB) {
	t.Helper()
	factStore := fetchsqlite.New(db)
	licStore := licsqlite.New(db)
	ifaceStore := ifacesqlite.New(db)
	cgStore := cgsqlite.New(db)
	exStore := exsqlite.New(db)

	for i, coord := range []coordinate.ModuleCoordinate{jsonDocRoot, jsonDocDep} {
		artefact := jsonDocArtefactIdentity(i)

		sealed := fetchtest.Sealed(t,
			fetchtest.Coordinate(coord),
			fetchtest.PipelineVersion(fetchapp.PipelineVersion),
			fetchtest.Status(fetchdomain.Verified),
			fetchtest.ModuleHash(fetchtest.H1(jsonDocHashValue(i, "zip"))),
			fetchtest.GoMod(jsonDocHashValue(i, "gomod")),
		)
		if err := factStore.PutFetchRecord(ctx, sealed); err != nil {
			t.Fatalf("seeding the fetch record for %s: %v", coord, err)
		}

		lic := licdomain.LicenseRecord{
			SchemaVersion:     licdomain.LicenseSchemaVersion,
			Ecosystem:         fetchdomain.EcosystemGo,
			Coordinate:        coord,
			PrimarySPDX:       "MIT",
			Expression:        "MIT",
			PrimaryConfidence: 0.99,
			LicenseFiles: []licdomain.LicenseFileEntry{
				{Path: "LICENSE", SPDX: "MIT", Confidence: 0.99, FileHash: "sha256:abc", FileSize: 100},
			},
			OverallStatus:    licdomain.LicenseStatusDetected,
			ExtractedAt:      jsonDocAt,
			PipelineVersion:  licapp.PipelineVersion,
			ArtefactIdentity: artefact,
		}
		lic.EffectiveSet = licdomain.DeriveEffectiveLicenseSet(lic.LicenseFiles)
		lic, err := licdomain.LicenseRecordHasher{}.SetContentHash(lic)
		if err != nil {
			t.Fatalf("sealing the licence record for %s: %v", coord, err)
		}
		if err := licStore.PutLicenseRecord(ctx, lic); err != nil {
			t.Fatalf("seeding the licence record for %s: %v", coord, err)
		}

		iface := ifacedomain.InterfaceRecord{
			SchemaVersion: ifacedomain.InterfaceSchemaVersion,
			Ecosystem:     fetchdomain.EcosystemGo,
			Coordinate:    coord,
			Packages: []ifacedomain.PackageInterface{{
				ImportPath: coord.Path(),
				Name:       "dep",
				Types: []ifacedomain.TypeDecl{{
					Name: "Client", Kind: ifacedomain.TypeKindStruct, Signature: "type Client struct{}",
					Methods: []ifacedomain.MethodDecl{
						{Name: "Do", Signature: "func (c *Client) Do() error", PtrReceiver: true},
					},
				}},
				Funcs: []ifacedomain.FuncDecl{{Name: jsonDocSymbol, Signature: "func New() *Client"}},
			}},
			OverallStatus:    ifacedomain.InterfaceStatusExtracted,
			ExtractedAt:      jsonDocAt,
			PipelineVersion:  ifaceapp.PipelineVersion,
			ArtefactIdentity: artefact,
		}
		iface, err = ifacedomain.InterfaceRecordHasher{}.SetContentHash(iface)
		if err != nil {
			t.Fatalf("sealing the interface record for %s: %v", coord, err)
		}
		if err := ifaceStore.PutInterfaceRecord(ctx, iface); err != nil {
			t.Fatalf("seeding the interface record for %s: %v", coord, err)
		}

		// One call, one interface and one implementation of it: the edge queries,
		// the implementers query and the reachability route each need a different
		// one of the four, and all four come from this record.
		cg := cgdomain.CallGraphRecord{
			SchemaVersion: cgdomain.CallGraphSchemaVersion,
			Ecosystem:     fetchdomain.EcosystemGo,
			Coordinate:    coord,
			Algorithm:     cgdomain.AlgorithmCHA,
			Nodes: []cgdomain.CallNode{
				{ID: coord.Path() + ".New", Module: coord.Path(), Package: coord.Path(), Symbol: "New", IsExportedAPI: true},
				{ID: coord.Path() + ".(*Client).Do", Module: coord.Path(), Package: coord.Path(), Symbol: "(*Client).Do", IsExportedAPI: true},
			},
			Edges: []cgdomain.CallEdge{{
				FromID: coord.Path() + ".New", ToID: coord.Path() + ".(*Client).Do",
				CallSite: cgdomain.SourcePosition{File: "dep.go", Line: 10}, Confidence: cgdomain.ConfidenceDirect,
			}},
			Interfaces: []cgdomain.InterfaceType{{
				ID: coord.Path() + ".Doer", Package: coord.Path(), Name: "Doer", Methods: []string{"Do"},
				Position: cgdomain.SourcePosition{File: "dep.go", Line: 3},
			}},
			Implementations: []cgdomain.InterfaceImplementation{{
				InterfaceID: coord.Path() + ".Doer", TypeID: coord.Path() + ".(*Client)", Package: coord.Path(),
				Position: cgdomain.SourcePosition{File: "dep.go", Line: 6},
				Methods:  []cgdomain.ImplementedMethod{{Method: "Do", NodeID: coord.Path() + ".(*Client).Do"}},
			}},
			OverallStatus:    cgdomain.CallGraphStatusExtracted,
			Completeness:     cgdomain.CompletenessBuiltWithBodies,
			NodeCount:        2,
			EdgeCount:        1,
			ExtractedAt:      jsonDocAt,
			PipelineVersion:  cgapp.PipelineVersion,
			AnalysisSource:   cgdomain.AnalysisSourceModuleZip,
			ArtefactIdentity: artefact,
		}
		cg, err = cgdomain.CallGraphRecordHasher{}.SetContentHash(cg)
		if err != nil {
			t.Fatalf("sealing the call graph record for %s: %v", coord, err)
		}
		if err := cgStore.PutCallGraphRecord(ctx, cg); err != nil {
			t.Fatalf("seeding the call graph record for %s: %v", coord, err)
		}

		example := exdomain.ExampleRecord{
			SchemaVersion: exdomain.ExampleSchemaVersion,
			Ecosystem:     fetchdomain.EcosystemGo,
			Coordinate:    coord,
			Examples: []exdomain.ExampleEntry{{
				Name: jsonDocExample, Package: "dep_test", AssociatedSymbol: jsonDocSymbol,
				Body: "{ _ = New() }", Validates: true,
			}},
			OverallStatus:    exdomain.ExampleStatusFound,
			ExtractedAt:      jsonDocAt,
			PipelineVersion:  exapp.PipelineVersion,
			ArtefactIdentity: artefact,
		}
		example, err = exdomain.ExampleRecordHasher{}.SetContentHash(example)
		if err != nil {
			t.Fatalf("sealing the example record for %s: %v", coord, err)
		}
		if err := exStore.PutExampleRecord(ctx, example); err != nil {
			t.Fatalf("seeding the example record for %s: %v", coord, err)
		}
	}
}

// seedJSONDocExtractionRun writes the run `extract show` and `extract list`
// answer from.
func seedJSONDocExtractionRun(t *testing.T, ctx context.Context, db sqlitestore.DB) {
	t.Helper()
	run := extdomain.ExtractionRun{
		SchemaVersion:   extdomain.ExtractionRunSchemaVersion,
		Ecosystem:       fetchdomain.EcosystemGo,
		ID:              jsonDocExtractID,
		WalkID:          jsonDocWalkID,
		RequestedStages: []string{"license", "interface"},
		PerModuleResults: map[coordinate.ModuleCoordinate]extdomain.ModuleExtractionResult{
			jsonDocDep: {Coordinate: jsonDocDep, Stages: map[string]extdomain.StageResult{
				"license":   {Status: extdomain.StageSucceeded, DurationMs: 10},
				"interface": {Status: extdomain.StageSucceeded, DurationMs: 12},
			}},
		},
		StartedAt:     jsonDocAt,
		CompletedAt:   jsonDocAt.Add(time.Second),
		OverallStatus: extdomain.ExtractionRunSucceeded,
	}
	run, err := extdomain.ExtractionRunHasher{}.SetContentHash(run)
	if err != nil {
		t.Fatalf("sealing the extraction run: %v", err)
	}
	if err := extsqlite.New(db).PutExtractionRun(ctx, run); err != nil {
		t.Fatalf("seeding the extraction run: %v", err)
	}
}

// seedJSONDocVulnerabilities writes the advisory snapshot, the finding against
// the dependency and the scan run that covered it.
//
// The finding carries a reachability result: without one `reachability` refuses
// rather than rendering, and a refusal is not a document.
func seedJSONDocVulnerabilities(t *testing.T, ctx context.Context, db sqlitestore.DB) {
	t.Helper()
	store := vulnsqlite.New(db)
	snapshot := vulntest.MustNewAt(jsonDocSnapSource, jsonDocSnapshotV, jsonDocAt)
	if err := store.PutDatabaseSnapshot(ctx, snapshot, strings.NewReader("advisory snapshot bytes")); err != nil {
		t.Fatalf("seeding the advisory snapshot: %v", err)
	}

	record := vulndomain.VulnerabilityRecord{
		Ecosystem:        fetchdomain.EcosystemGo,
		Coordinate:       jsonDocDep,
		WalkID:           jsonDocWalkID,
		OverallStatus:    vulndomain.StatusAffected,
		DatabaseSnapshot: snapshot,
		ScannedAt:        jsonDocAt,
		PipelineVersion:  vulnapp.PipelineVersion,
		Findings: []vulndomain.VulnerabilityFinding{{
			ID:              jsonDocFindingID,
			Summary:         "a seeded finding",
			AffectedRange:   "< v1.3.0",
			AffectedSymbols: []string{"Client.Do"},
			Reachable: &vulndomain.ReachabilityResult{
				IsReachable: true,
				Confidence:  vulndomain.ConfidenceHigh,
				Routes: []vulndomain.ReachabilityRoute{{
					{ModulePath: jsonDocRoot.Path(), Package: jsonDocRoot.Path(), Symbol: "main"},
					{
						ModulePath: jsonDocDep.Path(), ModuleVersion: jsonDocDep.Version(),
						Package: jsonDocDep.Path(), Receiver: "*Client", Symbol: "Do",
					},
				}},
				DerivedBy: vulndomain.ReachabilityDerivation{
					Analyser: vulndomain.AnalyserGovulncheck,
					Fidelity: "source",
				},
			},
		}},
	}
	record, err := vulndomain.VulnerabilityRecordHasher{}.SetContentHash(record)
	if err != nil {
		t.Fatalf("sealing the vulnerability record: %v", err)
	}
	if err := store.PutVulnerabilityRecord(ctx, record); err != nil {
		t.Fatalf("seeding the vulnerability record: %v", err)
	}

	run := vulndomain.WalkScanRun{
		ID:               jsonDocScanRunID,
		WalkID:           jsonDocWalkID,
		Snapshot:         snapshot,
		PerModuleResults: map[coordinate.ModuleCoordinate]string{jsonDocDep: record.ContentHash},
		StartedAt:        jsonDocAt,
		CompletedAt:      jsonDocAt.Add(time.Second),
		OverallStatus:    vulndomain.WalkStatusAffected,
		Operator:         "guard",
		PipelineVersion:  vulnapp.PipelineVersion,
	}
	run, err = vulndomain.WalkScanRunHasher{}.SetContentHash(run)
	if err != nil {
		t.Fatalf("sealing the scan run: %v", err)
	}
	if err := store.PutWalkScanRun(ctx, run); err != nil {
		t.Fatalf("seeding the scan run: %v", err)
	}
}

// seedJSONDocReports writes the records that are neither per-artefact nor
// per-walk-run: the SBOM, the directive scan and the native-library finding.
func seedJSONDocReports(t *testing.T, ctx context.Context, db sqlitestore.DB) {
	t.Helper()
	if err := sbomsqlite.New(db).PutSBOMRecord(ctx, sbomdomain.SBOMRecord{
		ID:              jsonDocSBOMID,
		Ecosystem:       sbomdomain.EcosystemGo,
		WalkID:          jsonDocWalkID,
		Format:          sbomdomain.CycloneDX16,
		Content:         []byte(`{"bomFormat":"CycloneDX","specVersion":"1.6","version":1}`),
		ContentHash:     "sha256:seeded",
		GeneratedAt:     jsonDocAt,
		PipelineVersion: "0.3.0",
		Operator:        "guard",
	}); err != nil {
		t.Fatalf("seeding the SBOM record: %v", err)
	}

	directives := []dirdomain.Directive{{
		Kind: dirdomain.KindReplace, Source: "go.mod", Line: 7,
		OldPath: jsonDocDep.Path(), NewPath: "example.com/fork", NewVersion: "v1.0.0",
		Applied: true, Class: dirdomain.RiskHigh,
	}}
	dirdomain.Sort(directives)
	if err := dirsqlite.New(db).PutDirectiveRecord(ctx, dirdomain.Record{
		ID:                jsonDocDirScanID,
		Ecosystem:         dirdomain.EcosystemGo,
		ProjectModulePath: jsonDocRoot.Path(),
		Directives:        directives,
		StartedAt:         jsonDocAt,
		CompletedAt:       jsonDocAt.Add(time.Second),
		ExtractedAt:       jsonDocAt,
		SchemaVersion:     dirdomain.DirectiveSchemaVersion,
		PipelineVersion:   dirdomain.PipelineVersion,
		ContentHash:       dirdomain.Hash(directives),
	}); err != nil {
		t.Fatalf("seeding the directive record: %v", err)
	}

	artefact := jsonDocArtefactIdentity(1)
	components := []nativedomain.Component{{
		Name: "SQLite", Version: "3.38.0", Confidence: nativedomain.ConfidenceDeclared,
		Evidence: []nativedomain.Evidence{{File: "dep.c", Declaration: `#define SQLITE_VERSION "3.38.0"`}},
	}}
	sources := []nativedomain.Source{{File: "dep.c", Bytes: 100, SHA256: "aa"}}
	if err := nativesqlite.New(db).PutNativeRecord(ctx, nativedomain.Record{
		SchemaVersion:          nativedomain.NativeSchemaVersion,
		Ecosystem:              nativedomain.EcosystemGo,
		Coordinate:             jsonDocDep,
		ArtefactIdentity:       artefact,
		PipelineVersion:        nativedomain.PipelineVersion,
		RecipeCatalogueVersion: nativedomain.RecipeCatalogueVersion,
		Presence:               nativedomain.PresenceIdentified,
		Components:             components,
		Sources:                sources,
		ExtractedAt:            jsonDocAt,
		ContentHash: nativedomain.Hash(jsonDocDep.String(), artefact, nativedomain.PipelineVersion,
			nativedomain.RecipeCatalogueVersion, nativedomain.PresenceIdentified, components, sources, nil),
	}); err != nil {
		t.Fatalf("seeding the native record: %v", err)
	}
}

// jsonDocModuleTags gives each seeded module its own hash body. Indexed rather
// than derived, so adding a third module without deciding its tag panics here
// instead of silently sharing an artefact identity with the second.
var jsonDocModuleTags = []string{"aaaa", "bbbb"}

// jsonDocHashValue is a distinct, well-formed hash body per module and artefact
// kind, so the two modules never share an artefact identity — which is what
// composition groups records by.
func jsonDocHashValue(module int, kind string) string {
	return jsonDocModuleTags[module] + kind + "0000000="
}

// jsonDocArtefactIdentity is the zip identity the per-artefact records pin.
func jsonDocArtefactIdentity(module int) string {
	return fetchtest.ZipArtefact(jsonDocHashValue(module, "zip")).String()
}
