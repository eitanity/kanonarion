package cmd_test

import (
	"archive/zip"
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/rogpeppe/go-internal/testscript"
	"golang.org/x/mod/sumdb/dirhash"

	"github.com/eitanity/kanonarion/internal/adapters/blobstore/localfs"
	fetchsqlite "github.com/eitanity/kanonarion/internal/adapters/factstore/sqlite"
	"github.com/eitanity/kanonarion/internal/adapters/sqlitestore"
	cgsqlite "github.com/eitanity/kanonarion/internal/callgraph/adapters/store/sqlite"
	cgapp "github.com/eitanity/kanonarion/internal/callgraph/application"
	cgdomain "github.com/eitanity/kanonarion/internal/callgraph/domain"
	"github.com/eitanity/kanonarion/internal/cli"
	"github.com/eitanity/kanonarion/internal/coordinate"
	exsqlite "github.com/eitanity/kanonarion/internal/example/adapters/store/sqlite"
	exapp "github.com/eitanity/kanonarion/internal/example/application"
	exdomain "github.com/eitanity/kanonarion/internal/example/domain"
	fetchapp "github.com/eitanity/kanonarion/internal/fetch/application"
	fetchdomain "github.com/eitanity/kanonarion/internal/fetch/domain"
	"github.com/eitanity/kanonarion/internal/fetch/fetchtest"
	fetchports "github.com/eitanity/kanonarion/internal/fetch/ports"
	ifsqlite "github.com/eitanity/kanonarion/internal/iface/adapters/store/sqlite"
	ifapp "github.com/eitanity/kanonarion/internal/iface/application"
	ifdomain "github.com/eitanity/kanonarion/internal/iface/domain"
	licsqlite "github.com/eitanity/kanonarion/internal/license/adapters/store/sqlite"
	licapp "github.com/eitanity/kanonarion/internal/license/application"
	licdomain "github.com/eitanity/kanonarion/internal/license/domain"
	vulnsqlite "github.com/eitanity/kanonarion/internal/vuln/adapters/store/sqlite"
	vulnapp "github.com/eitanity/kanonarion/internal/vuln/application"
	vuldomain "github.com/eitanity/kanonarion/internal/vuln/domain"
	"github.com/eitanity/kanonarion/internal/vuln/vulntest"
	"github.com/eitanity/kanonarion/internal/walk/adapters/walks/sqlite"
	"github.com/eitanity/kanonarion/internal/walk/domain"
)

func TestMain(m *testing.M) {
	testscript.Main(m, map[string]func(){
		"kanonarion": func() {
			if err := cli.Run(os.Args[1:], os.Stdout, os.Stderr); err != nil {
				// Mirror cmd/kanonarion/main.go: the CLI silences cobra's own
				// error printing, so the entry point must surface the
				// returned error to stderr itself.
				fmt.Fprintf(os.Stderr, "error: %v\n", err)
				os.Exit(1)
			}
		},
		"seedwalk": func() {
			cmdSeedWalk(os.Args[1:])
		},
		"seedcallgraph": func() {
			cmdSeedCallGraph(os.Args[1:])
		},
		"seedlicense": func() {
			cmdSeedLicense(os.Args[1:])
		},
		"seediface": func() {
			cmdSeedIface(os.Args[1:])
		},
		"seedexamples": func() {
			cmdSeedExamples(os.Args[1:])
		},
		"seedvuln": func() {
			cmdSeedVuln(os.Args[1:])
		},
		"seedvulnforwalk": func() {
			cmdSeedVulnForWalk(os.Args[1:])
		},
		"seedvulnpartial": func() {
			cmdSeedVulnPartial(os.Args[1:])
		},
	})
}

func TestScript(t *testing.T) {
	testscript.Run(t, testscript.Params{
		Dir: filepath.Join("..", "test", "fixtures", "script"),
		Setup: func(env *testscript.Env) error {
			// Point HOME at the sandbox so ~/.kanonarion resolves inside WORK.
			env.Vars = append(env.Vars, "HOME="+env.WorkDir)

			// Symlink project-relative paths that tests might need
			root, err := filepath.Abs("..")
			if err != nil {
				return fmt.Errorf("abs: %w", err)
			}
			links := []string{"docs", "internal", "cmd", "test", "go.mod", "go.sum"}
			for _, link := range links {
				if err := os.Symlink(filepath.Join(root, link), filepath.Join(env.WorkDir, link)); err != nil {
					return fmt.Errorf("symlink: %w", err)
				}
			}
			return nil
		},
	})
}

func cmdSeedWalk(args []string) {
	if len(args) != 1 {
		os.Exit(1)
	}
	storeRoot := filepath.Clean(args[0])
	if err := os.MkdirAll(storeRoot, 0o750); err != nil {
		os.Exit(1)
	}
	dbPath := filepath.Join(storeRoot, "mirror.db")
	migrations := append(fetchsqlite.Migrations(), sqlite.Migrations()...)
	db, err := sqlitestore.Open(dbPath, migrations, sqlitestore.IntentCreate)
	if err != nil {
		os.Exit(1)
	}
	store := sqlite.New(db)
	factStore := fetchsqlite.New(db)
	blobStore := localfs.New(storeRoot)

	for _, rec := range buildFixtureWalkRecords() {
		if err := store.PutWalk(context.Background(), rec); err != nil {
			_ = db.Close()
			os.Exit(1)
		}
	}

	// Seed fetch records for each node in the walk so that 'context' command finds them.
	// This ensures "Verification: Verified" appears in the output.
	walks := buildFixtureWalkRecords()
	latestWalk := walks[len(walks)-1]
	for _, node := range latestWalk.Graph.Nodes {
		// The zip is the canonical fixture artefact, shared with every other seed
		// helper, so a coordinate seeded twice is measured as one artefact.
		zipContent, parsedZipHash, zipIdentity, aerr := fixtureArtefact(node.Coordinate)
		if aerr != nil {
			_ = db.Close()
			os.Exit(1)
		}
		modContent := []byte("module " + node.Coordinate.Path() + "\n")
		modHash, _ := dirhash.Hash1([]string{"go.mod"}, func(string) (io.ReadCloser, error) {
			return io.NopCloser(bytes.NewReader(modContent)), nil
		})

		// This is a testscript subprocess entry point: it calls os.Exit and has no
		// testing handle, so it cannot use the fetchtest builder. It seals through
		// domain.Seal instead, which needs none — and which is the only way to
		// obtain the SealedRecord the store accepts.
		parsedModHash, merr := fetchdomain.ParseModuleHash(modHash)
		if merr != nil {
			_ = db.Close()
			os.Exit(1)
		}
		goModIdentity, mierr := fetchports.NewBlobIdentity(fetchports.BlobKindGoMod, parsedModHash)
		if mierr != nil {
			_ = db.Close()
			os.Exit(1)
		}
		if err := blobStore.Put(context.Background(), zipIdentity, bytes.NewReader(zipContent)); err != nil {
			_ = db.Close()
			os.Exit(1)
		}
		if err := blobStore.Put(context.Background(), goModIdentity, bytes.NewReader(modContent)); err != nil {
			_ = db.Close()
			os.Exit(1)
		}

		sealed, serr := fetchdomain.Seal(fetchdomain.FetchedModule{
			Coordinate:         node.Coordinate,
			ModuleHash:         parsedZipHash,
			GoModHash:          parsedModHash,
			VerificationStatus: fetchdomain.Verified,
			FetchedAt:          time.Now(),
			PipelineVersion:    fetchapp.PipelineVersion, // track the live fetch pipeline version
			ContentLocation:    zipIdentity.String(),
			GoModLocation:      goModIdentity.String(),
			MeasurementKind:    fetchdomain.MeasurementAcquired,
		})
		if serr != nil {
			_ = db.Close()
			os.Exit(1)
		}
		if err := factStore.PutFetchRecord(context.Background(), sealed); err != nil {
			_ = db.Close()
			os.Exit(1)
		}
	}

	_ = db.Close()
}

// fixtureArtefact builds the canonical fixture zip for coord — the same bytes
// every seed helper uses — and returns the bytes with the blob identity that
// addresses them.
//
// It exists because the helpers used to disagree. seedwalk hashed a real zip and
// filed a fetch record naming it, while seedcallgraph and seedexamples filed one
// naming a fixed "zip:h1:fixture-zip=" they never stored. A fixture that ran both
// therefore held two measurements describing one pinned version as two different
// artefacts — a genuine contradiction, invisible only while every read was keyed
// by fetch pipeline version and so never saw both records at once. The composed
// read sees both, and the divergence guard fails closed on them, which is the
// correct answer to a contradictory ledger; the fixture is what had to change.
func fixtureArtefact(coord coordinate.ModuleCoordinate) ([]byte, fetchdomain.ModuleHash, fetchports.BlobIdentity, error) {
	fail := func(stage string, err error) ([]byte, fetchdomain.ModuleHash, fetchports.BlobIdentity, error) {
		return nil, fetchdomain.ModuleHash{}, fetchports.BlobIdentity{}, fmt.Errorf("building fixture artefact for %s: %s: %w", coord, stage, err)
	}
	buf := new(bytes.Buffer)
	zw := zip.NewWriter(buf)
	f, err := zw.Create(coord.Path() + "@" + coord.Version() + "/README")
	if err != nil {
		return fail("creating zip entry", err)
	}
	if _, err := f.Write([]byte("zip content for " + coord.String())); err != nil {
		return fail("writing zip entry", err)
	}
	if err := zw.Close(); err != nil {
		return fail("closing zip", err)
	}
	content := buf.Bytes()

	tmp, err := os.CreateTemp("", "seed-*.zip")
	if err != nil {
		return fail("creating temp zip", err)
	}
	defer func() { _ = os.Remove(tmp.Name()) }()
	if _, err := tmp.Write(content); err != nil {
		return fail("writing temp zip", err)
	}
	if err := tmp.Close(); err != nil {
		return fail("closing temp zip", err)
	}
	raw, err := dirhash.HashZip(tmp.Name(), dirhash.Hash1)
	if err != nil {
		return fail("hashing zip", err)
	}
	hash, err := fetchdomain.ParseModuleHash(raw)
	if err != nil {
		return fail("parsing zip hash", err)
	}
	identity, err := fetchports.NewBlobIdentity(fetchports.BlobKindZip, hash)
	if err != nil {
		return fail("deriving zip identity", err)
	}
	return content, hash, identity, nil
}

// seedFixtureFetchRecord stores the canonical fixture artefact for coord and files
// one fetch measurement of it, so every helper that needs a fetch record for a
// coordinate files the same one. It returns the artefact identity the derived
// records must name.
func seedFixtureFetchRecord(
	factStore *fetchsqlite.Store,
	blobStore *localfs.Store,
	coord coordinate.ModuleCoordinate,
) (fetchports.BlobIdentity, error) {
	content, hash, identity, err := fixtureArtefact(coord)
	if err != nil {
		return fetchports.BlobIdentity{}, err
	}
	if err := blobStore.Put(context.Background(), identity, bytes.NewReader(content)); err != nil {
		return fetchports.BlobIdentity{}, fmt.Errorf("storing fixture artefact for %s: %w", coord, err)
	}
	sealed, err := fetchdomain.Seal(fetchdomain.FetchedModule{
		Coordinate:         coord,
		ModuleHash:         hash,
		VerificationStatus: fetchdomain.Verified,
		PipelineVersion:    fetchapp.PipelineVersion,
		ContentLocation:    identity.String(),
		MeasurementKind:    fetchdomain.MeasurementAcquired,
	})
	if err != nil {
		return fetchports.BlobIdentity{}, fmt.Errorf("sealing fixture fetch record for %s: %w", coord, err)
	}
	if err := factStore.PutFetchRecord(context.Background(), sealed); err != nil {
		return fetchports.BlobIdentity{}, fmt.Errorf("filing fixture fetch record for %s: %w", coord, err)
	}
	return identity, nil
}

func buildFixtureWalkRecords() []domain.WalkRecord {
	app := mustFixtureCoord("example.com/app", "v1.0.0")
	dep10 := mustFixtureCoord("example.com/dep", "v1.0.0")
	dep11 := mustFixtureCoord("example.com/dep", "v1.1.0")
	newDep := mustFixtureCoord("example.com/new", "v1.0.0")
	startA := time.Date(2025, 1, 15, 12, 0, 0, 0, time.UTC)
	startB := time.Date(2025, 1, 15, 13, 0, 0, 0, time.UTC)
	graphA := domain.Graph{
		Target: app,
		Nodes: []domain.GraphNode{
			{Coordinate: app, ResolutionSource: domain.ResolutionTarget},
			{Coordinate: dep10, DirectDependency: true, ResolutionSource: domain.ResolutionMVS},
		},
		Edges:           []domain.GraphEdge{{From: app, To: dep10, ConstraintVersion: "v1.0.0"}},
		ResolvedAt:      startA,
		PipelineVersion: "1.0.0",
	}
	graphB := domain.Graph{
		Target: app,
		Nodes: []domain.GraphNode{
			{Coordinate: app, ResolutionSource: domain.ResolutionTarget},
			{Coordinate: dep11, DirectDependency: true, ResolutionSource: domain.ResolutionMVS},
			{Coordinate: newDep, DirectDependency: true, ResolutionSource: domain.ResolutionMVS},
		},
		Edges: []domain.GraphEdge{
			{From: app, To: dep11, ConstraintVersion: "v1.1.0"},
			{From: app, To: newDep, ConstraintVersion: "v1.0.0"},
		},
		ResolvedAt:      startB,
		PipelineVersion: "1.0.0",
	}
	outcomeA := domain.WalkOutcome{
		Target: app,
		Graph:  graphA,
		PerNodeResults: map[coordinate.ModuleCoordinate]domain.NodeResult{
			app:   {Coordinate: app, Status: domain.NodeSucceeded, DurationMs: 10},
			dep10: {Coordinate: dep10, Status: domain.NodeSucceeded, DurationMs: 5},
		},
		StartedAt:     startA,
		CompletedAt:   startA.Add(time.Second),
		OverallStatus: domain.WalkSucceeded,
	}
	outcomeB := domain.WalkOutcome{
		Target: app,
		Graph:  graphB,
		PerNodeResults: map[coordinate.ModuleCoordinate]domain.NodeResult{
			app:    {Coordinate: app, Status: domain.NodeSucceeded, DurationMs: 10},
			dep11:  {Coordinate: dep11, Status: domain.NodeSucceeded, DurationMs: 5},
			newDep: {Coordinate: newDep, Status: domain.NodeSucceeded, DurationMs: 3},
		},
		StartedAt:     startB,
		CompletedAt:   startB.Add(time.Second),
		OverallStatus: domain.WalkSucceeded,
	}
	var hasher domain.WalkRecordHasher
	recA := domain.NewWalkRecord("01ARZ3NDEKTSV4RRFFQ69G5FAV", "fixture", "1.0.0", domain.WalkScopeCode, domain.WalkDepthFull, outcomeA, domain.DefaultDepthPolicy(), "")
	recA, _ = hasher.SetContentHash(recA)
	recB := domain.NewWalkRecord("01ARZ3NDEKTSV4RRFFQ69G5FBB", "fixture", "1.0.0", domain.WalkScopeCode, domain.WalkDepthFull, outcomeB, domain.DefaultDepthPolicy(), "")
	recB, _ = hasher.SetContentHash(recB)
	return []domain.WalkRecord{recA, recB}
}

func cmdSeedCallGraph(args []string) {
	if len(args) != 1 {
		os.Exit(1)
	}
	storeRoot := filepath.Clean(args[0])
	if err := os.MkdirAll(storeRoot, 0o750); err != nil {
		os.Exit(1)
	}
	dbPath := filepath.Join(storeRoot, "mirror.db")
	migrations := append(fetchsqlite.Migrations(), cgsqlite.Migrations()...)
	db, err := sqlitestore.Open(dbPath, migrations, sqlitestore.IntentCreate)
	if err != nil {
		os.Exit(1)
	}
	store := cgsqlite.New(db)
	factStore := fetchsqlite.New(db)
	blobStore := localfs.New(storeRoot)

	app := mustFixtureCoord("example.com/app", "v1.0.0")
	// The fetch measurement comes first, so the graph record can name the artefact
	// that measurement describes rather than a hand-written identity that no stored
	// artefact matches.
	appArtefact, aerr := seedFixtureFetchRecord(factStore, blobStore, app)
	if aerr != nil {
		_ = db.Close()
		os.Exit(1)
	}
	rec := cgdomain.CallGraphRecord{
		SchemaVersion: cgdomain.CallGraphSchemaVersion,
		Ecosystem:     fetchdomain.EcosystemGo,
		Coordinate:    app,
		Algorithm:     cgdomain.AlgorithmCHA,
		OverallStatus: cgdomain.CallGraphStatusExtracted,
		// The test axis is measured, and a test caller of Helper is in the graph
		// alongside the production one, so the fixture exercises both the default
		// (include) and the --exclude-tests view.
		TestScope: cgdomain.TestScopeAnalysed,
		// The reference axis is measured too. Without it every empty answer over
		// this fixture would downgrade to UNRESOLVED for a reason that has
		// nothing to do with what the fixture is exercising.
		ReferenceScope: cgdomain.ReferenceScopeAnalysed,
		Nodes: []cgdomain.CallNode{
			{ID: "example.com/app.Main", Package: "example.com/app", Symbol: "Main", IsExportedAPI: true},
			{ID: "example.com/app.Helper", Package: "example.com/app", Symbol: "Helper"},
			{ID: "example.com/app_test.TestHelper", Package: "example.com/app_test", Symbol: "TestHelper", IsTest: true},
			{ID: "example.com/app.(*Store).Put", Package: "example.com/app", Symbol: "Put", Receiver: "*Store"},
			{ID: "example.com/app_test.(*fakeStore).Put", Package: "example.com/app_test", Symbol: "Put", Receiver: "*fakeStore", IsTest: true},
			{ID: "fmt.Println", Package: "fmt", Symbol: "Println", IsExternal: true},
		},
		Edges: []cgdomain.CallEdge{
			{FromID: "example.com/app.Main", ToID: "example.com/app.Helper", Confidence: cgdomain.ConfidenceDirect},
			{FromID: "example.com/app.Helper", ToID: "fmt.Println", Confidence: cgdomain.ConfidenceDirect},
			{FromID: "example.com/app_test.TestHelper", ToID: "example.com/app.Helper", Confidence: cgdomain.ConfidenceDirect},
		},
		// The type-level relation: one port with a production implementer and a
		// test fake, which is the shape an interface change has to enumerate.
		Interfaces: []cgdomain.InterfaceType{
			{
				ID: "example.com/app.Store", Package: "example.com/app", Name: "Store",
				Methods:  []string{"Put"},
				Position: cgdomain.SourcePosition{File: "app.go", Line: 3},
			},
		},
		Implementations: []cgdomain.InterfaceImplementation{
			{
				InterfaceID: "example.com/app.Store",
				TypeID:      "example.com/app.(*Store)",
				Package:     "example.com/app",
				Methods:     []cgdomain.ImplementedMethod{{Method: "Put", NodeID: "example.com/app.(*Store).Put"}},
			},
			{
				InterfaceID: "example.com/app.Store",
				TypeID:      "example.com/app_test.(*fakeStore)",
				Package:     "example.com/app_test",
				IsTest:      true,
				Methods:     []cgdomain.ImplementedMethod{{Method: "Put", NodeID: "example.com/app_test.(*fakeStore).Put"}},
			},
		},
		NodeCount:       6,
		EdgeCount:       3,
		ExtractedAt:     time.Now(),
		PipelineVersion: cgapp.PipelineVersion,
		Completeness:    cgdomain.CompletenessBuiltWithBodies,
		// The fixture stands in for a graph built from the fetched zip seeded
		// below, so it names that artefact. The store refuses a zip-sourced record
		// that names none: composition groups records by which bytes they measured,
		// and an empty identity groups every record that also recorded nothing.
		AnalysisSource:   cgdomain.AnalysisSourceModuleZip,
		ArtefactIdentity: appArtefact.String(),
	}
	var hasher cgdomain.CallGraphRecordHasher
	rec, _ = hasher.SetContentHash(rec)

	if err := store.PutCallGraphRecord(context.Background(), rec); err != nil {
		_ = db.Close()
		os.Exit(1)
	}

	_ = db.Close()
}

func cmdSeedLicense(args []string) {
	if len(args) != 1 {
		os.Exit(1)
	}
	storeRoot := filepath.Clean(args[0])
	if err := os.MkdirAll(storeRoot, 0o750); err != nil {
		os.Exit(1)
	}
	dbPath := filepath.Join(storeRoot, "mirror.db")
	db, err := sqlitestore.Open(dbPath, licsqlite.Migrations(), sqlitestore.IntentCreate)
	if err != nil {
		os.Exit(1)
	}
	store := licsqlite.New(db)

	app := mustFixtureCoord("example.com/app", "v1.0.0")
	rec := licdomain.LicenseRecord{
		SchemaVersion:     licdomain.LicenseSchemaVersion,
		Ecosystem:         fetchdomain.EcosystemGo,
		Coordinate:        app,
		PrimarySPDX:       "MIT",
		PrimaryConfidence: 1.0,
		OverallStatus:     licdomain.LicenseStatusDetected,
		LicenseFiles: []licdomain.LicenseFileEntry{
			{Path: "LICENSE", SPDX: "MIT", Confidence: 1.0, FileHash: "sha256:abc", FileSize: 1024},
		},
		ExtractedAt:      time.Now(),
		PipelineVersion:  licapp.PipelineVersion,
		ArtefactIdentity: fetchtest.ZipArtefact("fixture-zip=").String(),
	}
	rec.SortFiles()
	var hasher licdomain.LicenseRecordHasher
	rec, _ = hasher.SetContentHash(rec)

	if err := store.PutLicenseRecord(context.Background(), rec); err != nil {
		_ = db.Close()
		os.Exit(1)
	}
	_ = db.Close()
}

func cmdSeedIface(args []string) {
	if len(args) != 1 {
		os.Exit(1)
	}
	storeRoot := filepath.Clean(args[0])
	if err := os.MkdirAll(storeRoot, 0o750); err != nil {
		os.Exit(1)
	}
	dbPath := filepath.Join(storeRoot, "mirror.db")
	db, err := sqlitestore.Open(dbPath, ifsqlite.Migrations(), sqlitestore.IntentCreate)
	if err != nil {
		os.Exit(1)
	}
	store := ifsqlite.New(db)

	app := mustFixtureCoord("example.com/app", "v1.0.0")
	rec := ifdomain.InterfaceRecord{
		SchemaVersion: ifdomain.InterfaceSchemaVersion,
		Ecosystem:     fetchdomain.EcosystemGo,
		Coordinate:    app,
		OverallStatus: ifdomain.InterfaceStatusExtracted,
		Packages: []ifdomain.PackageInterface{
			{
				ImportPath: "example.com/app",
				Name:       "app",
				Funcs: []ifdomain.FuncDecl{
					{Name: "Main", Signature: "func Main()"},
				},
				Types: []ifdomain.TypeDecl{
					{Name: "Config", Kind: ifdomain.TypeKindStruct, Signature: "type Config struct{}"},
				},
			},
		},
		ExtractedAt:      time.Now(),
		PipelineVersion:  ifapp.PipelineVersion,
		ArtefactIdentity: fetchtest.ZipArtefact("fixture-zip=").String(),
	}
	var hasher ifdomain.InterfaceRecordHasher
	rec, _ = hasher.SetContentHash(rec)

	if err := store.PutInterfaceRecord(context.Background(), rec); err != nil {
		_ = db.Close()
		os.Exit(1)
	}
	_ = db.Close()
}

func cmdSeedExamples(args []string) {
	if len(args) != 1 {
		os.Exit(1)
	}
	storeRoot := filepath.Clean(args[0])
	if err := os.MkdirAll(storeRoot, 0o750); err != nil {
		os.Exit(1)
	}
	dbPath := filepath.Join(storeRoot, "mirror.db")
	migrations := append(fetchsqlite.Migrations(), exsqlite.Migrations()...)
	db, err := sqlitestore.Open(dbPath, migrations, sqlitestore.IntentCreate)
	if err != nil {
		os.Exit(1)
	}
	store := exsqlite.New(db)
	factStore := fetchsqlite.New(db)
	blobStore := localfs.New(storeRoot)

	app := mustFixtureCoord("example.com/app", "v1.0.0")
	appArtefact, aerr := seedFixtureFetchRecord(factStore, blobStore, app)
	if aerr != nil {
		_ = db.Close()
		os.Exit(1)
	}
	rec := exdomain.ExampleRecord{
		SchemaVersion: exdomain.ExampleSchemaVersion,
		Ecosystem:     fetchdomain.EcosystemGo,
		Coordinate:    app,
		OverallStatus: exdomain.ExampleStatusFound,
		Examples: []exdomain.ExampleEntry{
			{
				Name:             "ExampleMain",
				Package:          "app",
				AssociatedSymbol: "Main",
				Body:             "fmt.Println(\"hello\")",
				Output:           "hello",
				Validates:        true,
			},
		},
		ParseFailures: []exdomain.ParseFailure{
			{File: "broken.go", Error: "syntax error"},
		},
		ExtractedAt:      time.Now(),
		PipelineVersion:  exapp.PipelineVersion,
		ArtefactIdentity: appArtefact.String(),
	}
	var hasher exdomain.ExampleRecordHasher
	rec, _ = hasher.SetContentHash(rec)

	if err := store.PutExampleRecord(context.Background(), rec); err != nil {
		_ = db.Close()
		os.Exit(1)
	}

	_ = db.Close()
}

// fixtureSnapshotBody is the advisory-database blob every seeder stores. The
// store seals a snapshot against the bytes it is given and refuses a declared
// hash those bytes contradict, so the fixtures hash this constant rather than
// asserting a placeholder.
const fixtureSnapshotBody = "{}"

func cmdSeedVuln(args []string) {
	if len(args) != 1 {
		os.Exit(1)
	}
	storeRoot := filepath.Clean(args[0])
	if err := os.MkdirAll(storeRoot, 0o750); err != nil {
		os.Exit(1)
	}
	dbPath := filepath.Join(storeRoot, "mirror.db")
	db, err := sqlitestore.Open(dbPath, vulnsqlite.Migrations(), sqlitestore.IntentCreate)
	if err != nil {
		os.Exit(1)
	}
	store := vulnsqlite.New(db)
	ctx := context.Background()

	snap := vulntest.MustSeal("govulndb", "v2025-01-01T00-00-00", time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC), vuldomain.HashSnapshotContent([]byte(fixtureSnapshotBody)))
	if err := store.PutDatabaseSnapshot(ctx, snap, strings.NewReader(fixtureSnapshotBody)); err != nil {
		_ = db.Close()
		os.Exit(1)
	}

	app := mustFixtureCoord("example.com/app", "v1.0.0")
	walkID := "01JWALKFIXTURE000000000001"
	runID1 := "01JSCANRUN0000000000000001"
	runID2 := "01JSCANRUN0000000000000002"
	scannedAt := time.Date(2025, 1, 1, 12, 0, 0, 0, time.UTC)

	vulnRec := vuldomain.VulnerabilityRecord{
		Ecosystem:        fetchdomain.EcosystemGo,
		Coordinate:       app,
		WalkID:           walkID,
		OverallStatus:    vuldomain.StatusAffected,
		DatabaseSnapshot: snap,
		Findings: []vuldomain.VulnerabilityFinding{
			{
				ID:            "GO-2025-0001",
				Aliases:       []string{"CVE-2025-0001"},
				Summary:       "example vulnerability",
				AffectedRange: "<v1.1.0",
				FixedIn:       "v1.1.0",
				PublishedAt:   scannedAt,
				ModifiedAt:    scannedAt,
			},
		},
		ScannedAt:       scannedAt,
		PipelineVersion: vulnapp.PipelineVersion,
		ContentHash:     "sha256:vulnrec",
	}
	if err := store.PutVulnerabilityRecord(ctx, sealVulnRecord(vulnRec)); err != nil {
		_ = db.Close()
		os.Exit(1)
	}

	run1 := vuldomain.WalkScanRun{
		ID:       runID1,
		WalkID:   walkID,
		Snapshot: snap,
		PerModuleResults: map[coordinate.ModuleCoordinate]string{
			app: vulnRec.ContentHash,
		},
		StartedAt:       scannedAt,
		CompletedAt:     scannedAt.Add(time.Second),
		OverallStatus:   vuldomain.WalkStatusAffected,
		PipelineVersion: vulnapp.PipelineVersion,
		Operator:        "test",
		ContentHash:     "sha256:run1",
	}
	if err := store.PutWalkScanRun(ctx, sealVulnRun(run1)); err != nil {
		_ = db.Close()
		os.Exit(1)
	}

	run2 := vuldomain.WalkScanRun{
		ID:               runID2,
		WalkID:           walkID,
		Snapshot:         snap,
		PerModuleResults: map[coordinate.ModuleCoordinate]string{},
		StartedAt:        scannedAt.Add(time.Hour),
		CompletedAt:      scannedAt.Add(time.Hour + time.Second),
		OverallStatus:    vuldomain.WalkStatusAllClean,
		PipelineVersion:  vulnapp.PipelineVersion,
		Operator:         "test",
		ContentHash:      "sha256:run2",
	}
	if err := store.PutWalkScanRun(ctx, sealVulnRun(run2)); err != nil {
		_ = db.Close()
		os.Exit(1)
	}

	_ = db.Close()
}

// cmdSeedVulnPartial seeds a walk scan run with mixed results: one Clean
// record, one ScanFailed record (with ErrorDetail), and one Unscannable record
// (with UnscannableReason). The overall walk status is Partial.
func cmdSeedVulnPartial(args []string) {
	if len(args) != 1 {
		os.Exit(1)
	}
	storeRoot := filepath.Clean(args[0])
	if err := os.MkdirAll(storeRoot, 0o750); err != nil {
		os.Exit(1)
	}
	dbPath := filepath.Join(storeRoot, "mirror.db")
	db, err := sqlitestore.Open(dbPath, vulnsqlite.Migrations(), sqlitestore.IntentCreate)
	if err != nil {
		os.Exit(1)
	}
	store := vulnsqlite.New(db)
	ctx := context.Background()

	snap := vulntest.MustSeal("govulndb", "v2025-01-01T00-00-00", time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC), vuldomain.HashSnapshotContent([]byte(fixtureSnapshotBody)))
	if err := store.PutDatabaseSnapshot(ctx, snap, strings.NewReader(fixtureSnapshotBody)); err != nil {
		_ = db.Close()
		os.Exit(1)
	}

	walkID := "01JWALKPARTIAL00000000001"
	scannedAt := time.Date(2025, 1, 1, 12, 0, 0, 0, time.UTC)

	clean := mustFixtureCoord("example.com/clean", "v1.0.0")
	failed := mustFixtureCoord("example.com/failed", "v1.0.0")
	unscan := mustFixtureCoord("example.com/noscan", "v1.0.0")

	cleanRec := vuldomain.VulnerabilityRecord{
		Ecosystem:  fetchdomain.EcosystemGo,
		Coordinate: clean, WalkID: walkID,
		OverallStatus: vuldomain.StatusClean, DatabaseSnapshot: snap,
		ScannedAt: scannedAt, PipelineVersion: vulnapp.PipelineVersion, ContentHash: "sha256:clean",
	}
	failedRec := vuldomain.VulnerabilityRecord{
		Ecosystem:  fetchdomain.EcosystemGo,
		Coordinate: failed, WalkID: walkID,
		OverallStatus:    vuldomain.StatusScanFailed,
		ErrorDetail:      "govulncheck: binary not found in module zip",
		DatabaseSnapshot: snap,
		ScannedAt:        scannedAt, PipelineVersion: vulnapp.PipelineVersion, ContentHash: "sha256:failed",
	}
	unscanRec := vuldomain.VulnerabilityRecord{
		Ecosystem:  fetchdomain.EcosystemGo,
		Coordinate: unscan, WalkID: walkID,
		OverallStatus:     vuldomain.StatusUnscannable,
		UnscannableReason: "no go.mod found in module zip",
		DatabaseSnapshot:  snap,
		ScannedAt:         scannedAt, PipelineVersion: vulnapp.PipelineVersion, ContentHash: "sha256:unscan",
	}

	for _, rec := range []vuldomain.VulnerabilityRecord{cleanRec, failedRec, unscanRec} {
		if err := store.PutVulnerabilityRecord(ctx, sealVulnRecord(rec)); err != nil {
			_ = db.Close()
			os.Exit(1)
		}
	}

	run := vuldomain.WalkScanRun{
		ID:       "01JSCANRUN0PARTIAL0000001",
		WalkID:   walkID,
		Snapshot: snap,
		PerModuleResults: map[coordinate.ModuleCoordinate]string{
			clean:  cleanRec.ContentHash,
			failed: failedRec.ContentHash,
			unscan: unscanRec.ContentHash,
		},
		StartedAt:       scannedAt,
		CompletedAt:     scannedAt.Add(time.Second),
		OverallStatus:   vuldomain.WalkStatusPartial,
		PipelineVersion: vulnapp.PipelineVersion,
		Operator:        "test",
		ContentHash:     "sha256:runpartial",
	}
	if err := store.PutWalkScanRun(ctx, sealVulnRun(run)); err != nil {
		_ = db.Close()
		os.Exit(1)
	}

	_ = db.Close()
}

// cmdSeedVulnForWalk seeds vuln data aligned with the latest walk created by
// cmdSeedWalk (walk ID 01ARZ3NDEKTSV4RRFFQ69G5FBB). It creates a scan run
// where example.com/app@v1.0.0 has an Affected VulnerabilityRecord and
// example.com/dep@v1.1.0 appears in PerModuleResults but has no record, so
// that tests can verify the --affected-only flag includes both.
func cmdSeedVulnForWalk(args []string) {
	if len(args) != 1 {
		os.Exit(1)
	}
	storeRoot := filepath.Clean(args[0])
	if err := os.MkdirAll(storeRoot, 0o750); err != nil {
		os.Exit(1)
	}
	dbPath := filepath.Join(storeRoot, "mirror.db")
	allMigs := append(append(fetchsqlite.Migrations(), sqlite.Migrations()...), vulnsqlite.Migrations()...)
	db, err := sqlitestore.Open(dbPath, allMigs, sqlitestore.IntentCreate)
	if err != nil {
		os.Exit(1)
	}
	store := vulnsqlite.New(db)
	ctx := context.Background()

	// walkID matches the latest walk created by cmdSeedWalk.
	const walkID = "01ARZ3NDEKTSV4RRFFQ69G5FBB"

	snap := vulntest.MustSeal("govulndb", "v2025-01-01T00-00-00", time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC), vuldomain.HashSnapshotContent([]byte(fixtureSnapshotBody)))
	if err := store.PutDatabaseSnapshot(ctx, snap, strings.NewReader(fixtureSnapshotBody)); err != nil {
		_ = db.Close()
		os.Exit(1)
	}

	app := mustFixtureCoord("example.com/app", "v1.0.0")
	dep := mustFixtureCoord("example.com/dep", "v1.1.0")
	// example.com/new@v1.0.0 is intentionally absent from PerModuleResults (Clean).
	scannedAt := time.Date(2025, 1, 1, 12, 0, 0, 0, time.UTC)

	// app has a full Affected VulnerabilityRecord.
	vulnRec := vuldomain.VulnerabilityRecord{
		Ecosystem:        fetchdomain.EcosystemGo,
		Coordinate:       app,
		WalkID:           walkID,
		OverallStatus:    vuldomain.StatusAffected,
		DatabaseSnapshot: snap,
		Findings: []vuldomain.VulnerabilityFinding{
			{
				ID:            "GO-2025-0001",
				Summary:       "example vulnerability",
				AffectedRange: "<v1.1.0",
				FixedIn:       "v1.1.0",
				PublishedAt:   scannedAt,
				ModifiedAt:    scannedAt,
			},
		},
		ScannedAt:       scannedAt,
		PipelineVersion: vulnapp.PipelineVersion,
		ContentHash:     "sha256:vulnrec-app",
	}
	if err := store.PutVulnerabilityRecord(ctx, sealVulnRecord(vulnRec)); err != nil {
		_ = db.Close()
		os.Exit(1)
	}

	// dep is listed in PerModuleResults with a non-empty content hash but has
	// no corresponding VulnerabilityRecord — simulates the scenario.
	run := vuldomain.WalkScanRun{
		ID:       "01JSCANRUN00WALKFIX0000001",
		WalkID:   walkID,
		Snapshot: snap,
		PerModuleResults: map[coordinate.ModuleCoordinate]string{
			app: vulnRec.ContentHash,
			dep: "sha256:dep-norecord", // record was never stored
		},
		StartedAt:       scannedAt,
		CompletedAt:     scannedAt.Add(time.Second),
		OverallStatus:   vuldomain.WalkStatusAffected,
		PipelineVersion: vulnapp.PipelineVersion,
		Operator:        "test",
		ContentHash:     "sha256:run-walkfix",
	}
	if err := store.PutWalkScanRun(ctx, sealVulnRun(run)); err != nil {
		_ = db.Close()
		os.Exit(1)
	}

	_ = db.Close()
}

func mustFixtureCoord(path, version string) coordinate.ModuleCoordinate {
	c, err := coordinate.NewModuleCoordinate(path, version)
	if err != nil {
		panic(err)
	}
	return c
}

// sealVulnRecord stamps a seeded record with its content hash. The store
// refuses an unsealed record, exactly as it does in production, so a fixture
// that skipped this would be seeding a write that cannot happen.
func sealVulnRecord(rec vuldomain.VulnerabilityRecord) vuldomain.VulnerabilityRecord {
	sealed, err := vuldomain.VulnerabilityRecordHasher{}.SetContentHash(rec)
	if err != nil {
		panic("sealing seeded vulnerability record: " + err.Error())
	}
	return sealed
}

// sealVulnRun is sealVulnRecord for a walk scan run.
func sealVulnRun(run vuldomain.WalkScanRun) vuldomain.WalkScanRun {
	sealed, err := vuldomain.WalkScanRunHasher{}.SetContentHash(run)
	if err != nil {
		panic("sealing seeded walk scan run: " + err.Error())
	}
	return sealed
}
