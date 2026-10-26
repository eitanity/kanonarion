package cli

import (
	"context"
	"io"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"testing"
	"time"

	"code.eitanity.com/kanonarion/internal/adapters/goenv"
	"code.eitanity.com/kanonarion/internal/adapters/sqlitestore"
	cgsqlite "code.eitanity.com/kanonarion/internal/callgraph/adapters/store/sqlite"
	cgapp "code.eitanity.com/kanonarion/internal/callgraph/application"
	cgdomain "code.eitanity.com/kanonarion/internal/callgraph/domain"
	"code.eitanity.com/kanonarion/internal/coordinate"
	fetchdomain "code.eitanity.com/kanonarion/internal/fetch/domain"
	vulnsqlite "code.eitanity.com/kanonarion/internal/vuln/adapters/store/sqlite"
	vulnapp "code.eitanity.com/kanonarion/internal/vuln/application"
	vuldomain "code.eitanity.com/kanonarion/internal/vuln/domain"
	"code.eitanity.com/kanonarion/internal/vuln/vulntest"
	"github.com/spf13/cobra"
)

// recordingFrames records every read frame a container is told to select.
type recordingFrames struct{ frames []cgdomain.BuildFrame }

func (r *recordingFrames) WithReadFrame(f cgdomain.BuildFrame) { r.frames = append(r.frames, f) }

func (r *recordingFrames) last() cgdomain.BuildFrame {
	if len(r.frames) == 0 {
		return cgdomain.BuildFrame{}
	}
	return r.frames[len(r.frames)-1]
}

var arm64Frame = cgdomain.BuildFrame{GOOS: "linux", GOARCH: "arm64"}

// A declaration settled while a container is open re-wires that container's
// read frame, whichever resolver settled it, so the order in which a command
// opens its store and resolves its flags cannot leave it in the host frame.
func TestDeclare_ReadoptsEveryOpenContainer(t *testing.T) {
	requireGoOnPath(t)
	ctr, cleanup, err := NewContainer(walkFrameVulnStore(t), "", "", false, activeConfig, buildLogger("error", io.Discard))
	if err != nil {
		t.Fatal(err)
	}
	rec := &recordingFrames{}
	ctr.cgFrames = rec
	t.Cleanup(func() { declare(goenv.Target{}, goenv.TinyGo{}) })

	if rerr := resolveBuildTarget(context.Background(), buildTargetFlags{target: "linux/arm64"}, "", ""); rerr != nil {
		t.Fatal(rerr)
	}
	if !cgdomain.SameFrame(rec.last(), arm64Frame) {
		t.Errorf("after resolveBuildTarget the open container reads in %s", rec.last())
	}
	if aerr := adoptNamedWalkFrame(context.Background(), ctr.QueryWalks, walkFrameReadWalkID); aerr != nil {
		t.Fatal(aerr)
	}
	if !cgdomain.SameFrame(rec.last(), inheritWasm) {
		t.Errorf("after adopting a wasip1 walk the open container reads in %s", rec.last())
	}
	if rerr := resolveReadTarget(context.Background(), buildTargetFlags{}, "callers", true, ""); rerr != nil {
		t.Fatal(rerr)
	}
	if !cgdomain.SameFrame(rec.last(), hostFrame()) {
		t.Errorf("an undeclared resolution left the open container in %s", rec.last())
	}

	// A released container is no longer re-wired.
	if cerr := cleanup(); cerr != nil {
		t.Fatal(cerr)
	}
	n := len(rec.frames)
	declare(goenv.Target{}, goenv.TinyGo{})
	if len(rec.frames) != n {
		t.Error("a released container was re-wired")
	}
}

// arm64Store is a store root over a real tree holding a host and a linux/arm64
// graph of the tree's module, each calling a function named for its frame, a
// project walk of the tree for each frame, and the arm64 walk's record of the
// dependency with a route rooted at the arm64 function.
func arm64Store(t *testing.T) (root, tree string) {
	t.Helper()
	root, tree, host := upgradeStoreHost(t)
	arm := host
	arm.platform.GOOS, arm.platform.GOARCH = "linux", "arm64"
	ctx := context.Background()
	db, err := sqlitestore.Open(filepath.Join(root, "mirror.db"), nil, sqlitestore.IntentCreate)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()
	if aerr := sqlitestore.Apply(db, allMigrations()); aerr != nil {
		t.Fatal(aerr)
	}
	app, err := coordinate.NewLocalCoordinate(jsonDocRootPath)
	if err != nil {
		t.Fatal(err)
	}
	at := jsonDocAt
	graphs := cgsqlite.New(db)
	for i, g := range []struct {
		frame cgdomain.BuildFrame
		fn    string
	}{{hostFrame(), "HostOnly"}, {arm64Frame, "ArmOnly"}} {
		main, fn, dep := jsonDocRootPath+".main", jsonDocRootPath+"."+g.fn, jsonDocDep.Path()+".Name"
		r := cgdomain.CallGraphRecord{
			SchemaVersion: cgdomain.CallGraphSchemaVersion, Ecosystem: fetchdomain.EcosystemGo, Coordinate: app,
			Algorithm: cgdomain.AlgorithmCHA, Completeness: cgdomain.CompletenessBuiltWithBodies,
			OverallStatus: cgdomain.CallGraphStatusExtracted, AnalysisSource: cgdomain.AnalysisSourceWorktree,
			WorktreeDigest: "analysed-sha256:t", WorktreeScanDigest: "scanned-sha256:t", AnalysisRoot: tree,
			TestScope: cgdomain.TestScopeAnalysed, ReferenceScope: cgdomain.ReferenceScopeAnalysed,
			Nodes: []cgdomain.CallNode{
				{ID: main, Module: jsonDocRootPath, Package: jsonDocRootPath, Symbol: "main"},
				{ID: fn, Module: jsonDocRootPath, Package: jsonDocRootPath, Symbol: g.fn, IsExportedAPI: true},
				{ID: dep, Module: jsonDocDep.Path(), Package: jsonDocDep.Path(), Symbol: "Name", IsExternal: true},
			},
			Edges: []cgdomain.CallEdge{
				{FromID: main, ToID: fn, Confidence: cgdomain.ConfidenceDirect, CallSite: cgdomain.SourcePosition{File: "root.go", Line: 3}},
				{FromID: fn, ToID: dep, Confidence: cgdomain.ConfidenceDirect, CallSite: cgdomain.SourcePosition{File: "root.go", Line: 5}},
			},
			Interfaces: []cgdomain.InterfaceType{{ID: jsonDocRootPath + ".Store", Package: jsonDocRootPath, Name: "Store", Methods: []string{"Get"}}},
			Implementations: []cgdomain.InterfaceImplementation{{
				InterfaceID: jsonDocRootPath + ".Store", TypeID: jsonDocRootPath + ".(*" + g.fn + "Store)", Package: jsonDocRootPath,
				Methods: []cgdomain.ImplementedMethod{{Method: "Get", NodeID: fn}},
			}},
			NodeCount: 3, EdgeCount: 2, ExtractedAt: at.Add(time.Duration(i) * time.Hour),
			PipelineVersion: cgapp.PipelineVersion, Frame: g.frame,
		}
		putSealedGraph(t, graphs, r)
		// The dependency's own graph in the same frame, exporting a function
		// named for it.
		api := jsonDocDep.Path() + "." + g.fn + "API"
		putSealedGraph(t, graphs, cgdomain.CallGraphRecord{
			SchemaVersion: cgdomain.CallGraphSchemaVersion, Ecosystem: fetchdomain.EcosystemGo, Coordinate: jsonDocDep,
			Algorithm: cgdomain.AlgorithmCHA, Completeness: cgdomain.CompletenessBuiltWithBodies,
			OverallStatus: cgdomain.CallGraphStatusExtracted, AnalysisSource: cgdomain.AnalysisSourceModuleZip, ArtefactIdentity: "zip:h1:dep",
			Nodes: []cgdomain.CallNode{
				{ID: dep, Module: jsonDocDep.Path(), Package: jsonDocDep.Path(), Symbol: "Name", IsExportedAPI: true},
				{ID: api, Module: jsonDocDep.Path(), Package: jsonDocDep.Path(), Symbol: g.fn + "API", IsExportedAPI: true},
			},
			Edges:     []cgdomain.CallEdge{{FromID: api, ToID: dep, Confidence: cgdomain.ConfidenceDirect, CallSite: cgdomain.SourcePosition{File: "dep.go", Line: 4}}},
			NodeCount: 2, EdgeCount: 1, ExtractedAt: at.Add(time.Duration(i) * time.Hour),
			PipelineVersion: cgapp.PipelineVersion, Frame: g.frame,
		})
	}
	const hostWalk, armWalk, armRun = "01JS0NARM640000000000000WH", "01JS0NARM640000000000000WA", "01JS0NARM640000000000000RA"
	seedProjectWalk(t, ctx, db, app, host, tree, seedWalkSpec{walkID: hostWalk, toolchain: host.toolchain, at: at})
	seedProjectWalk(t, ctx, db, app, arm, tree, seedWalkSpec{walkID: armWalk, toolchain: arm.toolchain, at: at.Add(time.Hour)})

	store := vulnsqlite.New(db)
	snapshot := vulntest.MustNewAt(jsonDocSnapSource, "v2026-03-09", at)
	if perr := store.PutDatabaseSnapshot(ctx, snapshot, strings.NewReader("advisory snapshot arm64")); perr != nil {
		t.Fatal(perr)
	}
	rooting := vuldomain.TargetRootedAt(app)
	vrec := vuldomain.VulnerabilityRecord{
		Ecosystem: fetchdomain.EcosystemGo, Coordinate: jsonDocDep, WalkID: armWalk,
		OverallStatus: vuldomain.StatusAffected, DatabaseSnapshot: snapshot, ScannedAt: at.Add(time.Hour),
		PipelineVersion: vulnapp.PipelineVersion, Rooting: rooting, Toolchain: "go1.27.2",
		Findings: []vuldomain.VulnerabilityFinding{{
			ID: jsonDocFindingID, Summary: "a routed finding", AffectedRange: "< v1.3.0", FixedIn: "v1.3.0",
			Reachable: &vuldomain.ReachabilityResult{
				IsReachable: true, Confidence: vuldomain.ConfidenceHigh,
				DerivedBy: vuldomain.ReachabilityDerivation{Analyser: vuldomain.AnalyserGovulncheck, Fidelity: "source", Rooting: rooting},
				Routes: []vuldomain.ReachabilityRoute{{
					{ModulePath: jsonDocRootPath, Package: jsonDocRootPath, Symbol: "ArmOnly"},
					{ModulePath: jsonDocDep.Path(), ModuleVersion: jsonDocDep.Version(), Package: jsonDocDep.Path(), Symbol: "Name"},
				}},
			},
		}},
	}
	if vrec, err = (vuldomain.VulnerabilityRecordHasher{}).SetContentHash(vrec); err != nil {
		t.Fatal(err)
	}
	if perr := store.PutVulnerabilityRecord(ctx, vrec); perr != nil {
		t.Fatal(perr)
	}
	run := vuldomain.WalkScanRun{
		ID: armRun, WalkID: armWalk, Snapshot: snapshot,
		PerModuleResults: map[coordinate.ModuleCoordinate]string{jsonDocDep: vrec.ContentHash},
		StartedAt:        at.Add(time.Hour), CompletedAt: at.Add(time.Hour + time.Second), OverallStatus: vuldomain.WalkStatusAffected,
		Operator: "guard", PipelineVersion: vulnapp.PipelineVersion,
	}
	if run, err = (vuldomain.WalkScanRunHasher{}).SetContentHash(run); err != nil {
		t.Fatal(err)
	}
	if perr := store.PutWalkScanRun(ctx, run); perr != nil {
		t.Fatal(perr)
	}
	return root, tree
}

func putSealedGraph(t *testing.T, graphs *cgsqlite.Store, r cgdomain.CallGraphRecord) {
	t.Helper()
	sealed, err := cgdomain.CallGraphRecordHasher{}.SetContentHash(r)
	if err != nil {
		t.Fatal(err)
	}
	if perr := graphs.PutCallGraphRecord(context.Background(), sealed); perr != nil {
		t.Fatal(perr)
	}
}

// frameGuardCase is one invocation of a command carrying the build-target
// flags, run with --target linux/arm64, and what in its answer shows the arm64
// record answered. exempt names why a command has no such observable.
type frameGuardCase struct {
	args   func(tree string) []string
	want   string
	exempt string
}

// frameGuardCases covers every command carrying the build-target flags; the
// guard below fails for one missing from it.
var frameGuardCases = map[string][]frameGuardCase{
	"callers": {{args: func(string) []string { return []string{"callers", jsonDocRootPath + ".ArmOnly"} }, want: jsonDocRootPath + ".main"}},
	"callees": {{args: func(string) []string { return []string{"callees", jsonDocRootPath + ".main"} }, want: jsonDocRootPath + ".ArmOnly"}},
	"callgraph-show": {{args: func(string) []string { return []string{"callgraph-show", jsonDocRootPath + "@local"} },
		want: "frame: linux/arm64"}},
	"implementers": {{args: func(string) []string { return []string{"implementers", jsonDocRootPath + ".Store"} }, want: "(*ArmOnlyStore)"}},
	"capability": {{args: func(string) []string { return []string{"capability", jsonDocRootPath + "@local"} },
		want: "frame: linux/arm64"}},
	"usage": {{args: func(tree string) []string {
		return []string{"usage", jsonDocDepCoord, "--gomod", filepath.Join(tree, "go.mod")}
	}, want: jsonDocDep.Path() + ".ArmOnlyAPI"}},
	"vuln-show": {{args: func(tree string) []string {
		return []string{"vuln-show", jsonDocDepCoord, "--gomod", filepath.Join(tree, "go.mod")}
	}, want: "node:   " + jsonDocRootPath + ".ArmOnly"}},
	"reachability": {
		{args: func(tree string) []string {
			return []string{"reachability", jsonDocDepCoord, "--vuln", jsonDocFindingID, "--gomod", filepath.Join(tree, "go.mod")}
		}, want: "node: " + jsonDocRootPath + ".ArmOnly"},
		{args: func(tree string) []string { return []string{"reachability", "--local", tree} }, want: "frame:     linux/arm64"},
	},
	"context": {{args: func(tree string) []string {
		return []string{"context", "--gomod", filepath.Join(tree, "go.mod"), "--json", "--entry-points-full"}
	}, want: jsonDocDep.Path() + ".ArmOnlyAPI"}},
	"symbol-context": {{exempt: "resolves the symbol through interface records, measured in the host frame, before any call-graph read"}},
	"symbol-find":    {{exempt: "reads interface records, which are measured in the host frame"}},
	"examples-find":  {{exempt: "reads examples records, which apply no build constraint"}},
	"dependents":     {{exempt: "reads walks only; the walk is selected by the declared platform before the store opens"}},
	"walk-list":      {{exempt: "--goos/--goarch/--tinygo filter the listed walks; it reads no call graph"}},
	"local":          {{args: func(tree string) []string { return []string{"local", tree} }, want: "frame linux/arm64"}},
	"callgraph": {{exempt: "extracts a fetched module; the frame it records is held by the --from-walk and local tests, " +
		"and it resolves before opening the store"}},
	"walk":      {{exempt: "resolves the build; it resolves its declaration before opening the store and reads no call graph"}},
	"audit":     {{exempt: "resolves and scans over the network; it resolves before opening the store"}},
	"inspect":   {{exempt: "resolves and scans over the network; it resolves before opening the store"}},
	"vuln-scan": {{exempt: "scans over the network; it resolves before opening the store, and its call graphs come from children"}},
	"sbom":      {{exempt: "reads walks and fetch records; it resolves before opening the store"}},
}

// commandsWithBuildTargetFlags walks the command tree for every command that
// registers the build-target declaration.
func commandsWithBuildTargetFlags() []string {
	var names []string
	var walk func(c *cobra.Command)
	walk = func(c *cobra.Command) {
		if c.Flags().Lookup("goarch") != nil && c.Flags().Lookup("tinygo") != nil {
			names = append(names, c.Name())
		}
		for _, sub := range c.Commands() {
			walk(sub)
		}
	}
	walk(newRootCmd(io.Discard, io.Discard))
	sort.Strings(names)
	return names
}

// Every command carrying the declaration answers from the declared frame's
// call graph, whichever order it opens the store and resolves the flag in.
func TestDeclaredTarget_EveryCommandReadsTheDeclaredFrame(t *testing.T) {
	requireGoOnPath(t)
	root, tree := arm64Store(t)
	names := commandsWithBuildTargetFlags()
	if len(names) < 10 {
		t.Fatalf("found %d commands carrying the flags: the walk is broken", len(names))
	}
	// local writes a newer record of the tree, so it runs last.
	sort.SliceStable(names, func(i, j int) bool { return names[j] == "local" && names[i] != "local" })
	for _, name := range names {
		cases, ok := frameGuardCases[name]
		if !ok {
			t.Errorf("%s carries --target and has no case here: add one, or an exemption naming why it reads no call graph", name)
			continue
		}
		for _, c := range cases {
			if c.exempt != "" {
				continue
			}
			args := append(c.args(tree), "--target", "linux/arm64")
			out, stderr, code := runTinyGoCLI(t, root, args...)
			if !strings.Contains(out+stderr, c.want) {
				t.Errorf("%v = exit %d, want %q from the arm64 record:\n%s%s", args, code, c.want, out, stderr)
			}
		}
	}
	for name := range frameGuardCases {
		if !slices.Contains(names, name) {
			t.Errorf("case %s names no command carrying the flags", name)
		}
	}
}
