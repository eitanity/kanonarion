package cli

import (
	"context"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"code.eitanity.com/kanonarion/internal/adapters/sqlitestore"
	cgsqlite "code.eitanity.com/kanonarion/internal/callgraph/adapters/store/sqlite"
	cgapp "code.eitanity.com/kanonarion/internal/callgraph/application"
	cgdomain "code.eitanity.com/kanonarion/internal/callgraph/domain"
	"code.eitanity.com/kanonarion/internal/coordinate"
	fetchdomain "code.eitanity.com/kanonarion/internal/fetch/domain"
	"code.eitanity.com/kanonarion/internal/gotoolchain"
	"code.eitanity.com/kanonarion/internal/vuln/adapters/reachability"
	vulnsqlite "code.eitanity.com/kanonarion/internal/vuln/adapters/store/sqlite"
	vulnapp "code.eitanity.com/kanonarion/internal/vuln/application"
	vuldomain "code.eitanity.com/kanonarion/internal/vuln/domain"
	"code.eitanity.com/kanonarion/internal/vuln/vulntest"
)

const (
	vulnFrameMissWalk = "01JS0NVFRAMEM1SS000000HOST1"
	vulnFrameMissRun  = "01JS0NVFRAMEM1SS000000RUN01"
)

// vulnFrameMissStore is a store over a real tree whose module's call graph is
// held under each of frames, a host project walk, and the host scan's record of
// the dependency with a route main → dep.Name. The route's hops are annotated
// at seed time the way a host scan annotates them.
func vulnFrameMissStore(t *testing.T, frames []cgdomain.BuildFrame) (root, tree string) {
	t.Helper()
	root, tree, host := upgradeStoreHost(t)
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
	graphs := cgsqlite.New(db)
	main, dep := jsonDocRootPath+".main", jsonDocDep.Path()+".Name"
	for _, f := range frames {
		putSealedGraph(t, graphs, cgdomain.CallGraphRecord{
			SchemaVersion: cgdomain.CallGraphSchemaVersion, Ecosystem: fetchdomain.EcosystemGo, Coordinate: app,
			Algorithm: cgdomain.AlgorithmCHA, Completeness: cgdomain.CompletenessBuiltWithBodies,
			OverallStatus: cgdomain.CallGraphStatusExtracted, AnalysisSource: cgdomain.AnalysisSourceWorktree,
			WorktreeDigest: "analysed-sha256:t", WorktreeScanDigest: "scanned-sha256:t", AnalysisRoot: tree,
			TestScope: cgdomain.TestScopeAnalysed, ReferenceScope: cgdomain.ReferenceScopeAnalysed,
			Nodes: []cgdomain.CallNode{
				{ID: main, Module: jsonDocRootPath, Package: jsonDocRootPath, Symbol: "main"},
				{ID: dep, Module: jsonDocDep.Path(), Package: jsonDocDep.Path(), Symbol: "Name", IsExternal: true},
			},
			Edges: []cgdomain.CallEdge{{FromID: main, ToID: dep, Confidence: cgdomain.ConfidenceDirect,
				CallSite: cgdomain.SourcePosition{File: "main.go", Line: 10}}},
			NodeCount: 2, EdgeCount: 1, ExtractedAt: jsonDocAt, PipelineVersion: cgapp.PipelineVersion, Frame: f,
		})
	}
	seedProjectWalk(t, ctx, db, app, host, tree, seedWalkSpec{walkID: vulnFrameMissWalk, toolchain: host.toolchain, at: jsonDocAt})

	store := vulnsqlite.New(db)
	snapshot := vulntest.MustNewAt(jsonDocSnapSource, "v2026-03-09", jsonDocAt)
	if perr := store.PutDatabaseSnapshot(ctx, snapshot, strings.NewReader("advisory snapshot")); perr != nil {
		t.Fatal(perr)
	}
	rooting := vuldomain.TargetRootedAt(app)
	vrec := vuldomain.VulnerabilityRecord{
		Ecosystem: fetchdomain.EcosystemGo, Coordinate: jsonDocDep, WalkID: vulnFrameMissWalk,
		OverallStatus: vuldomain.StatusAffected, DatabaseSnapshot: snapshot, ScannedAt: jsonDocAt,
		PipelineVersion: vulnapp.PipelineVersion, Rooting: rooting, Toolchain: gotoolchain.Version(host.toolchain),
		Findings: []vuldomain.VulnerabilityFinding{{
			ID: jsonDocFindingID, Summary: "a routed finding", AffectedRange: "< v1.3.0", FixedIn: "v1.3.0",
			Reachable: &vuldomain.ReachabilityResult{
				IsReachable: true, Confidence: vuldomain.ConfidenceHigh,
				DerivedBy: vuldomain.ReachabilityDerivation{Analyser: vuldomain.AnalyserGovulncheck, Fidelity: "source", Rooting: rooting},
				Routes: []vuldomain.ReachabilityRoute{{
					{ModulePath: jsonDocRootPath, Package: jsonDocRootPath, Symbol: "main"},
					{ModulePath: jsonDocDep.Path(), ModuleVersion: jsonDocDep.Version(), Package: jsonDocDep.Path(), Symbol: "Name"},
				}},
			},
		}},
	}
	graphs.WithReadFrame(hostFrame())
	reachability.NewDispatchAnnotator(reachability.NewCallSiteStoreReader(graphs, cgapp.PipelineVersion).
		WithReadFrame(func() (cgdomain.BuildFrame, string) { return hostFrame(), "" }), nil).AnnotateRecord(ctx, &vrec)
	if vrec, err = (vuldomain.VulnerabilityRecordHasher{}).SetContentHash(vrec); err != nil {
		t.Fatal(err)
	}
	if perr := store.PutVulnerabilityRecord(ctx, vrec); perr != nil {
		t.Fatal(perr)
	}
	run := vuldomain.WalkScanRun{
		ID: vulnFrameMissRun, WalkID: vulnFrameMissWalk, Snapshot: snapshot,
		PerModuleResults: map[coordinate.ModuleCoordinate]string{jsonDocDep: vrec.ContentHash},
		StartedAt:        jsonDocAt, CompletedAt: jsonDocAt.Add(time.Second), OverallStatus: vuldomain.WalkStatusAffected,
		Operator: "frame-miss", PipelineVersion: vulnapp.PipelineVersion,
	}
	if run, err = (vuldomain.WalkScanRunHasher{}).SetContentHash(run); err != nil {
		t.Fatal(err)
	}
	if perr := store.PutWalkScanRun(ctx, run); perr != nil {
		t.Fatal(perr)
	}
	return root, tree
}

// A host scan of a tree whose call graph is held only under another frame:
// reachability and vuln-show name that frame and its flag on the hop and the
// root, and the remedy names the tree. Held under the host, or under no frame,
// the three lines are what they were.
func TestVulnReaders_FrameMiss(t *testing.T) {
	requireGoOnPath(t)
	wasm := cgdomain.BuildFrame{GOOS: "wasip1", GOARCH: "wasm"}
	for _, tc := range []struct {
		name   string
		frames []cgdomain.BuildFrame
		want   func(tree string) []string
		absent []string
	}{
		{"other frame only", []cgdomain.BuildFrame{wasm}, func(tree string) []string {
			return []string{
				"not annotated, the call graph of " + jsonDocRootPath + "@local is held under wasip1/wasm, not under this scan's frame " +
					hostFrame().String() + "; read it with --target wasip1/wasm, or produce this frame's with: kanonarion local " + tree,
				"unrooted — the call graph of " + jsonDocRootPath + "@local is held under wasip1/wasm, not under this read's frame " +
					hostFrame().String() + "; read it with --target wasip1/wasm, so nothing can be said about what enters the route",
				"kanonarion local " + tree,
			}
		}, []string{"no call graph is", cgdomain.UnnamedWorkingTreeLead}},
		{"host record", []cgdomain.BuildFrame{wasm, hostFrame()}, func(string) []string {
			return []string{"direct, edge confidence Direct, at main.go:10, read from the call graph of " + jsonDocRootPath + "@local (BUILT_WITH_BODIES)",
				"root: ingress"}
		}, []string{"held under", "not annotated"}},
		{"no record", nil, func(string) []string {
			return []string{
				"not annotated, no call graph is held for " + jsonDocRootPath + "@local, the module this call site is in, so there is no edge to read; the route stands as the analyser reported it",
				"unrooted — no call graph is stored for " + jsonDocRootPath + "@local, so nothing can be said about what enters the route",
				cgdomain.UnnamedWorkingTreeLead + ", so run kanonarion local from inside it",
			}
		}, []string{"held under"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root, tree := vulnFrameMissStore(t, tc.frames)
			gomod := filepath.Join(tree, "go.mod")
			for _, args := range [][]string{
				{"reachability", jsonDocDepCoord, "--vuln", jsonDocFindingID, "--gomod", gomod},
				{"vuln-show", jsonDocDepCoord, "--gomod", gomod},
			} {
				out, stderr, code := runTinyGoCLI(t, root, args...)
				for _, w := range tc.want(tree) {
					if !strings.Contains(out, w) {
						t.Errorf("%s = exit %d, lacks %q:\n%s%s", args[0], code, w, out, stderr)
					}
				}
				for _, a := range tc.absent {
					if strings.Contains(out, a) {
						t.Errorf("%s says %q:\n%s", args[0], a, out)
					}
				}
			}
		})
	}
}
