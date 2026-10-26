package cli

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"code.eitanity.com/kanonarion/internal/adapters/goenv"
	"code.eitanity.com/kanonarion/internal/adapters/sqlitestore"
	cgsqlite "code.eitanity.com/kanonarion/internal/callgraph/adapters/store/sqlite"
	"code.eitanity.com/kanonarion/internal/coordinate"
	fetchdomain "code.eitanity.com/kanonarion/internal/fetch/domain"
	localdomain "code.eitanity.com/kanonarion/internal/local/domain"
	vulnsqlite "code.eitanity.com/kanonarion/internal/vuln/adapters/store/sqlite"
	vulnapp "code.eitanity.com/kanonarion/internal/vuln/application"
	vuldomain "code.eitanity.com/kanonarion/internal/vuln/domain"
	"code.eitanity.com/kanonarion/internal/vuln/vulntest"
	"code.eitanity.com/kanonarion/internal/walk/adapters/buildlist/tinygotest"
	walksqlite "code.eitanity.com/kanonarion/internal/walk/adapters/walks/sqlite"
	walkapp "code.eitanity.com/kanonarion/internal/walk/application"
	walkdomain "code.eitanity.com/kanonarion/internal/walk/domain"
)

// A wasm frame of either kind is refused by name before any probe child runs: the probe reads a symbol table, and no host
// binary is built in its place.
func TestReachabilityLocal_RefusesWasmFramesByName(t *testing.T) {
	requireGoOnPath(t)
	wasip2 := tinygotest.Target{GOOS: "linux", GOARCH: "arm", Triple: "wasm32-unknown-wasip2", Tags: []string{"tinygo.wasm", "wasip2", "tinygo"}, GOROOT: hostGOROOT(t)}
	fake := tinygotest.Install(t, map[string]tinygotest.Target{
		"wasip1": {GOOS: "wasip1", GOARCH: "wasm", Triple: "wasm32-unknown-wasi", Tags: []string{"tinygo.wasm", "tinygo"}, GOROOT: hostGOROOT(t)},
		"wasip2": wasip2,
	})
	t.Setenv("PATH", fake.Dir+string(os.PathListSeparator)+os.Getenv("PATH"))
	tree := writeTinyModule(t)
	store := walkFrameVulnStore(t)
	for _, tc := range []struct {
		flags []string
		named string
	}{
		{[]string{"--target", "wasip1/wasm"}, "--target wasip1/wasm"},
		{[]string{"--goos", "js", "--goarch", "wasm"}, "--target js/wasm"},
		{[]string{"--tinygo", "wasip1"}, "--tinygo wasip1"},
		{[]string{"--tinygo", "wasip2"}, "--tinygo wasip2"},
	} {
		_, stderr, code := runTinyGoCLI(t, store, append([]string{"reachability", "--local", tree}, tc.flags...)...)
		want := "reachability --local does not act on " + tc.named + " (applies to a frame whose build output carries a symbol table"
		if code != ExitConfig || !strings.Contains(stderr, want) || !strings.Contains(stderr, "no reader for a wasm module") {
			t.Errorf("%v = exit %d, want the refusal naming %s:\n%s", tc.flags, code, tc.named, stderr)
		}
	}
}

// The answer names the frame it probed in, after the module line, and --json
// carries it in callgraph-show's shape.
func TestReachabilityLocal_PrintsTheFrame(t *testing.T) {
	fixtureRoot, treeDir := twoWalkStore(t, true, false)
	stdout, stderr, err := runAside("reachability", "--local", treeDir, "--store-root", fixtureRoot)
	if err != nil {
		t.Fatalf("exit %d: %v\n%s", ExitCodeForError(err), err, stderr)
	}
	if !strings.Contains(stdout, "  module:    "+jsonDocRootPath+"\n  frame:     "+hostFrame().String()+"\n") {
		t.Errorf("the frame line does not follow the module line:\n%s", stdout)
	}
	stdout, _, err = runAside("reachability", "--local", treeDir, "--store-root", fixtureRoot, "--json")
	if err != nil {
		t.Fatalf("--json: %v", err)
	}
	var doc struct {
		Frame *frameJSON `json:"frame"`
	}
	if jerr := json.Unmarshal([]byte(stdout), &doc); jerr != nil {
		t.Fatalf("decoding: %v\n%s", jerr, stdout)
	}
	if want := toFrameJSON(hostFrame()); doc.Frame == nil || doc.Frame.Text != want.Text || doc.Frame.GOOS != want.GOOS || doc.Frame.GOARCH != want.GOARCH {
		t.Errorf("frame = %+v, want %+v", doc.Frame, want)
	}
}

// The probe's builder is stated on the probe line and per binary.
func TestPrintLocalReachability_NamesTheBuilder(t *testing.T) {
	var b strings.Builder
	out := reachabilityResultToOutput(localdomain.LocalReachabilityResult{
		ModulePath: "example.com/fw", ProbeKind: localdomain.ProbeKindBinary, ProbeBuilder: localdomain.ProbeBuilderTinyGo,
		Frame:    framePico,
		Coverage: localdomain.ProbeCoverage{Binaries: []localdomain.ProbedBinary{{ImportPath: "example.com/fw", Builder: localdomain.ProbeBuilderTinyGo}}},
	})
	if err := printLocalReachability(&b, out); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"  frame:     " + framePico.String() + "\n", "  probe:     binary, built by tinygo build\n"} {
		if !strings.Contains(b.String(), want) {
			t.Errorf("the answer does not say %q:\n%s", want, b.String())
		}
	}
	raw, err := json.Marshal(out)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{`"probe_builder":"tinygo build"`, `"builder":"tinygo build"`, `"tinygo_target":"pico"`} {
		if !strings.Contains(string(raw), want) {
			t.Errorf("--json does not carry %s:\n%s", want, raw)
		}
	}
}

// The seed follows the declaration: a store holding a host walk and a wasip1
// walk of one tree seeds a wasip1 probe from the wasip1 walk, and the module
// only the host walk scanned is uncovered for the probe, not served from the
// host walk. wasip1 is refused before the probe runs, so the use case is
// driven below the refusal; the fixture's finding names no symbol, so no build
// is attempted.
func TestLocalReachability_SeedsFromTheWalkOfItsFrame(t *testing.T) {
	fixtureRoot, treeDir, host := upgradeStoreHost(t)
	wasm := host
	wasm.platform.GOOS, wasm.platform.GOARCH = "wasip1", "wasm"
	seedWalkStore(t, fixtureRoot, treeDir, host, []seedWalkSpec{
		{walkID: seedOldWalkID, runID: seedOldRunID, toolchain: host.toolchain, at: jsonDocAt,
			snapshotV: "v2026-03-01", status: vuldomain.StatusAffected, findingID: jsonDocFindingID},
	}, false)
	seedEmptyScannedWalk(t, fixtureRoot, treeDir, wasm, seedNewWalkID, seedNewRunID, jsonDocAt.Add(time.Hour))

	declareForTest(t, "wasip1/wasm")
	out, err := runLocalReachabilityWithRoot(t, fixtureRoot, treeDir)
	if err != nil {
		t.Fatalf("runLocalReachabilityInner: %v", err)
	}
	if !strings.Contains(out.SeedRestriction, `walk "`+seedNewWalkID+`"`) {
		t.Errorf("the seed is not the wasip1 walk: %q", out.SeedRestriction)
	}
	if out.Frame == nil || out.Frame.Text != "wasip1/wasm" {
		t.Errorf("frame = %+v, want wasip1/wasm", out.Frame)
	}
	if len(out.Modules) != 0 || len(out.Coverage.UncoveredModules) != 1 {
		t.Fatalf("the host walk's finding reached a wasip1 probe: %+v", out)
	}
	if got := out.Coverage.UncoveredModules[0].Reason; got != localdomain.UncoveredNotInSeedWalk {
		t.Errorf("uncovered reason = %q", got)
	}

	// The control: the host frame seeds from the host walk and serves its finding.
	declareForTest(t, "")
	out, err = runLocalReachabilityWithRoot(t, fixtureRoot, treeDir)
	if err != nil {
		t.Fatalf("host: %v", err)
	}
	if !strings.Contains(out.SeedRestriction, `walk "`+seedOldWalkID+`"`) || len(out.Modules) != 1 {
		t.Errorf("the host probe did not seed from the host walk: %+v", out)
	}
}

// declareForTest sets the invocation's declared target, empty for the host,
// until the test ends.
func declareForTest(t *testing.T, pair string) {
	t.Helper()
	prevT, prevG := declaredTarget, declaredTinyGo
	t.Cleanup(func() { declaredTarget, declaredTinyGo = prevT, prevG })
	declaredTarget, declaredTinyGo = goenv.Target{}, goenv.TinyGo{}
	if pair != "" {
		tgt, err := goenv.ParseTarget(pair)
		if err != nil {
			t.Fatal(err)
		}
		declaredTarget = tgt
	}
}

// runLocalReachabilityWithRoot runs the probe's use case against storeRoot.
func runLocalReachabilityWithRoot(t *testing.T, root, tree string) (reachabilityOutput, error) {
	t.Helper()
	prev := storeRoot
	storeRoot = root
	defer func() { storeRoot = prev }()
	var stderr strings.Builder
	return runLocalReachabilityInner(context.Background(), tree, &stderr)
}

// seedEmptyScannedWalk writes a project walk of treeDir in env's frame whose
// completed scan run holds no record.
func seedEmptyScannedWalk(t *testing.T, root, treeDir string, env walkBuildEnv, walkID, runID string, at time.Time) {
	t.Helper()
	ctx := context.Background()
	db, err := sqlitestore.Open(filepath.Join(root, "mirror.db"), nil, sqlitestore.IntentCreate)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()
	rootCoord, err := coordinate.NewLocalCoordinate(jsonDocRootPath)
	if err != nil {
		t.Fatal(err)
	}
	seedProjectWalk(t, ctx, db, rootCoord, env, treeDir, seedWalkSpec{walkID: walkID, toolchain: env.toolchain, at: at})
	snapshot := vulntest.MustNewAt(jsonDocSnapSource, "v2026-03-05", at)
	store := vulnsqlite.New(db)
	if perr := store.PutDatabaseSnapshot(ctx, snapshot, strings.NewReader("advisory snapshot wasm")); perr != nil {
		t.Fatal(perr)
	}
	run := vuldomain.WalkScanRun{
		ID: runID, WalkID: walkID, Snapshot: snapshot, PerModuleResults: map[coordinate.ModuleCoordinate]string{},
		StartedAt: at, CompletedAt: at.Add(time.Second), OverallStatus: vuldomain.WalkStatusAllClean,
		Operator: "guard", PipelineVersion: vulnapp.PipelineVersion,
	}
	if run, err = (vuldomain.WalkScanRunHasher{}).SetContentHash(run); err != nil {
		t.Fatal(err)
	}
	if perr := store.PutWalkScanRun(ctx, run); perr != nil {
		t.Fatal(perr)
	}
}

const walkFrameReadWalkID = "01JS0NFRAME0000000000000WV1"

// walkFrameVulnStore is a store root holding a host and a wasip1 graph of
// inheritCoord, a walk of it resolved for wasip1/wasm, and that walk's record
// of example.com/dep with a route rooted at a function only the wasip1 graph
// holds. Which graph a read classified the root in shows in the node it names.
func walkFrameVulnStore(t *testing.T) string {
	t.Helper()
	ctx := context.Background()
	root := t.TempDir()
	db, err := sqlitestore.Open(filepath.Join(root, "mirror.db"), nil, sqlitestore.IntentCreate)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()
	if aerr := sqlitestore.Apply(db, allMigrations()); aerr != nil {
		t.Fatal(aerr)
	}
	at := time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)
	graphs := cgsqlite.New(db)
	for _, r := range []struct {
		frame  string
		symbol string
	}{{"host", "Host"}, {"wasm", "Wasm"}} {
		f := hostFrame()
		if r.frame == "wasm" {
			f = inheritWasm
		}
		if perr := graphs.PutCallGraphRecord(ctx, inheritRecord(t, f, r.symbol, at)); perr != nil {
			t.Fatal(perr)
		}
	}

	nodes := []walkdomain.GraphNode{
		{Coordinate: inheritCoord, ResolutionSource: walkdomain.ResolutionMVS},
		{Coordinate: jsonDocDep, DirectDependency: true, ResolutionSource: walkdomain.ResolutionMVS},
	}
	graph := walkdomain.Graph{Target: inheritCoord, Nodes: nodes,
		Edges:      []walkdomain.GraphEdge{{From: inheritCoord, To: jsonDocDep, ConstraintVersion: jsonDocDep.Version()}},
		ResolvedAt: at, PipelineVersion: walkapp.PipelineVersion,
		BuildEnv: walkdomain.BuildEnv{GOOS: "wasip1", GOARCH: "wasm", GoVersion: "go1.27.2"}}
	graph.Sort()
	outcome := walkdomain.WalkOutcome{Target: inheritCoord, Graph: graph,
		PerNodeResults: map[coordinate.ModuleCoordinate]walkdomain.NodeResult{
			inheritCoord: {Coordinate: inheritCoord, Status: walkdomain.NodeSucceeded},
			jsonDocDep:   {Coordinate: jsonDocDep, Status: walkdomain.NodeSucceeded},
		},
		StartedAt: at, CompletedAt: at.Add(time.Second), OverallStatus: walkdomain.WalkSucceeded}
	rec := walkdomain.NewWalkRecord(walkFrameReadWalkID, "frame", walkapp.PipelineVersion,
		walkdomain.WalkScopeCode, walkdomain.WalkDepthFull, outcome, walkdomain.DefaultDepthPolicy(), "")
	if rec, err = (walkdomain.WalkRecordHasher{}).SetContentHash(rec); err != nil {
		t.Fatal(err)
	}
	if perr := walksqlite.New(db).PutWalk(ctx, rec); perr != nil {
		t.Fatal(perr)
	}

	store := vulnsqlite.New(db)
	snapshot := vulntest.MustNewAt(jsonDocSnapSource, "v2026-10-01", at)
	if perr := store.PutDatabaseSnapshot(ctx, snapshot, strings.NewReader("advisory snapshot frame")); perr != nil {
		t.Fatal(perr)
	}
	rooting := vuldomain.TargetRootedAt(inheritCoord)
	vrec := vuldomain.VulnerabilityRecord{
		Ecosystem: fetchdomain.EcosystemGo, Coordinate: jsonDocDep, WalkID: walkFrameReadWalkID,
		OverallStatus: vuldomain.StatusAffected, DatabaseSnapshot: snapshot, ScannedAt: at,
		PipelineVersion: vulnapp.PipelineVersion, Rooting: rooting, Toolchain: "go1.27.2",
		Findings: []vuldomain.VulnerabilityFinding{{
			ID: jsonDocFindingID, Summary: "a routed finding", AffectedRange: "< v1.3.0", FixedIn: "v1.3.0",
			AffectedSymbols: []string{"Parse"},
			Reachable: &vuldomain.ReachabilityResult{
				IsReachable: true, Confidence: vuldomain.ConfidenceHigh,
				DerivedBy: vuldomain.ReachabilityDerivation{Analyser: vuldomain.AnalyserGovulncheck, Fidelity: "source", Rooting: rooting},
				Routes: []vuldomain.ReachabilityRoute{{
					{ModulePath: "example.com/app", ModuleVersion: "v1.0.0", Package: "example.com/app/handlers", Symbol: "Wasm"},
					{ModulePath: "example.com/dep", ModuleVersion: "v1.2.0", Package: "example.com/dep", Symbol: "Parse"},
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
		ID: "01JS0NFRAME0000000000000RV1", WalkID: walkFrameReadWalkID, Snapshot: snapshot,
		PerModuleResults: map[coordinate.ModuleCoordinate]string{jsonDocDep: vrec.ContentHash},
		StartedAt:        at, CompletedAt: at.Add(time.Second), OverallStatus: vuldomain.WalkStatusAffected,
		Operator: "frame", PipelineVersion: vulnapp.PipelineVersion,
	}
	if run, err = (vuldomain.WalkScanRunHasher{}).SetContentHash(run); err != nil {
		t.Fatal(err)
	}
	if perr := store.PutWalkScanRun(ctx, run); perr != nil {
		t.Fatal(perr)
	}
	return root
}

// wasmRootNode is the route root as only the wasip1 graph resolves it.
const wasmRootNode = "example.com/app/handlers.Wasm"

// Each vuln reader that takes --walk-id classifies the route root in that
// walk's frame: the wasip1 graph resolves the root to its node, the host graph
// cannot.
func TestWalkID_SuppliesTheFrameToTheVulnReaders(t *testing.T) {
	requireGoOnPath(t)
	root := walkFrameVulnStore(t)
	for _, tc := range []struct {
		name string
		args []string
		want string
	}{
		{"vuln-show", []string{"vuln-show", jsonDocDepCoord, "--walk-id", walkFrameReadWalkID}, "node:   " + wasmRootNode},
		{"reachability --vuln", []string{"reachability", jsonDocDepCoord, "--vuln", jsonDocFindingID, "--walk-id", walkFrameReadWalkID}, "node: " + wasmRootNode},
		{"vuln-by-id", []string{"vuln-by-id", jsonDocFindingID, "--walk-id", walkFrameReadWalkID, "--json"}, `"node_id": "` + wasmRootNode + `"`},
		{"context", []string{"context", "--walk-id", walkFrameReadWalkID, "--json", "--entry-points-full"}, `"` + wasmRootNode + `"`},
	} {
		out, stderr, code := runTinyGoCLI(t, root, tc.args...)
		if code != 0 || !strings.Contains(out, tc.want) {
			t.Errorf("%s = exit %d, want %q in the answer:\n%s%s", tc.name, code, tc.want, out, stderr)
		}
	}
	// The control: with no walk named the read frame is the host's, whose graph
	// does not hold the root.
	out, stderr, code := runTinyGoCLI(t, root, "vuln-show", jsonDocDepCoord)
	if code != 0 || strings.Contains(out, "node:   "+wasmRootNode) {
		t.Errorf("an unanchored read classified the root in the wasip1 graph: exit %d\n%s%s", code, out, stderr)
	}
	// A declaration beside --walk-id stays refused.
	for _, args := range [][]string{
		{"vuln-show", jsonDocDepCoord, "--walk-id", walkFrameReadWalkID, "--target", "linux/amd64"},
		{"reachability", jsonDocDepCoord, "--vuln", jsonDocFindingID, "--walk-id", walkFrameReadWalkID, "--target", "linux/amd64"},
		{"context", "--walk-id", walkFrameReadWalkID, "--target", "linux/amd64"},
	} {
		if _, stderr, code := runTinyGoCLI(t, root, args...); code != ExitConfig || !strings.Contains(stderr, "does not act on --target/--goos/--goarch") {
			t.Errorf("%v = exit %d, want the refusal by name:\n%s", args, code, stderr)
		}
	}
}

// Real toolchain: a pico program calling an affected symbol of GO-2022-1059
// reads present from tinygo's own ELF; the host build is read as before; both
// wasm frames are refused. Skipped by name without tinygo or the network.
func TestReachabilityLocal_RealTinyGoPicoReadsItsOwnArtefact(t *testing.T) {
	cache := requireRealTinyGoScan(t)
	dir := t.TempDir()
	for name, content := range map[string]string{
		"go.mod": "module example.com/fx\n\ngo 1.24\n\nrequire golang.org/x/text v0.3.7\n",
		"go.sum": "golang.org/x/text v0.3.7 h1:olpwvP2KacW1ZWvsR7uQhoyTYvKAupfQrRGBFM352Gk=\ngolang.org/x/text v0.3.7/go.mod h1:u+2+/6zg+i71rQMx5EYifcz6MCKuco9NR6JIITiCfzQ=\n",
		"main.go": "package main\n\nimport (\n\t\"fmt\"\n\n\t\"golang.org/x/text/language\"\n)\n\n" +
			"func main() {\n\ttags, _, err := language.ParseAcceptLanguage(\"en-US,fr;q=0.8\")\n\tfmt.Println(tags, err)\n}\n",
	} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	gomod := filepath.Join(dir, "go.mod")
	root := t.TempDir()
	for _, tc := range []struct {
		flags          []string
		frame, builder string
	}{
		{[]string{"--tinygo", "pico"}, "tinygo/pico (linux/arm)", "tinygo build"},
		{nil, hostFrame().String(), "go build"},
	} {
		for _, cmd := range [][]string{{"walk", "--gomod", gomod, "--from-modcache=" + cache}, {"vuln-scan", "--gomod", gomod}} {
			if _, stderr, code := runTinyGoCLI(t, root, append(append(cmd, tc.flags...), "--no-progress")...); code != ExitOK {
				t.Fatalf("%v %v exited %d: %s", cmd, tc.flags, code, stderr)
			}
		}
		out, stderr, code := runTinyGoCLI(t, root, append([]string{"reachability", "--local", dir}, tc.flags...)...)
		for _, want := range []string{
			"  frame:     " + tc.frame + "\n", "  probe:     binary, built by " + tc.builder + "\n",
			"GO-2022-1059 (CVE-2022-32149, GHSA-69ch-w2m2-3vjp) [present, by: symbol-table]",
			"symbols:   golang.org/x/text/language.ParseAcceptLanguage\n",
		} {
			if code != ExitOK || !strings.Contains(out, want) {
				t.Errorf("reachability --local %v = exit %d, want %q:\n%s%s", tc.flags, code, want, out, stderr)
			}
		}
	}
	for _, flags := range [][]string{{"--target", "wasip1/wasm"}, {"--tinygo", "wasip1"}} {
		if _, stderr, code := runTinyGoCLI(t, root, append([]string{"reachability", "--local", dir}, flags...)...); code != ExitConfig ||
			!strings.Contains(stderr, "does not act on "+strings.Join(flags, " ")) {
			t.Errorf("%v = exit %d, want the refusal by name:\n%s", flags, code, stderr)
		}
	}
}
