package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/eitanity/kanonarion/internal/adapters/sqlitestore"
	cgsqlite "github.com/eitanity/kanonarion/internal/callgraph/adapters/store/sqlite"
	cgapp "github.com/eitanity/kanonarion/internal/callgraph/application"
	cgdomain "github.com/eitanity/kanonarion/internal/callgraph/domain"
	"github.com/eitanity/kanonarion/internal/coordinate"
	fetchdomain "github.com/eitanity/kanonarion/internal/fetch/domain"
	"github.com/eitanity/kanonarion/internal/walk/adapters/buildlist/tinygotest"
	walksqlite "github.com/eitanity/kanonarion/internal/walk/adapters/walks/sqlite"
	walkapp "github.com/eitanity/kanonarion/internal/walk/application"
	walkdomain "github.com/eitanity/kanonarion/internal/walk/domain"
)

// The three commands that extract or show one call graph take the declaration
// with the refusals walk has, each by name and before the store is opened.
func TestCallGraphFrameFlags_RefuseAsWalkDoes(t *testing.T) {
	tree := writeTinyModule(t)
	for _, cmd := range [][]string{
		{"local", tree}, {"callgraph", "example.com/mod@v1.0.0"}, {"callgraph-show", "example.com/mod@v1.0.0"},
		{"capability", "example.com/mod@v1.0.0"},
	} {
		for _, tc := range []struct {
			name string
			path func(t *testing.T) string
			args []string
			want string
		}{
			{"tinygo with --target", nil, []string{"--tinygo", "pico", "--target", "linux/arm"},
				"--tinygo and --target both declare the build target; pass one of them"},
			{"tinygo with --goos", nil, []string{"--tinygo", "pico", "--goos", "linux", "--goarch", "arm"},
				"--tinygo and --goos/--goarch both declare the build target; pass one of them"},
			{"half a pair", nil, []string{"--goos", "linux"},
				"GOOS=linux was declared without a GOARCH; name both halves or neither"},
			{"unknown pair", nil, []string{"--target", "linux/notanarch"},
				"build target linux/notanarch is not one this Go toolchain builds for"},
			{"no tinygo on PATH", pathWithoutTinyGo, []string{"--tinygo", "pico"},
				"a TinyGo build target needs the tinygo command on PATH"},
			{"unknown tinygo target", nil, []string{"--tinygo", "nosuchboard"},
				"tinygo does not know the target \"nosuchboard\""},
		} {
			t.Run(cmd[0]+"/"+tc.name, func(t *testing.T) {
				requireGoOnPath(t)
				installFakeTinyGo(t)
				if tc.path != nil {
					t.Setenv("PATH", tc.path(t))
				}
				root := t.TempDir()
				_, stderr, code := runTinyGoCLI(t, root, append(append([]string{}, cmd...), tc.args...)...)
				if code != ExitConfig {
					t.Errorf("exit %d, want %d (%s)", code, ExitConfig, stderr)
				}
				if !strings.Contains(stderr, tc.want) {
					t.Errorf("refusal %q does not say %q", stderr, tc.want)
				}
				if _, err := os.Stat(filepath.Join(root, "mirror.db")); err == nil {
					t.Error("a refused declaration still opened a store")
				}
			})
		}
	}
}

var framePico = cgdomain.BuildFrame{GOOS: "linux", GOARCH: "arm", GOARM: "6", TinyGoTarget: "pico",
	TinyGoVersion: "0.42.0", TinyGoTags: []string{"baremetal", "cortexm"}}

// callgraph-show names the frame on a line of its own and in --json; the run
// summaries carry it on their result line; history names it per generation. A
// record that states none prints nothing, so existing output does not move.
func TestCallGraphShow_PrintsTheFrame(t *testing.T) {
	r := cgdomain.CallGraphRecord{Coordinate: mustCoord(t, "example.com/mod", "v1.0.0"), Frame: framePico,
		OverallStatus: cgdomain.CallGraphStatusExtracted, Algorithm: cgdomain.AlgorithmCHA}
	var text bytes.Buffer
	if err := printCallGraphRecord(r, 0, 0, &text); err != nil {
		t.Fatalf("printCallGraphRecord: %v", err)
	}
	if want := "\n  frame: tinygo/pico (linux/arm)  tinygo 0.42.0  tags baremetal,cortexm\n"; !strings.Contains(text.String(), want) {
		t.Errorf("text lacks %q:\n%s", want, text.String())
	}
	doc, err := json.Marshal(toCallGraphJSON(r))
	if err != nil {
		t.Fatalf("marshalling: %v", err)
	}
	if want := `"frame":{"text":"tinygo/pico (linux/arm)","goos":"linux","goarch":"arm","goarm":"6","tinygo_target":"pico","tinygo_version":"0.42.0","tinygo_tags":["baremetal","cortexm"]}`; !strings.Contains(string(doc), want) {
		t.Errorf("json lacks %s:\n%s", want, doc)
	}
	var summary bytes.Buffer
	if err = printCallGraphSummary(context.Background(), r, false, false, "", &summary, callGraphRunJSON{}); err != nil {
		t.Fatalf("printCallGraphSummary: %v", err)
	}
	if !strings.HasPrefix(summary.String(), "example.com/mod@v1.0.0: Extracted — 0 nodes, 0 edges [CHA] frame tinygo/pico (linux/arm)\n") {
		t.Errorf("summary = %q", summary.String())
	}
	if got := historyFrame(r); got != "    frame:    tinygo/pico (linux/arm)  tinygo 0.42.0  tags baremetal,cortexm\n" {
		t.Errorf("history frame = %q", got)
	}

	r.Frame = cgdomain.BuildFrame{}
	text.Reset()
	if err = printCallGraphRecord(r, 0, 0, &text); err != nil {
		t.Fatalf("printCallGraphRecord: %v", err)
	}
	if doc, err = json.Marshal(toCallGraphJSON(r)); err != nil {
		t.Fatalf("marshalling: %v", err)
	}
	if strings.Contains(text.String(), "frame") || strings.Contains(string(doc), `"frame"`) || summaryFrame(r) != "" || historyFrame(r) != "" {
		t.Errorf("a record stating no frame printed one:\n%s\n%s", text.String(), doc)
	}
}

// cgFrameStore is a store root holding three working-tree graphs of
// example.com/app at one root — under the host frame, tinygo/wasip1 and
// wasip1/wasm — each calling a helper named for its frame, plus a walk resolved
// for wasip1/wasm.
func cgFrameStore(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	db, err := sqlitestore.Open(filepath.Join(root, "mirror.db"), nil, sqlitestore.IntentCreate)
	if err != nil {
		t.Fatalf("opening the store: %v", err)
	}
	defer func() { _ = db.Close() }()
	if aerr := sqlitestore.Apply(db, allMigrations()); aerr != nil {
		t.Fatalf("migrating the store: %v", aerr)
	}
	app, err := coordinate.NewLocalCoordinate("example.com/app")
	if err != nil {
		t.Fatalf("local coordinate: %v", err)
	}
	at := time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)
	wasip1 := cgdomain.BuildFrame{GOOS: "wasip1", GOARCH: "wasm", TinyGoTarget: "wasip1", TinyGoVersion: "0.42.0"}
	store := cgsqlite.New(db)
	for i, g := range []struct {
		frame  cgdomain.BuildFrame
		callee string
	}{
		{hostFrame(), "example.com/app.HostOnly"}, {wasip1, "example.com/app.WasmOnly"},
		{cgdomain.BuildFrame{GOOS: "wasip1", GOARCH: "wasm"}, "example.com/app.PlainWasm"},
	} {
		r := cgdomain.CallGraphRecord{
			SchemaVersion: cgdomain.CallGraphSchemaVersion, Ecosystem: fetchdomain.EcosystemGo, Coordinate: app,
			Algorithm: cgdomain.AlgorithmCHA, Completeness: cgdomain.CompletenessBuiltWithBodies,
			OverallStatus: cgdomain.CallGraphStatusExtracted, AnalysisSource: cgdomain.AnalysisSourceWorktree,
			WorktreeDigest: "analysed-sha256:t", WorktreeScanDigest: "scanned-sha256:t", AnalysisRoot: "/src/app",
			TestScope: cgdomain.TestScopeAnalysed, ReferenceScope: cgdomain.ReferenceScopeAnalysed,
			Nodes: []cgdomain.CallNode{
				{ID: "example.com/app.main", Module: "example.com/app", Package: "example.com/app", Symbol: "main"},
				{ID: g.callee, Module: "example.com/app", Package: "example.com/app", Symbol: g.callee[len("example.com/app."):]},
			},
			Edges: []cgdomain.CallEdge{{FromID: "example.com/app.main", ToID: g.callee, Confidence: cgdomain.ConfidenceDirect,
				CallSite: cgdomain.SourcePosition{File: "main.go", Line: 3}}},
			NodeCount: 2, EdgeCount: 1, ExtractedAt: at.Add(time.Duration(i) * time.Hour),
			PipelineVersion: cgapp.PipelineVersion, Frame: g.frame,
		}
		sealed, serr := cgdomain.CallGraphRecordHasher{}.SetContentHash(r)
		if serr != nil {
			t.Fatalf("SetContentHash: %v", serr)
		}
		if perr := store.PutCallGraphRecord(context.Background(), sealed); perr != nil {
			t.Fatalf("PutCallGraphRecord: %v", perr)
		}
	}

	dep := mustCoord(t, "example.com/dep", "v1.0.0")
	nodes := []walkdomain.GraphNode{
		{Coordinate: app, ResolutionSource: walkdomain.ResolutionLocalMainModule},
		{Coordinate: dep, DirectDependency: true, ResolutionSource: walkdomain.ResolutionMVS},
	}
	graph := walkdomain.Graph{Target: app, Nodes: nodes, Edges: []walkdomain.GraphEdge{{From: app, To: dep, ConstraintVersion: "v1.0.0"}},
		ResolvedAt: at, PipelineVersion: walkapp.PipelineVersion,
		BuildEnv: walkdomain.BuildEnv{GOOS: "wasip1", GOARCH: "wasm", GoVersion: "go1.27.2"}}
	graph.Sort()
	results := map[coordinate.ModuleCoordinate]walkdomain.NodeResult{
		app: {Coordinate: app, Status: walkdomain.NodeSucceeded}, dep: {Coordinate: dep, Status: walkdomain.NodeSucceeded},
	}
	outcome := walkdomain.WalkOutcome{Target: app, Graph: graph, PerNodeResults: results,
		StartedAt: at, CompletedAt: at.Add(time.Second), OverallStatus: walkdomain.WalkSucceeded}
	rec := walkdomain.NewWalkRecord(frameWalkID, "frame", walkapp.PipelineVersion,
		walkdomain.WalkScopeCode, walkdomain.WalkDepthFull, outcome, walkdomain.DefaultDepthPolicy(), "")
	rec, err = walkdomain.WalkRecordHasher{}.SetContentHash(rec)
	if err != nil {
		t.Fatalf("sealing the walk: %v", err)
	}
	if perr := walksqlite.New(db).PutWalk(context.Background(), rec); perr != nil {
		t.Fatalf("seeding the walk: %v", perr)
	}
	return root
}

const frameWalkID = "01JS0NFRAME0000000000000WA1"

// installWasip1TinyGo puts a fake tinygo knowing wasip1 first on PATH.
func installWasip1TinyGo(t *testing.T) {
	t.Helper()
	fake := tinygotest.Install(t, map[string]tinygotest.Target{
		"wasip1": {GOOS: "wasip1", GOARCH: "wasm", Triple: "wasm32-unknown-wasi", Tags: []string{"tinygo.wasm", "tinygo"}, GOROOT: hostGOROOT(t)},
	})
	t.Setenv("PATH", fake.Dir+string(os.PathListSeparator)+os.Getenv("PATH"))
}

// callers takes the declaration with no flag of its own: the container's read
// frame is set from it, so one worktree's two frames each answer their own read.
func TestCallers_AnswerFromTheDeclaredFramesRecord(t *testing.T) {
	requireGoOnPath(t)
	installWasip1TinyGo(t)
	root := cgFrameStore(t)

	out, stderr, code := runTinyGoCLI(t, root, "callers", "example.com/app.WasmOnly", "--tinygo", "wasip1")
	if code != 0 || !strings.Contains(out, "example.com/app.main") {
		t.Errorf("callers --tinygo wasip1 = exit %d\n%s%s", code, out, stderr)
	}
	if out, stderr, code = runTinyGoCLI(t, root, "callers", "example.com/app.HostOnly", "--tinygo", "wasip1"); code == 0 {
		t.Errorf("the host record answered a wasip1 read:\n%s%s", out, stderr)
	}
	out, stderr, code = runTinyGoCLI(t, root, "callers", "example.com/app.HostOnly")
	if code != 0 || !strings.Contains(out, "example.com/app.main") {
		t.Errorf("callers with no flag = exit %d\n%s%s", code, out, stderr)
	}
	if out, stderr, code = runTinyGoCLI(t, root, "callers", "example.com/app.WasmOnly"); code == 0 {
		t.Errorf("the wasip1 record answered a host read:\n%s%s", out, stderr)
	}
}

// callgraph-show selects by frame too, and a frame the ledger does not hold is
// refused naming the frames it does and the command that produces this one.
func TestCallGraphShow_SelectsByFrame(t *testing.T) {
	requireGoOnPath(t)
	installWasip1TinyGo(t)
	root := cgFrameStore(t)
	out, stderr, code := runTinyGoCLI(t, root, "callgraph-show", "example.com/app@local", "--tinygo", "wasip1")
	if code != 0 || !strings.Contains(out, "frame: tinygo/wasip1 (wasip1/wasm)") || !strings.Contains(out, "WasmOnly") {
		t.Errorf("callgraph-show --tinygo wasip1 = exit %d\n%s%s", code, out, stderr)
	}
	_, stderr, code = runTinyGoCLI(t, root, "callgraph-show", "example.com/app@local", "--target", "linux/arm64")
	if code != ExitNotFound {
		t.Errorf("an unheld frame exited %d, want %d", code, ExitNotFound)
	}
	for _, want := range []string{
		"no callgraph record for example.com/app@local extracted under linux/arm64",
		"tinygo/wasip1 (wasip1/wasm)", "--tinygo wasip1",
		"kanonarion local /src/app --target linux/arm64",
	} {
		if !strings.Contains(stderr, want) {
			t.Errorf("the refusal does not say %q:\n%s", want, stderr)
		}
	}
}

// A walk's frame is the extraction frame: a declaration that disagrees with it
// is refused naming both, before anything is analysed.
func TestCallGraphFromWalk_DisagreeingDeclarationIsRefused(t *testing.T) {
	requireGoOnPath(t)
	root := cgFrameStore(t)
	_, stderr, code := runTinyGoCLI(t, root, "callgraph", "example.com/dep@v1.0.0", "--from-walk", frameWalkID, "--target", "linux/amd64")
	if code != ExitConfig {
		t.Errorf("exit %d, want %d:\n%s", code, ExitConfig, stderr)
	}
	for _, want := range []string{
		"walk " + frameWalkID + " was resolved for wasip1/wasm, and this invocation declares linux/amd64",
		"kanonarion callgraph example.com/dep@v1.0.0 --from-walk " + frameWalkID + " --target wasip1/wasm",
	} {
		if !strings.Contains(stderr, want) {
			t.Errorf("the refusal does not say %q:\n%s", want, stderr)
		}
	}
}

// The discovery search passes over a consumer walk of another frame, and the
// notice counts it.
func TestFramePassedOverClause(t *testing.T) {
	if got := framePassedOverClause(0, hostFrame()); got != "" {
		t.Errorf("nothing passed over still says %q", got)
	}
	if got := framePassedOverClause(2, hostFrame()); !strings.Contains(got, "2 walk(s) resolved for a frame other than "+hostFrame().String()) {
		t.Errorf("clause = %q", got)
	}
	env := walkdomain.BuildEnv{GOOS: "linux", GOARCH: "arm"}
	if !walkFrameMatches(env, cgdomain.BuildFrame{GOOS: "linux", GOARCH: "arm", GOARM: "7"}) {
		t.Error("a standard walk records no GOARM and was refused for stating none")
	}
	env.GOARM, env.TinyGoTarget = "6", "pico"
	if walkFrameMatches(env, cgdomain.BuildFrame{GOOS: "linux", GOARCH: "arm", GOARM: "7"}) {
		t.Error("a pico walk matched a plain linux/arm frame")
	}
}

// Real toolchain: one working tree analysed under four frames holds four
// records, each read selects its own, and an unchanged tree reuses per frame.
// Skipped by name when tinygo is absent.
func TestLocal_RealToolchainRecordsOneGraphPerFrame(t *testing.T) {
	requireGoOnPath(t)
	if _, err := exec.LookPath("tinygo"); err != nil {
		t.Skip("tinygo is not on PATH; this test measures what it defines")
	}
	tree := writeTinyModule(t)
	root := t.TempDir()
	frames := []struct {
		flags []string
		frame string
	}{
		{nil, hostFrame().String()},
		{[]string{"--target", "wasip1/wasm"}, "wasip1/wasm"},
		{[]string{"--tinygo", "wasip1"}, "tinygo/wasip1 (wasip1/wasm)"},
		{[]string{"--tinygo", "pico"}, "tinygo/pico (linux/arm)"},
	}
	for _, f := range frames {
		out, stderr, _ := runTinyGoCLI(t, root, append([]string{"local", tree}, f.flags...)...)
		if !strings.Contains(out, " frame "+f.frame) || !strings.Contains(stderr, "derived by this run") {
			t.Errorf("local %v:\n%s%s", f.flags, out, stderr)
		}
	}
	for _, f := range frames {
		out, stderr, _ := runTinyGoCLI(t, root, append([]string{"local", tree}, f.flags...)...)
		if !strings.Contains(out, " frame "+f.frame+" (cached)") || !strings.Contains(stderr, "that record was reused") {
			t.Errorf("an unchanged tree under %v was not served its own record:\n%s%s", f.flags, out, stderr)
		}
		show, serr, code := runTinyGoCLI(t, root, append([]string{"callgraph-show", "example.com/tiny@local"}, f.flags...)...)
		if code != 0 || !strings.Contains(show, "\n  frame: "+f.frame) {
			t.Errorf("callgraph-show %v = exit %d:\n%s%s", f.flags, code, show, serr)
		}
	}
}

// The frame refusal's remedy lines, frames included, are accepted by the CLI's
// own parser.
func TestFrameConflictRemedy_EveryLineParses(t *testing.T) {
	c := cgdomain.CallGraphConflict{
		Coordinate: mustCoord(t, "example.com/mod", "v1.0.0"), Field: cgdomain.ConflictFieldFrame,
		Frames: []cgdomain.BuildFrame{hostFrame(), {GOOS: "wasip1", GOARCH: "wasm"}, framePico},
	}
	lines := c.Remedy().Lines
	if len(lines) != 4 {
		t.Fatalf("remedy lines = %q, want --history and one per frame", lines)
	}
	for _, line := range lines {
		if err := parseInvocation(t, line); err != nil {
			t.Errorf("remedy line %q is rejected by the CLI's own parser: %v", line, err)
		}
	}
}

// A walk named by --walk-id fixes the read frame: its own frame answers, and a
// declaration beside it is refused by name on every call-graph read that takes
// --walk-id.
func TestWalkID_SuppliesTheReadFrame(t *testing.T) {
	requireGoOnPath(t)
	root := cgFrameStore(t)
	out, stderr, code := runTinyGoCLI(t, root, "callers", "example.com/app.PlainWasm", "--walk-id", frameWalkID)
	if code != 0 || !strings.Contains(out, "example.com/app.main") || !strings.Contains(out, "frame wasip1/wasm") {
		t.Errorf("callers --walk-id of a wasip1/wasm walk = exit %d\n%s%s", code, out, stderr)
	}
	if out, stderr, code = runTinyGoCLI(t, root, "callers", "example.com/app.HostOnly", "--walk-id", frameWalkID); code == 0 {
		t.Errorf("the host record answered under a wasip1/wasm walk:\n%s%s", out, stderr)
	}
	if out, stderr, code = runTinyGoCLI(t, root, "callers", "example.com/app.HostOnly"); code != 0 {
		t.Errorf("with no --walk-id the host frame did not answer: exit %d\n%s%s", code, out, stderr)
	}
	for _, cmd := range [][]string{
		{"callers", "example.com/app.HostOnly"}, {"callees", "example.com/app.main"},
		{"implementers", "example.com/app.Store"}, {"usage", "example.com/dep@v1.0.0"},
		{"capability", "example.com/app@local"},
	} {
		args := append(append([]string{}, cmd...), "--walk-id", frameWalkID, "--target", "linux/amd64")
		_, stderr, code := runTinyGoCLI(t, root, args...)
		if code != ExitConfig || !strings.Contains(stderr, cmd[0]+" does not act on --target/--goos/--goarch") {
			t.Errorf("%v = exit %d, want the refusal by name:\n%s", args, code, stderr)
		}
	}
}

// capability reads the declared frame's record, says which on its frame line
// and in --json, and refuses a walk id the store does not hold.
func TestCapability_ReadsTheDeclaredFrame(t *testing.T) {
	requireGoOnPath(t)
	installWasip1TinyGo(t)
	root := cgFrameStore(t)
	out, stderr, code := runTinyGoCLI(t, root, "capability", "example.com/app@local", "--tinygo", "wasip1")
	if code != 0 || !strings.HasPrefix(out, "example.com/app@local capabilities:\n  frame: tinygo/wasip1 (wasip1/wasm)  tinygo 0.42.0\n") {
		t.Errorf("capability --tinygo wasip1 = exit %d\n%s%s", code, out, stderr)
	}
	out, stderr, code = runTinyGoCLI(t, root, "capability", "example.com/app@local", "--walk-id", frameWalkID, "--json")
	if code != 0 || !strings.Contains(out, `"frame": {
    "text": "wasip1/wasm",`) {
		t.Errorf("capability --walk-id --json = exit %d\n%s%s", code, out, stderr)
	}
	_, stderr, code = runTinyGoCLI(t, root, "capability", "example.com/app@local", "--walk-id", "01JS0NNOSUCHWALK0000000000")
	if code != ExitNotFound || !strings.Contains(stderr, `no walk record matched walk id "01JS0NNOSUCHWALK0000000000"`) {
		t.Errorf("a missing walk = exit %d:\n%s", code, stderr)
	}
}
