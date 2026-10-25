package cli

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/eitanity/kanonarion/internal/adapters/sqlitestore"
	cgsqlite "github.com/eitanity/kanonarion/internal/callgraph/adapters/store/sqlite"
	cgapp "github.com/eitanity/kanonarion/internal/callgraph/application"
	cgdomain "github.com/eitanity/kanonarion/internal/callgraph/domain"
	cgports "github.com/eitanity/kanonarion/internal/callgraph/ports"
	"github.com/eitanity/kanonarion/internal/cli/testfakes"
	"github.com/eitanity/kanonarion/internal/coordinate"
	fetchdomain "github.com/eitanity/kanonarion/internal/fetch/domain"
	walksqlite "github.com/eitanity/kanonarion/internal/walk/adapters/walks/sqlite"
	walkapp "github.com/eitanity/kanonarion/internal/walk/application"
	walkdomain "github.com/eitanity/kanonarion/internal/walk/domain"
)

// frameMissRegenerateEnv names a directory: the permutation test then keeps its
// stores there and rewrites its golden, so a build can be read against them.
const frameMissRegenerateEnv = "KANONARION_FRAMEMISS_REGENERATE"

const (
	frameMissHostWalk = "01JS0NFRAMEM1SS0000000HOST1"
	frameMissWasmWalk = "01JS0NFRAMEM1SS0000000WASM1"
)

var graphDigestLine = regexp.MustCompile(`graph: sha256:[0-9a-f]{64},`)

var frameMissWasm = cgdomain.BuildFrame{GOOS: "wasip1", GOARCH: "wasm"}

// frameMissStore writes, under root, a store holding example.com/app@local
// under each of frames, a code walk of it for the host and one for
// wasip1/wasm, and the working tree those records name.
func frameMissStore(t *testing.T, root string, frames []cgdomain.BuildFrame) (tree string) {
	t.Helper()
	tree = filepath.Join(root, "tree")
	if err := os.MkdirAll(tree, 0o750); err != nil { // #nosec G703 -- the test's own root, or the directory its regenerate hook names
		t.Fatalf("creating the tree: %v", err)
	}
	gomod := []byte("module example.com/app\n\ngo 1.24\n\nrequire example.com/dep v1.0.0\n")
	if err := os.WriteFile(filepath.Join(tree, "go.mod"), gomod, 0o600); err != nil { // #nosec G703 -- as above
		t.Fatalf("writing go.mod: %v", err)
	}
	tree, err := filepath.EvalSymlinks(tree)
	if err != nil {
		t.Fatalf("resolving the tree: %v", err)
	}
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
	store := cgsqlite.New(db)
	for i, f := range frames {
		r := cgdomain.CallGraphRecord{
			SchemaVersion: cgdomain.CallGraphSchemaVersion, Ecosystem: fetchdomain.EcosystemGo, Coordinate: app,
			Algorithm: cgdomain.AlgorithmCHA, Completeness: cgdomain.CompletenessBuiltWithBodies,
			OverallStatus: cgdomain.CallGraphStatusExtracted, AnalysisSource: cgdomain.AnalysisSourceWorktree,
			WorktreeDigest: "analysed-sha256:t", WorktreeScanDigest: "scanned-sha256:t", AnalysisRoot: tree,
			TestScope: cgdomain.TestScopeAnalysed, ReferenceScope: cgdomain.ReferenceScopeAnalysed,
			Nodes: []cgdomain.CallNode{
				{ID: "example.com/app.main", Module: "example.com/app", Package: "example.com/app", Symbol: "main"},
				{ID: "example.com/app.(Dog).Speak", Module: "example.com/app", Package: "example.com/app", Receiver: "Dog", Symbol: "Speak", IsExportedAPI: true},
				{ID: "example.com/dep.Use", Module: "example.com/dep", Package: "example.com/dep", Symbol: "Use", IsExternal: true, IsExportedAPI: true},
			},
			Edges: []cgdomain.CallEdge{
				{FromID: "example.com/app.main", ToID: "example.com/app.(Dog).Speak", Confidence: cgdomain.ConfidenceDirect,
					CallSite: cgdomain.SourcePosition{File: "main.go", Line: 9}},
				{FromID: "example.com/app.main", ToID: "example.com/dep.Use", Confidence: cgdomain.ConfidenceDirect,
					CallSite: cgdomain.SourcePosition{File: "main.go", Line: 10}},
			},
			Interfaces: []cgdomain.InterfaceType{{ID: "example.com/app.Speaker", Package: "example.com/app", Name: "Speaker", Methods: []string{"Speak"}}},
			Implementations: []cgdomain.InterfaceImplementation{{InterfaceID: "example.com/app.Speaker", TypeID: "example.com/app.(Dog)",
				Package: "example.com/app", Methods: []cgdomain.ImplementedMethod{{Method: "Speak", NodeID: "example.com/app.(Dog).Speak"}}}},
			NodeCount: 3, EdgeCount: 2, ExtractedAt: at.Add(time.Duration(i) * time.Hour),
			PipelineVersion: cgapp.PipelineVersion, Frame: f,
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
	// The walks record the toolchain the tree resolves today, so the golden pins
	// frame misses and not this host's Go release.
	goVersion := currentWalkBuildEnv(context.Background(), "", tree, nil).toolchain
	for i, w := range []struct {
		id  string
		env walkdomain.BuildEnv
	}{
		{frameMissHostWalk, walkdomain.BuildEnv{GOOS: hostFrame().GOOS, GOARCH: hostFrame().GOARCH, GoVersion: goVersion}},
		{frameMissWasmWalk, walkdomain.BuildEnv{GOOS: "wasip1", GOARCH: "wasm", GoVersion: goVersion}},
	} {
		started := at.Add(time.Duration(i) * time.Minute)
		graph := walkdomain.Graph{Target: app, Nodes: []walkdomain.GraphNode{
			{Coordinate: app, ResolutionSource: walkdomain.ResolutionLocalMainModule},
			{Coordinate: dep, DirectDependency: true, ResolutionSource: walkdomain.ResolutionMVS},
		}, Edges: []walkdomain.GraphEdge{{From: app, To: dep, ConstraintVersion: "v1.0.0"}},
			ResolvedAt: started, PipelineVersion: walkapp.PipelineVersion, BuildEnv: w.env}
		graph.Sort()
		outcome := walkdomain.WalkOutcome{Target: app, Graph: graph,
			PerNodeResults: map[coordinate.ModuleCoordinate]walkdomain.NodeResult{
				app: {Coordinate: app, Status: walkdomain.NodeSucceeded}, dep: {Coordinate: dep, Status: walkdomain.NodeSucceeded},
			},
			StartedAt: started, CompletedAt: started.Add(time.Second), OverallStatus: walkdomain.WalkSucceeded}
		rec, herr := walkdomain.WalkRecordHasher{}.SetContentHash(walkdomain.NewWalkRecord(w.id, "frame-miss", walkapp.PipelineVersion,
			walkdomain.WalkScopeCode, walkdomain.WalkDepthFull, outcome, walkdomain.DefaultDepthPolicy(), ""))
		if herr != nil {
			t.Fatalf("sealing the walk: %v", herr)
		}
		if perr := walksqlite.New(db).PutWalk(context.Background(), rec); perr != nil {
			t.Fatalf("seeding the walk: %v", perr)
		}
	}
	return tree
}

// Every call-graph read, over a store holding the record under another frame,
// this host's, or both, and each way an invocation names its frame: a miss is
// refused as a frame miss naming the frames held, and a hit prints what the
// golden froze.
func TestCallGraphReads_FrameMissPermutations(t *testing.T) {
	requireGoOnPath(t)
	host := hostFrame()
	hostFlag := host.GOOS + "/" + host.GOARCH
	stores := []struct {
		name   string
		frames []cgdomain.BuildFrame
	}{
		{"other", []cgdomain.BuildFrame{frameMissWasm}},
		{"host", []cgdomain.BuildFrame{host}},
		{"both", []cgdomain.BuildFrame{frameMissWasm, host}},
	}
	invocations := []struct {
		name  string
		args  []string
		frame cgdomain.BuildFrame
		walk  bool
	}{
		{"no flag", nil, host, false},
		{"--target wasip1/wasm", []string{"--target", "wasip1/wasm"}, frameMissWasm, false},
		{"--target host", []string{"--target", hostFlag}, host, false},
		{"--walk-id host", []string{"--walk-id", frameMissHostWalk}, host, true},
		{"--walk-id wasip1/wasm", []string{"--walk-id", frameMissWasmWalk}, frameMissWasm, true},
	}
	reads := []struct {
		name      string
		args      []string
		takesWalk bool
	}{
		{"callers", []string{"callers", "example.com/app.(Dog).Speak"}, true},
		{"callees", []string{"callees", "example.com/app.main"}, true},
		{"implementers", []string{"implementers", "example.com/app.Speaker"}, true},
		{"usage", []string{"usage", "example.com/dep@v1.0.0"}, true},
		{"capability", []string{"capability", "example.com/app@local"}, true},
		{"callgraph-show", []string{"callgraph-show", "example.com/app@local"}, false},
	}

	path, err := filepath.Abs(filepath.Join("testdata", "framemiss.golden"))
	if err != nil {
		t.Fatalf("locating the golden: %v", err)
	}
	keep := os.Getenv(frameMissRegenerateEnv)
	var golden bytes.Buffer
	for _, st := range stores {
		root := t.TempDir()
		if keep != "" {
			root = filepath.Join(keep, st.name)
		}
		tree := frameMissStore(t, root, st.frames)
		t.Chdir(tree)
		for _, rd := range reads {
			for _, inv := range invocations {
				if inv.walk && !rd.takesWalk {
					continue
				}
				name := st.name + "/" + rd.name + "/" + inv.name
				out, stderr, code := runTinyGoCLI(t, root, append(append([]string{}, rd.args...), inv.args...)...)
				held := false
				for _, f := range st.frames {
					held = held || cgdomain.SameFrame(f, inv.frame)
				}
				if !held {
					checkFrameMissRefusal(t, name, stderr, code, inv.frame, st.frames[0], tree)
					continue
				}
				if code != 0 {
					t.Errorf("%s: a hit exited %d:\n%s%s", name, code, out, stderr)
				}
				// The graph digest covers the tree's path, which is a temporary directory.
				out = graphDigestLine.ReplaceAllString(strings.ReplaceAll(out, tree, "<tree>"), "graph: <digest>,")
				fmt.Fprintf(&golden, "=== %s (exit %d)\n%s", name, code, out)
			}
		}
	}

	compareGolden(t, path, golden.String(), keep != "")
}

// compareGolden fails when got is not the golden at path, after rewriting the
// golden with got when regenerate is set.
func compareGolden(t *testing.T, path, got string, regenerate bool) {
	t.Helper()
	if regenerate {
		if err := os.WriteFile(path, []byte(got), 0o600); err != nil {
			t.Fatalf("writing the golden: %v", err)
		}
	}
	want, err := os.ReadFile(path) // #nosec G304 -- the test's own testdata file
	if err != nil {
		t.Fatalf("reading the golden: %v", err)
	}
	if got != string(want) {
		t.Errorf("the hits moved from the golden %s:\n%s", path, got)
	}
}

// checkFrameMissRefusal asserts a miss is a frame miss: exit 4, the read frame
// and the held one named with its flag, and the tree the remedy re-analyses.
func checkFrameMissRefusal(t *testing.T, name, stderr string, code int, want, held cgdomain.BuildFrame, tree string) {
	t.Helper()
	if code != ExitNotFound {
		t.Errorf("%s: a frame miss exited %d, want %d:\n%s", name, code, ExitNotFound, stderr)
	}
	for _, s := range []string{"extracted under " + want.String(), held.String(), held.FlagSpelling(), "kanonarion local " + tree} {
		if !strings.Contains(stderr, s) {
			t.Errorf("%s: the refusal does not say %q:\n%s", name, s, stderr)
		}
	}
	for _, s := range []string{"no longer decodes", "typo", cgdomain.UnnamedWorkingTreeLead} {
		if strings.Contains(stderr, s) {
			t.Errorf("%s: a frame miss is misreported as %q:\n%s", name, s, stderr)
		}
	}
}

// A generation of another frame and one this build cannot decode are two
// reasons, and the note states both, the frame first.
func TestSupersededGenerationsNote_FrameBeforeSchema(t *testing.T) {
	coord := mustCoord(t, "example.com/mod", "v1.0.0")
	wasm := cgdomain.CallGraphRecord{Coordinate: coord, Frame: frameMissWasm, ContentHash: "sha256:wasm"}
	lister := listedGenerations{coord: coord, hashes: []string{"sha256:wasm", "sha256:undecodable"}}

	note, err := supersededGenerationsNote(context.Background(), coord, lister, []cgdomain.CallGraphRecord{wasm}, []cgdomain.CallGraphRecord{wasm})
	if err != nil {
		t.Fatalf("supersededGenerationsNote: %v", err)
	}
	want := "1 generation(s) extracted under wasip1/wasm; read one with --target wasip1/wasm; " +
		"the store holds 1 generation(s) of it written at a record schema this build no longer decodes"
	if note != want {
		t.Errorf("note = %q\nwant  %q", note, want)
	}

	// The refusal carries the same two clauses, and names the read frame it missed.
	err = missingCallGraphRefusal(context.Background(), coord, historyOf{lister, []cgdomain.CallGraphRecord{wasm}})
	if got := ExitCodeForError(err); got != ExitNotFound {
		t.Errorf("exit = %d, want %d", got, ExitNotFound)
	}
	if !strings.Contains(err.Error(), "extracted under "+hostFrame().String()+" — "+want) {
		t.Errorf("refusal = %s", err)
	}

	// With no other frame held, only the schema clause is stated, as before.
	if note, err = supersededGenerationsNote(context.Background(), coord, lister, []cgdomain.CallGraphRecord{wasm}, nil); err != nil {
		t.Fatalf("supersededGenerationsNote: %v", err)
	}
	if strings.Contains(note, "extracted under") || !strings.Contains(note, "no longer decodes") {
		t.Errorf("note = %q", note)
	}
}

// listedGenerations is a listing of one coordinate's generations by hash.
type listedGenerations struct {
	coord  coordinate.ModuleCoordinate
	hashes []string
}

func (l listedGenerations) ListCallGraphCoordinates(context.Context, cgports.CallGraphFilter) ([]cgports.CallGraphCoordinate, error) {
	gens := make([]cgports.CallGraphGeneration, 0, len(l.hashes))
	for _, h := range l.hashes {
		gens = append(gens, cgports.CallGraphGeneration{ContentHash: h})
	}
	return []cgports.CallGraphCoordinate{{ModulePath: l.coord.Path(), ModuleVersion: l.coord.Version(),
		PipelineVersion: cgapp.PipelineVersion, Generations: gens}}, nil
}

// historyOf decodes recs out of the listing it wraps.
type historyOf struct {
	listedGenerations
	recs []cgdomain.CallGraphRecord
}

func (h historyOf) CallGraphHistory(context.Context, coordinate.ModuleCoordinate, string) ([]cgdomain.CallGraphRecord, error) {
	return h.recs, nil
}

// otherFrameOnly serves nothing under the read frame and holds one decodable
// generation under wasip1/wasm beside the listed generations it wraps.
type otherFrameOnly struct {
	*testfakes.FakeQueryCallGraph
	listed     listedGenerations
	recs       []cgdomain.CallGraphRecord
	historyErr error
}

func (o otherFrameOnly) GetCallGraphRecordFrom(context.Context, coordinate.ModuleCoordinate, string, cgdomain.ComposeRequest) (cgdomain.CallGraphRecord, bool, error) {
	return cgdomain.CallGraphRecord{}, false, nil
}

func (o otherFrameOnly) CallGraphHistory(_ context.Context, coord coordinate.ModuleCoordinate, _ string) ([]cgdomain.CallGraphRecord, error) {
	if coord != o.listed.coord {
		return nil, nil
	}
	return o.recs, o.historyErr
}

func (o otherFrameOnly) ListCallGraphCoordinates(ctx context.Context, f cgports.CallGraphFilter) ([]cgports.CallGraphCoordinate, error) {
	return o.listed.ListCallGraphCoordinates(ctx, f)
}

func newOtherFrameOnly(t *testing.T, path, version string, hashes ...string) otherFrameOnly {
	t.Helper()
	coord := mustCoord(t, path, version)
	return otherFrameOnly{
		FakeQueryCallGraph: &testfakes.FakeQueryCallGraph{},
		listed:             listedGenerations{coord: coord, hashes: hashes},
		recs:               []cgdomain.CallGraphRecord{{Coordinate: coord, Frame: frameMissWasm, ContentHash: hashes[0]}},
	}
}

// The symbol reads' refusal states an undecodable generation after the frame,
// and a version that names no coordinate is passed over, not fatal.
func TestFrameMiss_StatesSchemaAfterFrame(t *testing.T) {
	uc := newOtherFrameOnly(t, "example.com/mod", "v1.0.0", "sha256:wasm", "sha256:undecodable")
	err := moduleFrameMiss(context.Background(), uc, "example.com/mod", []string{"not a version", "v1.0.0"})
	if got := ExitCodeForError(err); got != ExitNotFound {
		t.Fatalf("exit = %d, want %d: %v", got, ExitNotFound, err)
	}
	want := "the ledger holds one extracted under wasip1/wasm; try --history, or read that frame with --target wasip1/wasm; " +
		"the store holds 1 generation(s) of it written at a record schema this build no longer decodes. Produce one under " + hostFrame().String()
	if !strings.Contains(err.Error(), want) {
		t.Errorf("refusal = %s\nwant it to contain %s", err, want)
	}
	if err = moduleFrameMiss(context.Background(), uc, "example.com/other", []string{"v1.0.0"}); err != nil {
		t.Errorf("a module held under no frame was refused as a frame miss: %v", err)
	}
}

// usage refuses a dependency held only under another frame as a frame miss,
// rather than reporting its surface as never enumerated.
func TestUsage_DependencyHeldUnderAnotherFrame(t *testing.T) {
	uc := newOtherFrameOnly(t, "example.com/dep", "v1.0.0", "sha256:wasm")
	stored, err := uc.ListCallGraphCoordinates(context.Background(), cgports.CallGraphFilter{})
	if err != nil {
		t.Fatal(err)
	}
	_, err = resolveUsageModule(context.Background(), uc, mustCoord(t, "example.com/dep", "v1.0.0"), coordinate.ModuleSet{}, "", stored)
	if got := ExitCodeForError(err); got != ExitNotFound || !strings.Contains(fmt.Sprint(err), "extracted under wasip1/wasm") {
		t.Errorf("usage of an other-frame dependency = exit %d: %v", got, err)
	}
}

// A history that cannot be read leaves the refusal to the listing alone.
func TestMissingCallGraphRefusal_UnreadableHistory(t *testing.T) {
	uc := newOtherFrameOnly(t, "example.com/mod", "v1.0.0", "sha256:undecodable")
	uc.historyErr = fmt.Errorf("reading the history")
	err := missingCallGraphRefusal(context.Background(), uc.listed.coord, uc)
	if err == nil || strings.Contains(err.Error(), "extracted under") || !strings.Contains(err.Error(), "no longer decodes") {
		t.Errorf("refusal = %v", err)
	}
}

// putFrameRecord adds to the store at root a sealed graph of coord under frame
// whose only node is id.
func putFrameRecord(t *testing.T, root string, coord coordinate.ModuleCoordinate, frame cgdomain.BuildFrame, id string) {
	t.Helper()
	db, err := sqlitestore.Open(filepath.Join(root, "mirror.db"), nil, sqlitestore.IntentCreate)
	if err != nil {
		t.Fatalf("opening the store: %v", err)
	}
	defer func() { _ = db.Close() }()
	pkg, sym, _ := strings.Cut(id, ".")
	putSealedGraph(t, cgsqlite.New(db), cgdomain.CallGraphRecord{
		SchemaVersion: cgdomain.CallGraphSchemaVersion, Ecosystem: fetchdomain.EcosystemGo, Coordinate: coord,
		Algorithm: cgdomain.AlgorithmCHA, Completeness: cgdomain.CompletenessBuiltWithBodies,
		OverallStatus: cgdomain.CallGraphStatusExtracted, AnalysisSource: cgdomain.AnalysisSourceModuleZip, ArtefactIdentity: "zip:h1:x",
		Nodes:     []cgdomain.CallNode{{ID: id, Module: coord.Path(), Package: pkg, Symbol: sym, IsExportedAPI: true}},
		NodeCount: 1, ExtractedAt: time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC), PipelineVersion: cgapp.PipelineVersion, Frame: frame,
	})
}

// frameMissClassStores is a host-held store whose scope also holds stdlib and
// example.com/dep only under wasip1/wasm, and a store holding the app only
// under wasip1/wasm; the working directory is the host store's tree.
func frameMissClassStores(t *testing.T) (hostRoot, wasmRoot string) {
	t.Helper()
	hostRoot, wasmRoot = t.TempDir(), t.TempDir()
	t.Chdir(frameMissStore(t, hostRoot, []cgdomain.BuildFrame{hostFrame()}))
	stdlib, err := coordinate.NewStdlibCoordinateAt("v1.27.2")
	if err != nil {
		t.Fatal(err)
	}
	putFrameRecord(t, hostRoot, stdlib, frameMissWasm, "fmt.Println")
	putFrameRecord(t, hostRoot, mustCoord(t, "example.com/dep", "v1.0.0"), frameMissWasm, "example.com/dep.Use")
	frameMissStore(t, wasmRoot, []cgdomain.BuildFrame{frameMissWasm})
	return hostRoot, wasmRoot
}

// context's call-graph section names the frames a graph is held under.
func TestFrameMiss_ContextSection(t *testing.T) {
	requireGoOnPath(t)
	root, wasmStore := frameMissClassStores(t)
	out, stderr, code := runTinyGoCLI(t, wasmStore, "context", "example.com/app@local")
	if code != 0 || !strings.Contains(out, "Call Graph:      (held under wasip1/wasm — read with --target wasip1/wasm)") {
		t.Errorf("context of a graph held under wasip1 = exit %d:\n%s%s", code, out, stderr)
	}
	out, _, _ = runTinyGoCLI(t, wasmStore, "context", "example.com/app@local", "--json")
	if !strings.Contains(out, `"status": "other_frame"`) || !strings.Contains(out, `"held_frames": [`) {
		t.Errorf("context --json lacks the held frames:\n%s", out)
	}
	if out, _, _ = runTinyGoCLI(t, root, "context", "example.com/app@local"); strings.Contains(out, "held under") {
		t.Errorf("context of a host-held graph names other frames:\n%s", out)
	}
}

// The not-searched notice names a scope coordinate held only under other frames.
func TestFrameMiss_NotSearchedNotice(t *testing.T) {
	requireGoOnPath(t)
	root, _ := frameMissClassStores(t)
	_, stderr, _ := runTinyGoCLI(t, root, "callees", "example.com/app.main", "--walk-id", frameMissHostWalk)
	if want := "notice: 1 module version(s) in the build scope are held only under other frames and were not searched: " +
		"example.com/dep@v1.0.0 (wasip1/wasm; read with --target wasip1/wasm)"; !strings.Contains(stderr, want) {
		t.Errorf("the notice lacks %q:\n%s", want, stderr)
	}
	out, _, _ := runTinyGoCLI(t, root, "implementers", "example.com/app.Speaker", "--walk-id", frameMissHostWalk, "--json")
	if !strings.Contains(out, `"reason": "other_frame"`) || !strings.Contains(out, `"frames": [`) {
		t.Errorf("implementers --json lacks the other_frame row:\n%s", out)
	}
}

// A standard-library symbol held only under another frame is a frame miss.
func TestFrameMiss_StdlibSymbol(t *testing.T) {
	requireGoOnPath(t)
	root, _ := frameMissClassStores(t)
	for _, args := range [][]string{{"callees", "fmt.Println"}, {"implementers", "fmt.Stringer"}} {
		_, stderr, code := runTinyGoCLI(t, root, args...)
		if code != ExitNotFound || !strings.Contains(stderr, "no callgraph record for stdlib@v1.27.2 extracted under "+hostFrame().String()) ||
			!strings.Contains(stderr, "--target wasip1/wasm") {
			t.Errorf("%v = exit %d:\n%s", args, code, stderr)
		}
	}
	if _, stderr, code := runTinyGoCLI(t, root, "callees", "example.com/nothere.F"); code != ExitConfig || strings.Contains(stderr, "stdlib") {
		t.Errorf("a non-stdlib symbol was routed to the stdlib frame check: exit %d\n%s", code, stderr)
	}
}

// interface-diff --used-by names the frames the consumer's graph is held under.
func TestFrameMiss_UsedByConsumer(t *testing.T) {
	requireGoOnPath(t)
	_, wasmStore := frameMissClassStores(t)
	used := &usedByResult{consumerBinding: consumerBinding{Consumer: mustCoord(t, "example.com/app", "local")}}
	if used.absentGraphClause() != "there is no stored call graph for it; run: kanonarion local ." ||
		used.absentGraphLead() != "no stored call graph for example.com/app" || used.absentGraphRemedy() != "; run: kanonarion local ." {
		t.Error("a consumer with no graph at all is no longer stated as before")
	}
	ctr, cleanup, err := NewContainer(wasmStore, "", "", false, activeConfig, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer releaseStore(cleanup)
	used.frameMiss = consumerFrameMiss(context.Background(), ctr.QueryCallGraph, used.Consumer)
	want := "held under wasip1/wasm, not under this read's frame " + hostFrame().String() +
		"; read it with --target wasip1/wasm, or produce this frame's with: kanonarion local "
	if !strings.Contains(used.absentGraphLead(), want) || used.absentGraphClause() != used.frameMiss || used.absentGraphRemedy() != "" {
		t.Errorf("used-by frame miss = %q", used.frameMiss)
	}
	if consumerFrameMiss(context.Background(), ctr.QueryCallGraph, mustCoord(t, "example.com/none", "v1.0.0")) != "" {
		t.Error("a consumer held under no frame was stated as a frame miss")
	}
}
