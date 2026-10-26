package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"math/rand/v2"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"slices"
	"strings"
	"testing"
	"time"

	"code.eitanity.com/kanonarion/internal/adapters/sqlitestore"
	cgsqlite "code.eitanity.com/kanonarion/internal/callgraph/adapters/store/sqlite"
	cgapp "code.eitanity.com/kanonarion/internal/callgraph/application"
	cgdomain "code.eitanity.com/kanonarion/internal/callgraph/domain"
	"code.eitanity.com/kanonarion/internal/coordinate"
	fetchdomain "code.eitanity.com/kanonarion/internal/fetch/domain"
	walksqlite "code.eitanity.com/kanonarion/internal/walk/adapters/walks/sqlite"
	walkapp "code.eitanity.com/kanonarion/internal/walk/application"
	walkdomain "code.eitanity.com/kanonarion/internal/walk/domain"
)

// The fixture: a served graph and graphs held only at a superseded pipeline,
// both holding edges into one symbol, through the real store and Run.

const (
	nsTarget   = "example.com/lib.Target"
	nsIface    = "example.com/lib.Store"
	nsOld      = "0.1.0"
	nsWalkID   = "01JS0NSEARCHED000000000WA1"
	nsAppPath  = "example.com/app"
	nsWtRoot   = "/src/wt"
	nsAppRoot  = "/src/app"
	nsLibV1    = "v1.0.0"
	nsReDerive = "re-derive with:"
)

// nsGen is one generation the fixture lays down.
type nsGen struct {
	path, version, pipeline string
	edges                   [][2]string
	root                    string // worktree root; "" for a module zip
	iface                   bool   // declares nsIface with one implementer
}

// nsGenerations is the whole fixture. mixed holds a served and a superseded
// generation and must never be named; deep and deepc touch only a second-level
// symbol, so only a traversal names them.
func nsGenerations(withSuperseded bool) []nsGen {
	served := []nsGen{
		{path: nsAppPath, version: coordinate.LocalVersion, pipeline: cgapp.PipelineVersion, root: nsAppRoot,
			edges: [][2]string{{"example.com/app.Main", nsTarget}}},
		{path: "example.com/lib", version: nsLibV1, pipeline: cgapp.PipelineVersion, iface: true,
			edges: [][2]string{{nsTarget, "example.com/lib.leaf"}}},
		{path: "example.com/mixed", version: nsLibV1, pipeline: cgapp.PipelineVersion,
			edges: [][2]string{{"example.com/mixed.Call", nsTarget}, {nsTarget, "example.com/mixed.cb"}}},
	}
	if !withSuperseded {
		return served
	}
	return append(served,
		nsGen{path: "example.com/lib", version: "v0.9.0", pipeline: nsOld, iface: true},
		nsGen{path: "example.com/lib", version: "v0.8.0", pipeline: nsOld, iface: true},
		nsGen{path: "example.com/lib", version: "v0.8.0", pipeline: cgapp.PipelineVersion, iface: true},
		nsGen{path: "example.com/old", version: nsLibV1, pipeline: nsOld,
			edges: [][2]string{{"example.com/old.Caller", nsTarget}, {nsTarget, "example.com/lib.other"}}},
		nsGen{path: "example.com/mixed", version: nsLibV1, pipeline: nsOld,
			edges: [][2]string{{"example.com/mixed.Call", nsTarget}, {nsTarget, "example.com/mixed.cb"}}},
		nsGen{path: "example.com/deep", version: nsLibV1, pipeline: nsOld,
			edges: [][2]string{{"example.com/deep.X", "example.com/app.Main"}}},
		nsGen{path: "example.com/deepc", version: nsLibV1, pipeline: nsOld,
			edges: [][2]string{{"example.com/lib.leaf", "example.com/deepc.Y"}}},
		nsGen{path: "example.com/wt", version: coordinate.LocalVersion, pipeline: nsOld, root: nsWtRoot,
			edges: [][2]string{{"example.com/wt.Run", nsTarget}}},
		nsGen{path: "example.com/wt2", version: coordinate.LocalVersion, pipeline: nsOld,
			edges: [][2]string{{"example.com/wt2.Run", nsTarget}}},
	)
}

func nsRecord(t *testing.T, g nsGen, at time.Time) cgdomain.CallGraphRecord {
	t.Helper()
	coord := mustCoord(t, g.path, g.version)
	nodes := map[string]bool{}
	var edges []cgdomain.CallEdge
	for i, e := range g.edges {
		nodes[e[0]], nodes[e[1]] = true, true
		edges = append(edges, cgdomain.CallEdge{FromID: e[0], ToID: e[1], Confidence: cgdomain.ConfidenceDirect,
			CallSite: cgdomain.SourcePosition{File: "f.go", Line: i + 1}})
	}
	if g.path == "example.com/lib" {
		nodes[nsTarget] = true
	}
	var ns []cgdomain.CallNode
	for id := range nodes {
		ns = append(ns, cgdomain.CallNode{ID: id, Package: id[:strings.LastIndex(id, ".")], Symbol: id[strings.LastIndex(id, ".")+1:]})
	}
	r := builtRecord(ns, edges)
	r.SchemaVersion = cgdomain.CallGraphSchemaVersion
	r.Ecosystem = fetchdomain.EcosystemGo
	r.Coordinate = coord
	r.Algorithm = cgdomain.AlgorithmCHA
	r.OverallStatus = cgdomain.CallGraphStatusExtracted
	r.AnalysisSource = cgdomain.AnalysisSourceModuleZip
	r.ArtefactIdentity = "zip:h1:" + g.path
	if g.root != "" {
		r.AnalysisSource = cgdomain.AnalysisSourceWorktree
		r.ArtefactIdentity = ""
		r.WorktreeDigest = "sha256:" + strings.Repeat("a", 8)
		r.AnalysisRoot = g.root
	}
	if g.iface {
		r.Interfaces = []cgdomain.InterfaceType{{ID: nsIface, Package: "example.com/lib", Name: "Store", Methods: []string{"Get"}}}
		r.Implementations = []cgdomain.InterfaceImplementation{{InterfaceID: nsIface, TypeID: "example.com/lib.(*mem)"}}
	}
	r.NodeCount, r.EdgeCount = len(ns), len(edges)
	r.ExtractedAt = at
	r.PipelineVersion = g.pipeline
	r.Frame = hostFrame()
	sealed, err := cgdomain.CallGraphRecordHasher{}.SetContentHash(r)
	if err != nil {
		t.Fatalf("SetContentHash: %v", err)
	}
	return sealed
}

// nsStore writes the generations in the given order to a scratch store, with a
// walk whose scope is the app, lib@v1.0.0, old, mixed and a module never
// analysed.
func nsStore(t *testing.T, gens []nsGen) string {
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
	ctx := context.Background()
	store := cgsqlite.New(db)
	at := time.Date(2026, 9, 15, 12, 0, 0, 0, time.UTC)
	for i, g := range gens {
		if perr := store.PutCallGraphRecord(ctx, nsRecord(t, g, at.Add(time.Duration(i)*time.Minute))); perr != nil {
			t.Fatalf("PutCallGraphRecord %s@%s: %v", g.path, g.version, perr)
		}
	}
	nsSeedWalk(t, ctx, db)
	return root
}

func nsSeedWalk(t *testing.T, ctx context.Context, db sqlitestore.DB) {
	t.Helper()
	app, err := coordinate.NewLocalCoordinate(nsAppPath)
	if err != nil {
		t.Fatalf("local coordinate: %v", err)
	}
	nodes := []walkdomain.GraphNode{{Coordinate: app, ResolutionSource: walkdomain.ResolutionLocalMainModule}}
	results := map[coordinate.ModuleCoordinate]walkdomain.NodeResult{app: {Coordinate: app, Status: walkdomain.NodeSucceeded}}
	var edges []walkdomain.GraphEdge
	for _, p := range []string{"example.com/lib", "example.com/old", "example.com/mixed", "example.com/never"} {
		c := mustCoord(t, p, nsLibV1)
		nodes = append(nodes, walkdomain.GraphNode{Coordinate: c, DirectDependency: true, ResolutionSource: walkdomain.ResolutionMVS})
		edges = append(edges, walkdomain.GraphEdge{From: app, To: c, ConstraintVersion: nsLibV1})
		results[c] = walkdomain.NodeResult{Coordinate: c, Status: walkdomain.NodeSucceeded}
	}
	at := time.Date(2026, 9, 15, 11, 0, 0, 0, time.UTC)
	graph := walkdomain.Graph{Target: app, Nodes: nodes, Edges: edges, ResolvedAt: at, PipelineVersion: walkapp.PipelineVersion}
	graph.Sort()
	outcome := walkdomain.WalkOutcome{Target: app, Graph: graph, PerNodeResults: results,
		StartedAt: at, CompletedAt: at.Add(time.Second), OverallStatus: walkdomain.WalkSucceeded}
	rec := walkdomain.NewWalkRecord(nsWalkID, "guard", walkapp.PipelineVersion,
		walkdomain.WalkScopeCode, walkdomain.WalkDepthFull, outcome, walkdomain.DefaultDepthPolicy(), "")
	rec, err = walkdomain.WalkRecordHasher{}.SetContentHash(rec)
	if err != nil {
		t.Fatalf("sealing the walk: %v", err)
	}
	if perr := walksqlite.New(db).PutWalk(ctx, rec); perr != nil {
		t.Fatalf("seeding the walk: %v", perr)
	}
}

func nsRun(t *testing.T, root string, args ...string) (string, string) {
	t.Helper()
	var stdout, stderr bytes.Buffer
	if err := Run(append(args, "--store-root", root), &stdout, &stderr); err != nil {
		t.Fatalf("%v = %v\nstderr: %s", args, err, stderr.String())
	}
	return stdout.String(), stderr.String()
}

type nsEntry struct {
	Coordinate string   `json:"coordinate"`
	Pipelines  []string `json:"pipelines"`
	Reason     string   `json:"reason"`
	Remedy     string   `json:"remedy"`
}

// nsDocNotSearched decodes not_searched from a JSON document.
func nsDocNotSearched(t *testing.T, stdout string) []nsEntry {
	t.Helper()
	var doc struct {
		NotSearched []nsEntry `json:"not_searched"`
	}
	if err := json.Unmarshal([]byte(stdout), &doc); err != nil {
		t.Fatalf("decoding the document: %v\n%s", err, stdout)
	}
	return doc.NotSearched
}

func nsCoords(es []nsEntry) []string {
	out := make([]string, 0, len(es))
	for _, e := range es {
		out = append(out, e.Coordinate+" "+e.Reason)
	}
	return out
}

// nsNamed lists the coordinates a stderr notice names, with the reason its
// notice line states.
func nsNamed(stderr string) []string {
	var out []string
	for _, line := range strings.Split(stderr, "\n") {
		reason := ""
		switch {
		case strings.Contains(line, "only from superseded extraction logic"):
			reason = "superseded"
		case strings.Contains(line, "no call graph at any pipeline"):
			reason = "not_analysed"
		default:
			continue
		}
		list := line[strings.Index(line, "searched: ")+len("searched: ") : strings.LastIndex(line, " — ")]
		for _, c := range strings.Split(nsPipelines.ReplaceAllString(list, ""), ", ") {
			out = append(out, c+" "+reason)
		}
	}
	return out
}

var nsPipelines = regexp.MustCompile(` \(pipeline [^)]*\)`)

func nsWant(t *testing.T, label string, got, want []string) {
	t.Helper()
	if len(got) == 0 && len(want) == 0 {
		return
	}
	got = slices.Sorted(slices.Values(got))
	if !reflect.DeepEqual(got, want) {
		t.Errorf("%s names %v, want %v", label, got, want)
	}
}

var (
	nsCallersPlain = []string{"example.com/old@v1.0.0 superseded", "example.com/wt2@local superseded", "example.com/wt@local superseded"}
	nsCallersDeep  = []string{"example.com/deep@v1.0.0 superseded", "example.com/old@v1.0.0 superseded",
		"example.com/wt2@local superseded", "example.com/wt@local superseded"}
	nsCalleesPlain = []string{"example.com/old@v1.0.0 superseded"}
	nsCalleesDeep  = []string{"example.com/deepc@v1.0.0 superseded", "example.com/old@v1.0.0 superseded"}
	nsScoped       = []string{"example.com/never@v1.0.0 not_analysed", "example.com/old@v1.0.0 superseded"}
	nsImplPlain    = []string{"example.com/lib@v0.9.0 superseded"}
)

// nsCase is one form of one command and what it must name.
type nsCase struct {
	args []string
	want []string
	// doc says the --json form is an object carrying not_searched; the plain
	// edge queries print an array, so they state it on stderr.
	doc bool
}

func nsCases() []nsCase {
	scope := []string{"--walk-id", nsWalkID}
	return []nsCase{
		{args: []string{"callers", nsTarget}, want: nsCallersPlain},
		{args: []string{"callers", nsTarget, "--transitive", "--no-progress"}, want: nsCallersDeep, doc: true},
		{args: append([]string{"callers", nsTarget}, scope...), want: nsScoped},
		{args: append([]string{"callers", nsTarget, "--transitive", "--no-progress"}, scope...), want: nsScoped, doc: true},
		{args: []string{"callees", nsTarget}, want: nsCalleesPlain},
		{args: []string{"callees", nsTarget, "--transitive", "--no-progress"}, want: nsCalleesDeep, doc: true},
		{args: append([]string{"callees", nsTarget}, scope...), want: nsScoped},
		{args: append([]string{"callees", nsTarget, "--transitive", "--no-progress"}, scope...), want: nsScoped, doc: true},
		{args: []string{"implementers", nsIface}, want: nsImplPlain, doc: true},
		{args: append([]string{"implementers", nsIface}, scope...), want: nsScoped, doc: true},
	}
}

// TestNotSearched_EveryFormNamesWhatItCouldNotRead: text on stderr, and under
// --json in the document or, for a bare array, on stderr.
func TestNotSearched_EveryFormNamesWhatItCouldNotRead(t *testing.T) {
	root := nsStore(t, nsGenerations(true))
	for _, c := range nsCases() {
		t.Run(strings.Join(c.args, " "), func(t *testing.T) {
			stdout, stderr := nsRun(t, root, c.args...)
			nsWant(t, "text stderr", nsNamed(stderr), c.want)
			if strings.Contains(stdout, "were not searched") {
				t.Errorf("the notice is on stdout:\n%s", stdout)
			}

			stdout, stderr = nsRun(t, root, append(c.args, "--json")...)
			if c.doc {
				nsWant(t, "document", nsCoords(nsDocNotSearched(t, stdout)), c.want)
				if strings.Contains(stderr, "were not searched") {
					t.Errorf("stderr repeats what the document carries:\n%s", stderr)
				}
				return
			}
			nsWant(t, "--json stderr", nsNamed(stderr), c.want)
		})
	}
}

// TestNotSearched_RemedyNamesTheCommandThatReDerives: callgraph for a published
// module, local with the recorded tree, and a named placeholder otherwise.
func TestNotSearched_RemedyNamesTheCommandThatReDerives(t *testing.T) {
	root := nsStore(t, nsGenerations(true))
	_, stderr := nsRun(t, root, "callers", nsTarget)
	for _, want := range []string{
		nsReDerive,
		"  kanonarion fetch example.com/old@v1.0.0 && kanonarion callgraph example.com/old@v1.0.0\n",
		"  kanonarion local " + nsWtRoot + "\n",
		"  example.com/wt2@local: no stored record names the working tree, so run kanonarion local from inside it\n",
		"example.com/old@v1.0.0 (pipeline 0.1.0)",
	} {
		if !strings.Contains(stderr, want) {
			t.Errorf("stderr lacks %q:\n%s", want, stderr)
		}
	}
	stdout, _ := nsRun(t, root, "callers", nsTarget, "--transitive", "--no-progress", "--json")
	got := map[string]nsEntry{}
	for _, e := range nsDocNotSearched(t, stdout) {
		got[e.Coordinate] = e
	}
	if e := got["example.com/old@v1.0.0"]; e.Remedy != "kanonarion fetch example.com/old@v1.0.0 && kanonarion callgraph example.com/old@v1.0.0" ||
		!reflect.DeepEqual(e.Pipelines, []string{nsOld}) {
		t.Errorf("old = %+v", e)
	}
	if e := got["example.com/wt@local"]; e.Remedy != "kanonarion local "+nsWtRoot {
		t.Errorf("wt = %+v", e)
	}
	if e := got["example.com/wt2@local"]; e.Remedy != "" {
		t.Errorf("wt2 names remedy %q for a tree no record names", e.Remedy)
	}
}

// TestNotSearched_ScopeNamesTheNeverAnalysedRemedy: a module with no graph is
// told to analyse, not re-derive.
func TestNotSearched_ScopeNamesTheNeverAnalysedRemedy(t *testing.T) {
	root := nsStore(t, nsGenerations(true))
	_, stderr := nsRun(t, root, "callers", nsTarget, "--walk-id", nsWalkID)
	if !strings.Contains(stderr, "analyse with:\n  kanonarion fetch example.com/never@v1.0.0 && kanonarion callgraph example.com/never@v1.0.0\n") {
		t.Errorf("stderr does not name the never-analysed module's remedy:\n%s", stderr)
	}
}

// TestNotSearched_InsertionOrderDoesNotChangeTheAnswer shuffles the fixture's
// records and requires the same not_searched every time.
func TestNotSearched_InsertionOrderDoesNotChangeTheAnswer(t *testing.T) {
	gens := nsGenerations(true)
	rng := rand.New(rand.NewPCG(9, 10)) // #nosec G404 -- a seeded, reproducible shuffle, not a secret
	var first map[string]string
	for range 6 {
		rng.Shuffle(len(gens), func(i, j int) { gens[i], gens[j] = gens[j], gens[i] })
		root := nsStore(t, gens)
		got := map[string]string{}
		for _, args := range [][]string{
			{"callers", nsTarget, "--transitive", "--no-progress", "--json"},
			{"callees", nsTarget, "--transitive", "--no-progress", "--json"},
			{"implementers", nsIface, "--json"},
			{"callers", nsTarget, "--transitive", "--no-progress", "--json", "--walk-id", nsWalkID},
		} {
			stdout, _ := nsRun(t, root, args...)
			b, err := json.Marshal(nsDocNotSearched(t, stdout))
			if err != nil {
				t.Fatal(err)
			}
			got[strings.Join(args, " ")] = string(b)
		}
		_, stderr := nsRun(t, root, "callers", nsTarget)
		got["callers"] = stderr
		if first == nil {
			first = got
			continue
		}
		if !reflect.DeepEqual(got, first) {
			t.Fatalf("insertion order changed the answer:\n%v\nvs\n%v", got, first)
		}
	}
}

// TestNotSearched_AllServedStoreSaysNothing is the control: no notice, no key.
func TestNotSearched_AllServedStoreSaysNothing(t *testing.T) {
	root := nsStore(t, nsGenerations(false))
	for _, c := range nsCases() {
		if strings.Contains(strings.Join(c.args, " "), nsWalkID) {
			continue // the scope holds never and old, which nothing analysed here
		}
		t.Run(strings.Join(c.args, " "), func(t *testing.T) {
			for _, extra := range [][]string{nil, {"--json"}} {
				stdout, stderr := nsRun(t, root, append(append([]string{}, c.args...), extra...)...)
				if stderr != "" {
					t.Errorf("stderr is not empty:\n%s", stderr)
				}
				if strings.Contains(stdout, "not_searched") || strings.Contains(stdout, "were not searched") {
					t.Errorf("stdout names a gap where there is none:\n%s", stdout)
				}
			}
		})
	}
}

// TestNotSearched_RefusalIsUnchanged: a symbol in no served graph still exits 4
// naming the remedy, and no notice is added beside it.
func TestNotSearched_RefusalIsUnchanged(t *testing.T) {
	root := nsStore(t, nsGenerations(true))
	var stdout, stderr bytes.Buffer
	err := Run([]string{"callers", "example.com/old.Caller", "--store-root", root}, &stdout, &stderr)
	if code := ExitCodeForError(err); code != ExitNotFound {
		t.Fatalf("exit %d (%v), want %d", code, err, ExitNotFound)
	}
	if !strings.Contains(err.Error(), "kanonarion callgraph example.com/old@v1.0.0") {
		t.Errorf("the refusal does not name the remedy: %v", err)
	}
	if strings.Contains(stderr.String(), "were not searched") {
		t.Errorf("a refusal carries the notice too:\n%s", stderr.String())
	}
}

// TestNotSearched_GoModScopeNamesTheNeverAnalysed runs the --gomod route itself
// on a project walk of the fixture.
func TestNotSearched_GoModScopeNamesTheNeverAnalysed(t *testing.T) {
	root := nsStore(t, nsGenerations(true))
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "go.mod"), []byte("module "+nsAppPath+"\n\ngo 1.24\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	nsSeedProjectWalk(t, root, dir)
	t.Chdir(dir)
	_, stderr := nsRun(t, root, "callers", nsTarget, "--gomod", "./go.mod")
	nsWant(t, "--gomod", nsNamed(stderr), nsScoped)
}

func nsSeedProjectWalk(t *testing.T, root, dir string) {
	t.Helper()
	ctx := context.Background()
	db, err := sqlitestore.Open(filepath.Join(root, "mirror.db"), nil, sqlitestore.IntentCreate)
	if err != nil {
		t.Fatalf("opening the store: %v", err)
	}
	defer func() { _ = db.Close() }()
	wrec, err := walksqlite.New(db).GetWalk(ctx, nsWalkID)
	if err != nil {
		t.Fatalf("reading the fixture walk: %v", err)
	}
	env := currentWalkBuildEnv(ctx, "", dir, nil)
	wrec.ID = "01JS0NSEARCHED000000000WA2"
	wrec.ProjectDir = dir
	wrec.ContentHash = ""
	wrec.Graph.BuildEnv = walkdomain.BuildEnv{GOOS: env.platform.GOOS, GOARCH: env.platform.GOARCH, GoVersion: env.toolchain}
	wrec, err = walkdomain.WalkRecordHasher{}.SetContentHash(wrec)
	if err != nil {
		t.Fatalf("sealing the project walk: %v", err)
	}
	if perr := walksqlite.New(db).PutWalk(ctx, wrec); perr != nil {
		t.Fatalf("seeding the project walk: %v", perr)
	}
}
