package cli

import (
	"context"
	"encoding/json"
	"os"
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
)

// loweringStore writes a store holding example.com/app@local under the pico
// frame, Partial for the lowering gap when gap is set and Extracted otherwise.
func loweringStore(t *testing.T, gap bool) (root, tree string) {
	t.Helper()
	root = t.TempDir()
	tree = filepath.Join(root, "tree")
	if err := os.MkdirAll(tree, 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(tree, "go.mod"), []byte("module example.com/app\n\ngo 1.24\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	tree, err := filepath.EvalSymlinks(tree)
	if err != nil {
		t.Fatal(err)
	}
	db, err := sqlitestore.Open(filepath.Join(root, "mirror.db"), nil, sqlitestore.IntentCreate)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()
	if aerr := sqlitestore.Apply(db, allMigrations()); aerr != nil {
		t.Fatal(aerr)
	}
	app, err := coordinate.NewLocalCoordinate("example.com/app")
	if err != nil {
		t.Fatal(err)
	}
	r := cgdomain.CallGraphRecord{
		SchemaVersion: cgdomain.CallGraphSchemaVersion, Ecosystem: fetchdomain.EcosystemGo, Coordinate: app,
		Algorithm: cgdomain.AlgorithmCHA, Completeness: cgdomain.CompletenessBuiltWithBodies,
		OverallStatus: cgdomain.CallGraphStatusExtracted, AnalysisSource: cgdomain.AnalysisSourceWorktree,
		WorktreeDigest: "analysed-sha256:t", WorktreeScanDigest: "scanned-sha256:t", AnalysisRoot: tree,
		TestScope: cgdomain.TestScopeAnalysed, ReferenceScope: cgdomain.ReferenceScopeAnalysed,
		Nodes: []cgdomain.CallNode{
			{ID: "example.com/app.main", Module: "example.com/app", Package: "example.com/app", Symbol: "main"},
			{ID: "example.com/app.send", Module: "example.com/app", Package: "example.com/app", Symbol: "send"},
		},
		Edges: []cgdomain.CallEdge{{FromID: "example.com/app.main", ToID: "example.com/app.send",
			Confidence: cgdomain.ConfidenceDirect, CallSite: cgdomain.SourcePosition{File: "main.go", Line: 9}}},
		NodeCount: 2, EdgeCount: 1, ExtractedAt: time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC),
		PipelineVersion: cgapp.PipelineVersion, Frame: framePico,
	}
	if gap {
		r.OverallStatus = cgdomain.CallGraphStatusPartial
		r.FailureDetail = cgdomain.TinyGoLoweringGap{Found: "0.45.0", Covered: []string{"0.42.0", "0.43.0", "0.44.0"}}.Clause()
	}
	sealed, err := cgdomain.CallGraphRecordHasher{}.SetContentHash(r)
	if err != nil {
		t.Fatal(err)
	}
	if err := cgsqlite.New(db).PutCallGraphRecord(context.Background(), sealed); err != nil {
		t.Fatal(err)
	}
	return root, tree
}

// Every edge read over a record without TinyGo's compiler-inserted calls states
// it: a list carries it on its answer line, an empty answer or a symbol only
// such an edge reaches is UNRESOLVED with the lowering remedy, and --json states
// it on stderr or, for a closure, on the document. A record with the calls says
// nothing of the kind.
func TestEdgeReads_StateTheTinyGoLoweringGap(t *testing.T) {
	requireGoOnPath(t)
	installFakeTinyGo(t)
	const gapSays = "tinygo-lowering-unrecorded at example.com/app@local (TinyGo 0.45.0 ran"
	root, tree := loweringStore(t, true)
	t.Chdir(tree)
	for _, tc := range []struct {
		args   []string
		want   []string
		stderr string
		json   bool
	}{
		{args: []string{"callers", "example.com/app.send"}, want: []string{
			"answer: RESOLVED-PRESENT — 1 caller of example.com/app.send; the calls TinyGo's compiler inserts are not recorded", gapSays}},
		{args: []string{"callees", "example.com/app.main"}, want: []string{"RESOLVED-PRESENT", gapSays}},
		{args: []string{"callers", "example.com/app.send", "--transitive"}, want: []string{"RESOLVED-PRESENT", gapSays}},
		{args: []string{"callees", "example.com/app.main", "--transitive"}, want: []string{"RESOLVED-PRESENT", gapSays}},
		{args: []string{"callers", "runtime.chanSend"}, want: []string{"answer: UNRESOLVED — callers of runtime.chanSend", gapSays,
			"lowering table covers TinyGo 0.45.0", "kanonarion local " + tree + " --tinygo pico"}},
		{args: []string{"callers", "example.com/app.main"}, want: []string{"answer: UNRESOLVED", gapSays}},
		{args: []string{"callees", "example.com/app.send", "--transitive"}, want: []string{"answer: UNRESOLVED", gapSays}},
		{args: []string{"callers", "example.com/app.send"}, json: true, stderr: "do not include the calls TinyGo's compiler inserts: " + gapSays},
		{args: []string{"callees", "runtime.chanSend"}, json: true, stderr: "do not include the calls TinyGo's compiler inserts: " + gapSays},
	} {
		checkLoweringRead(t, root, tc.args, tc.json, tc.want, tc.stderr)
	}
	out, stderr, code := runTinyGoCLI(t, root, "callers", "example.com/app.send", "--transitive", "--json", "--tinygo", "pico")
	var doc struct {
		Lowering []dispatchJSON `json:"tinygo_lowering_unrecorded"`
	}
	if err := json.Unmarshal([]byte(out), &doc); err != nil || code != 0 || len(doc.Lowering) != 1 ||
		doc.Lowering[0].Site != "example.com/app@local" || !strings.Contains(doc.Lowering[0].Detail, "TinyGo 0.45.0 ran") {
		t.Errorf("--transitive --json = exit %d, %+v (%v)\n%s%s", code, doc, err, out, stderr)
	}

	clean, cleanTree := loweringStore(t, false)
	t.Chdir(cleanTree)
	for _, args := range [][]string{{"callers", "example.com/app.send"}, {"callers", "example.com/app.main"},
		{"callers", "example.com/app.send", "--transitive", "--json"}} {
		out, stderr, _ := runTinyGoCLI(t, clean, append(args, "--tinygo", "pico")...)
		if strings.Contains(out+stderr, "lowering") {
			t.Errorf("%v over a record with the calls states a lowering gap:\n%s%s", args, out, stderr)
		}
	}
}

// checkLoweringRead runs one read under the pico frame and checks what it says.
func checkLoweringRead(t *testing.T, root string, args []string, jsonOut bool, want []string, wantStderr string) {
	t.Helper()
	full := append(append([]string{}, args...), "--tinygo", "pico")
	if jsonOut {
		full = append(full, "--json")
	}
	out, stderr, code := runTinyGoCLI(t, root, full...)
	if code != 0 {
		t.Errorf("%v: exit %d\n%s%s", full, code, out, stderr)
		return
	}
	for _, w := range want {
		if !strings.Contains(out, w) {
			t.Errorf("%v does not say %q:\n%s", full, w, out)
		}
	}
	if wantStderr != "" && !strings.Contains(stderr, wantStderr) {
		t.Errorf("%v: stderr does not say %q:\n%s", full, wantStderr, stderr)
	}
	for _, never := range []string{"RESOLVED-ABSENT", "has not been analysed", "edges in the failed package"} {
		if strings.Contains(out+stderr, never) {
			t.Errorf("%v says %q:\n%s%s", full, never, out, stderr)
		}
	}
}
