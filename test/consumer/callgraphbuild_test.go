package consumer_test

import (
	"bytes"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"code.eitanity.com/kanonarion/pkg/kanonarion"
)

// filesStore is a store root whose config.yaml selects the files backend.
func filesStore(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	writeConfig(t, root, "version: \"3\"\nstorage:\n  backend: files\n")
	return root
}

// buildGraph fetches graphModule into the store at root and builds its call
// graph with the driver's CallGraphBuild.
func buildGraph(t *testing.T, root string) (kanonarion.CallGraphBuildResult, error) {
	t.Helper()
	drv, cleanup, err := kanonarion.OpenDriver(root)
	if err != nil {
		t.Fatalf("OpenDriver: %v", err)
	}
	defer closeStore(t, cleanup)
	coord := mustCoord(t, graphModule, graphVersion)
	if _, err := drv.FetchServe.Serve(t.Context(), kanonarion.ServeRequest{Coordinate: coord}); err != nil {
		t.Fatalf("FetchServe.Serve %s: %v", coord, err)
	}
	return drv.CallGraphBuild.Run(t.Context(), kanonarion.CallGraphBuildRequest{Coordinate: coord}) //nolint:wrapcheck // the test reads the use case's own error
}

// noSQLiteUnder fails if any file under root is a SQLite database.
func noSQLiteUnder(t *testing.T, root string) {
	t.Helper()
	var files []string
	if err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err == nil && !d.IsDir() {
			files = append(files, path)
		}
		return err
	}); err != nil {
		t.Fatal(err)
	}
	for _, path := range files {
		data, err := os.ReadFile(filepath.Clean(path))
		if err != nil {
			t.Fatal(err)
		}
		if bytes.HasPrefix(data, []byte("SQLite format 3")) || strings.HasSuffix(path, ".db") {
			t.Errorf("a SQLite file was created at %s", path)
		}
	}
}

// An application that serves the call-graph child builds one module's call
// graph on its own backend, and every call-graph query answers from it at the
// exported pipeline version.
func TestConsumer_ABuiltCallGraphAnswersTheCallGraphQueries(t *testing.T) {
	f := newChildFixture(t)
	f.offline(t)
	root := filesStore(t)

	built, err := buildGraph(t, root)
	if err != nil {
		t.Fatalf("CallGraphBuild.Run: %v", err)
	}
	if built.Outcome.OverallStatus != kanonarion.CallGraphStatusExtracted || built.Outcome.EdgeCount == 0 {
		t.Fatalf("CallGraphBuild.Run outcome = %+v, want an extracted graph", built.Outcome)
	}

	q, cleanup, err := kanonarion.Open(root)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer closeStore(t, cleanup)
	if _, ok, ferr := q.Fetch.GetFetchRecord(t.Context(), mustCoord(t, graphModule, graphVersion), ""); ferr != nil || !ok {
		t.Errorf("GetFetchRecord with no pipeline version = %v, %v; want the fetched record", ok, ferr)
	}
	assertEdgeQueries(t, q.CallGraph)
	assertImplementers(t, q.CallGraph)
	noSQLiteUnder(t, root)
}

const (
	graphUp     = graphModule + ".Up"
	graphTwice  = graphModule + ".Twice"
	graphThrice = graphModule + ".Thrice"
)

// assertEdgeQueries checks direct callers and callees, with the exported
// pipeline version and with none, and the transitive closure of callers.
func assertEdgeQueries(t *testing.T, uc *kanonarion.QueryCallGraphUseCase) {
	t.Helper()
	ctx, pv, all, opts := t.Context(), kanonarion.CallGraphPipelineVersion, kanonarion.ModuleSet{}, kanonarion.EdgeQueryOptions{}
	callers, err := uc.FindCallers(ctx, graphUp, pv, all, opts)
	if err != nil || len(callers) != 1 || callers[0].FromID != graphTwice {
		t.Errorf("FindCallers(%s) = %+v, %v; want %s", graphUp, callers, err, graphTwice)
	}
	unnamed, err := uc.FindCallers(ctx, graphUp, "", all, opts)
	if err != nil || len(unnamed) != 1 {
		t.Errorf("FindCallers(%s) with no pipeline version = %+v, %v; want the current pipeline's edge", graphUp, unnamed, err)
	}
	callees, err := uc.FindCallees(ctx, graphTwice, pv, all, opts)
	if err != nil || len(callees) != 1 || callees[0].ToID != graphUp {
		t.Errorf("FindCallees(%s) = %+v, %v; want %s", graphTwice, callees, err, graphUp)
	}
	closure, err := uc.TraverseCallers(ctx, kanonarion.TraversalRequest{SymbolID: graphUp, PipelineVersion: pv})
	if err != nil || closure.Truncated || strings.Join(closure.Nodes, " ") != graphThrice+" "+graphTwice {
		t.Errorf("TraverseCallers(%s, depth 0) = %+v, %v; want [%s %s]", graphUp, closure, err, graphThrice, graphTwice)
	}
}

// assertImplementers checks the fixture interface's one implementer.
func assertImplementers(t *testing.T, uc *kanonarion.QueryCallGraphUseCase) {
	t.Helper()
	want := graphModule + ".(english)"
	res, err := uc.Implementers(t.Context(), kanonarion.ImplementersRequest{
		InterfaceID: graphModule + ".Greeter", PipelineVersion: kanonarion.CallGraphPipelineVersion,
	})
	if err != nil || len(res.Implementers) != 1 || res.Implementers[0].Implementation.TypeID != want ||
		res.Answer.Outcome != kanonarion.AnswerResolvedPresent {
		t.Errorf("Implementers(%s.Greeter) = %+v, %v; want %s", graphModule, res, err, want)
	}
}

// An application that does not serve the call-graph child gets an error that
// carries the child's failure, not an empty graph.
func TestConsumer_ACallGraphBuildTheApplicationDoesNotServeIsAnError(t *testing.T) {
	f := newChildFixture(t)
	f.offline(t)
	t.Setenv(noCallGraphEnv, "1")
	root := filesStore(t)

	built, err := buildGraph(t, root)
	if err == nil || !strings.Contains(err.Error(), "subprocess failed") || !strings.Contains(err.Error(), noCallGraphMessage) {
		t.Errorf("CallGraphBuild.Run = %+v, %v; want the child's failure", built, err)
	}
	noSQLiteUnder(t, root)
}
