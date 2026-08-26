package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/eitanity/kanonarion/internal/cli/testfakes"
	"github.com/eitanity/kanonarion/internal/coordinate"
	walkdomain "github.com/eitanity/kanonarion/internal/walk/domain"
)

// The defect this file pins: `dependents` was the one read with no way to name
// the build the question is about. With no --walk-id it searched the store for
// any walk holding the coordinate, which invents a root — and then refused
// whenever two of a developer's projects happened to hold it, on a store where
// that was 86 of 876 coordinates. Dependents are a property of one build.
//
// The fixtures below are the shape that made the search look adequate and the
// shape that shows it is not: one project, walked in two scopes, holding
// different modules. A linter is in the tool closure and not in the code build.

// rootedProject writes a go.mod for modulePath into a fresh directory and
// returns the directory.
func rootedProject(t *testing.T, modulePath string) string {
	t.Helper()
	dir := t.TempDir()
	body := "module " + modulePath + "\n\ngo 1.26\n"
	if err := os.WriteFile(filepath.Join(dir, "go.mod"), []byte(body), 0o600); err != nil {
		t.Fatalf("writing go.mod: %v", err)
	}
	return dir
}

// rootedWalk builds a succeeded project walk of one scope, rooted at modulePath
// and holding each of holds as a direct dependency with an edge from the root.
func rootedWalk(t *testing.T, id, modulePath, dir string, scope walkdomain.WalkScope, holds ...coordinate.ModuleCoordinate) walkdomain.WalkRecord {
	t.Helper()
	root, err := coordinate.NewLocalCoordinate(modulePath)
	if err != nil {
		t.Fatalf("local coordinate: %v", err)
	}
	nodes := []walkdomain.GraphNode{{Coordinate: root, ResolutionSource: walkdomain.ResolutionLocalMainModule}}
	edges := make([]walkdomain.GraphEdge, 0, len(holds))
	for _, h := range holds {
		nodes = append(nodes, walkdomain.GraphNode{Coordinate: h, DirectDependency: true, ResolutionSource: walkdomain.ResolutionMVS})
		edges = append(edges, walkdomain.GraphEdge{From: root, To: h})
	}
	return walkdomain.WalkRecord{
		ID:            id,
		Target:        root,
		Scope:         scope,
		OverallStatus: walkdomain.WalkSucceeded,
		ProjectDir:    dir,
		Graph: walkdomain.Graph{
			Target:   root,
			Nodes:    nodes,
			Edges:    edges,
			BuildEnv: walkdomain.BuildEnv{GOOS: runtime.GOOS, GOARCH: runtime.GOARCH},
		},
	}
}

// runDependentsIn runs the command from dir, which is what decides whether the
// working directory supplies a root at all.
func runDependentsIn(t *testing.T, dir string, walks *testfakes.FakeQueryWalks, coord coordinate.ModuleCoordinate,
	f dependentsFlags, jsonOut bool,
) (string, string, error) {
	t.Helper()
	t.Chdir(dir)
	var stdout, stderr bytes.Buffer
	err := dependentsWith(context.Background(), &Container{QueryWalks: walks}, coord, f, jsonOut, &stdout, &stderr)
	return stdout.String(), stderr.String(), err
}

// The default case, and the whole point: standing in a project, with no flag at
// all, the answer is about that project's build.
func TestDependents_NoFlagsAnswersFromTheProjectYouAreStandingIn(t *testing.T) {
	const modulePath = "example.com/app"
	dir := rootedProject(t, modulePath)
	lib := mustCoord(t, "example.com/lib", "v1.0.0")
	consumer := mustCoord(t, "example.com/consumer", "v1.0.0")

	code := rootedWalk(t, "W-code", modulePath, dir, walkdomain.WalkScopeCode, lib, consumer)
	code.Graph.Edges = append(code.Graph.Edges, walkdomain.GraphEdge{From: consumer, To: lib})
	walks := selectionStore(code)

	stdout, _, err := runDependentsIn(t, dir, walks, lib, dependentsFlags{}, false)
	if err != nil {
		t.Fatalf("a question asked inside a project could not be rooted: %v", err)
	}
	for _, want := range []string{"W-code", "example.com/consumer@v1.0.0", "go.mod"} {
		if !strings.Contains(stdout, want) {
			t.Errorf("the answer does not name %q:\n%s", want, stdout)
		}
	}
}

// The falsifying case. Nothing names a build and there is no go.mod to take one
// from, so there is no question to answer. The refusal names all three ways to
// give one — and the store is never listed, because a silent fall back to the
// search is the defect being removed.
func TestDependents_NoRootRefusesAndDoesNotSearch(t *testing.T) {
	lib := mustCoord(t, "example.com/lib", "v1.0.0")
	app := mustCoord(t, "example.com/app", "v1.0.0")
	walks := containmentFixture(containmentWalk{id: "walk-app", root: app, holds: []coordinate.ModuleCoordinate{lib}})

	_, _, err := runDependentsIn(t, t.TempDir(), walks, lib, dependentsFlags{}, false)
	if err == nil {
		t.Fatal("a question that names no build was answered anyway")
	}
	for _, want := range []string{"property of one build", "--gomod", "--walk-id", "--any-build"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("the refusal does not name %q: %v", want, err)
		}
	}
	if code, ok := ExitCodeFromError(err); !ok || code != ExitConfig {
		t.Errorf("exit code = %d (carried %v), want ExitConfig", code, ok)
	}
	if walks.ListCalls != 0 {
		t.Errorf("the store was listed %d time(s): the refusal fell back to the search it exists to remove", walks.ListCalls)
	}
}

// The trap the ticket was measured on. A linter is in the tool closure and not
// in the code build — on the live store, 235 of the tool walk's 246 modules are
// absent from the 22-node code walk. Rooting at ./go.mod without a scope flag
// would answer "nothing depends on it", which is the regression that makes this
// change a trade rather than an improvement.
//
// Under --tool it answers. Under the default it refuses, names the scope that
// holds the module, and never reports an absence.
func TestDependents_ToolClosureModuleAnswersUnderToolAndIsNamedUnderCode(t *testing.T) {
	const modulePath = "example.com/app"
	dir := rootedProject(t, modulePath)
	linter := mustCoord(t, "example.com/linter", "v0.2.2")
	linterDep := mustCoord(t, "example.com/linterdep", "v1.0.0")
	lib := mustCoord(t, "example.com/lib", "v1.0.0")

	code := rootedWalk(t, "W-code", modulePath, dir, walkdomain.WalkScopeCode, lib)
	tool := rootedWalk(t, "W-tool", modulePath, dir, walkdomain.WalkScopeTool, linter, linterDep)
	tool.Graph.Edges = append(tool.Graph.Edges, walkdomain.GraphEdge{From: linterDep, To: linter})
	// Newest first, as the adapter orders: the code walk is what recency serves.
	walks := selectionStore(code, tool)

	stdout, _, err := runDependentsIn(t, dir, walks, linter, dependentsFlags{tool: true}, false)
	if err != nil {
		t.Fatalf("--tool could not answer about a tool-closure module: %v", err)
	}
	for _, want := range []string{"W-tool", "example.com/linterdep@v1.0.0"} {
		if !strings.Contains(stdout, want) {
			t.Errorf("the --tool answer does not name %q:\n%s", want, stdout)
		}
	}

	stdout, _, err = runDependentsIn(t, dir, walks, linter, dependentsFlags{}, false)
	if err == nil {
		t.Fatalf("the code build does not hold this module and the read answered anyway:\n%s", stdout)
	}
	if strings.Contains(stdout, "No modules") {
		t.Errorf("a module the build does not contain was reported as having no dependents:\n%s", stdout)
	}
	for _, want := range []string{"does not contain", "tool scope", "W-tool", "--tool"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("the refusal does not name %q: %v", want, err)
		}
	}
}

// A rooted question holds a coordinate once, so the ambiguity refusal is
// unreachable from one however many of the caller's projects hold the module.
// This is the 86-of-876 case: both builds hold lib, and standing in one of them
// is not a choice between them.
func TestDependents_RootedQuestionIsNeverAmbiguous(t *testing.T) {
	lib := mustCoord(t, "example.com/lib", "v1.0.0")
	dirA := rootedProject(t, "example.com/a")
	dirB := rootedProject(t, "example.com/b")
	walks := selectionStore(
		rootedWalk(t, "W-b", "example.com/b", dirB, walkdomain.WalkScopeCode, lib),
		rootedWalk(t, "W-a", "example.com/a", dirA, walkdomain.WalkScopeCode, lib),
	)

	for name, tc := range map[string]struct{ dir, wantWalk string }{
		"standing in a": {dirA, "W-a"},
		"standing in b": {dirB, "W-b"},
	} {
		t.Run(name, func(t *testing.T) {
			stdout, _, err := runDependentsIn(t, tc.dir, walks, lib, dependentsFlags{}, false)
			if err != nil {
				var amb *ambiguousBuildRefusal
				if errors.As(err, &amb) {
					t.Fatalf("a rooted question refused for ambiguity: %v", err)
				}
				t.Fatalf("dependentsWith: %v", err)
			}
			if !strings.Contains(stdout, tc.wantWalk) {
				t.Errorf("the answer does not come from %s:\n%s", tc.wantWalk, stdout)
			}
		})
	}

	// The control: the same store, the same coordinate, under --any-build. This
	// is where two builds ARE two answers, and the refusal is the right one.
	_, _, err := runDependentsIn(t, t.TempDir(), walks, lib, dependentsFlags{anyBuild: true}, false)
	var amb *ambiguousBuildRefusal
	if !errors.As(err, &amb) {
		t.Fatalf("--any-build no longer reproduces the multi-build refusal: %v", err)
	}
}

// --walk-id is a record, not a manifest, and it wins from inside a project whose
// own walk would otherwise answer. The control for everything above.
func TestDependents_WalkIDOverridesTheProjectYouAreStandingIn(t *testing.T) {
	const modulePath = "example.com/app"
	dir := rootedProject(t, modulePath)
	lib := mustCoord(t, "example.com/lib", "v1.0.0")
	consumer := mustCoord(t, "example.com/consumer", "v1.0.0")

	code := rootedWalk(t, "W-code", modulePath, dir, walkdomain.WalkScopeCode, lib)
	other := rootedWalk(t, "W-other", "example.com/other", t.TempDir(), walkdomain.WalkScopeCode, lib, consumer)
	other.Graph.Edges = append(other.Graph.Edges, walkdomain.GraphEdge{From: consumer, To: lib})
	walks := selectionStore(code, other)

	stdout, _, err := runDependentsIn(t, dir, walks, lib, dependentsFlags{walkID: "W-other"}, false)
	if err != nil {
		t.Fatalf("dependentsWith: %v", err)
	}
	if !strings.Contains(stdout, "W-other") || strings.Contains(stdout, "W-code") {
		t.Errorf("--walk-id did not override the working directory's own build:\n%s", stdout)
	}
	if !strings.Contains(stdout, "example.com/consumer@v1.0.0") {
		t.Errorf("the named walk's answer is missing:\n%s", stdout)
	}
}

// A flag the dispatch path cannot act on is refused rather than accepted and
// discarded: --tool projects a manifest into a scope, and neither a pinned walk
// nor the store-wide search has a manifest to project.
func TestDependents_ScopeFlagsAreRefusedWhereNoManifestIsRead(t *testing.T) {
	lib := mustCoord(t, "example.com/lib", "v1.0.0")
	app := mustCoord(t, "example.com/app", "v1.0.0")
	walks := containmentFixture(containmentWalk{id: "walk-app", root: app, holds: []coordinate.ModuleCoordinate{lib}})

	for name, f := range map[string]dependentsFlags{
		"pinned walk with --tool":  {walkID: "walk-app", tool: true},
		"pinned walk with --gomod": {walkID: "walk-app", gomod: defaultGoModPath},
		"search with --project":    {anyBuild: true, project: true},
		"pinned walk with search":  {walkID: "walk-app", anyBuild: true},
	} {
		t.Run(name, func(t *testing.T) {
			_, _, err := runDependentsIn(t, t.TempDir(), walks, lib, f, false)
			if err == nil {
				t.Fatal("a flag this path cannot act on was accepted and discarded")
			}
			if !strings.Contains(err.Error(), "does not act on") {
				t.Errorf("the refusal does not say the flag was not acted on: %v", err)
			}
		})
	}
}

// The JSON surface owes the rooting as data. A consumer reading walk_id cannot
// otherwise tell a build the caller named from one the tool searched out, nor a
// code build from a tool one — and those two hold different modules.
func TestDependentsJSON_StatesTheManifestAndScopeThatRootedIt(t *testing.T) {
	const modulePath = "example.com/app"
	dir := rootedProject(t, modulePath)
	lib := mustCoord(t, "example.com/lib", "v1.0.0")
	walks := selectionStore(rootedWalk(t, "W-code", modulePath, dir, walkdomain.WalkScopeCode, lib))

	stdout, _, err := runDependentsIn(t, dir, walks, lib, dependentsFlags{}, true)
	if err != nil {
		t.Fatalf("dependentsWith: %v", err)
	}
	var out struct {
		WalkID        string            `json:"walk_id"`
		WalkSelection walkSelectionJSON `json:"walk_selection"`
	}
	if err := json.Unmarshal([]byte(stdout), &out); err != nil {
		t.Fatalf("decoding: %v\n%s", err, stdout)
	}
	if out.WalkID != "W-code" {
		t.Errorf("walk_id = %q, want W-code", out.WalkID)
	}
	if out.WalkSelection.Rule != string(walkHeldByGoMod) {
		t.Errorf("rule = %q, want %q", out.WalkSelection.Rule, walkHeldByGoMod)
	}
	if out.WalkSelection.Root != "example.com/app@local" {
		t.Errorf("root = %q, want the build the answer is about", out.WalkSelection.Root)
	}
	if !strings.HasSuffix(out.WalkSelection.GoMod, "go.mod") {
		t.Errorf("gomod = %q, want the manifest that named the build", out.WalkSelection.GoMod)
	}
	if out.WalkSelection.Scope != string(scopeCode) {
		t.Errorf("scope = %q, want %q", out.WalkSelection.Scope, scopeCode)
	}
	if out.WalkSelection.Choice == nil {
		t.Fatal("the selector's account of which walk answered is absent, so a JSON reader cannot see what was not checked")
	}
}

// The version leg of the same refusal: a build that pins v1.1.0 does not contain
// v1.0.0, and the caller wants the version it does pin rather than the news that
// their coordinate is absent.
func TestDependents_BuildWithAnotherVersionNamesTheOneItResolved(t *testing.T) {
	const modulePath = "example.com/app"
	dir := rootedProject(t, modulePath)
	walks := selectionStore(rootedWalk(t, "W-code", modulePath, dir, walkdomain.WalkScopeCode,
		mustCoord(t, "example.com/lib", "v1.1.0")))

	_, _, err := runDependentsIn(t, dir, walks, mustCoord(t, "example.com/lib", "v1.0.0"), dependentsFlags{}, false)
	if err == nil {
		t.Fatal("a coordinate the build does not contain was answered")
	}
	for _, want := range []string{"does not contain", "resolved example.com/lib at v1.1.0"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("the refusal does not name %q: %v", want, err)
		}
	}
}
