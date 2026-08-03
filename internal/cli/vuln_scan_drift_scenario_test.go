package cli

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/eitanity/kanonarion/internal/cli/testfakes"
	walkapp "github.com/eitanity/kanonarion/internal/walk/application"
	walkdomain "github.com/eitanity/kanonarion/internal/walk/domain"
	walkports "github.com/eitanity/kanonarion/internal/walk/ports"
)

// driftScenarioProject is the fixture the scenario edits: a module whose one
// dependency is required at a version and replaced by a directory beside it.
//
// The replace is what makes the sequence run anywhere, offline: the toolchain
// still reports the REQUIRED version for the dependency, so changing one line of
// go.mod changes what the manifest resolves to without a proxy, a module cache,
// or a network. Editing that line is the reproduction's `go get`.
type driftScenarioProject struct {
	gomodPath string
}

func newDriftScenarioProject(t *testing.T) driftScenarioProject {
	t.Helper()
	dir := t.TempDir()
	write := func(name, content string) {
		t.Helper()
		if err := os.MkdirAll(filepath.Dir(filepath.Join(dir, name)), 0o750); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write("main.go", "package app\n\nimport _ \"example.com/dep\"\n")
	write("dep/go.mod", "module example.com/dep\n\ngo 1.24\n")
	write("dep/dep.go", "package dep\n")
	p := driftScenarioProject{gomodPath: filepath.Join(dir, "go.mod")}
	p.require(t, "v1.0.0")
	return p
}

// require rewrites the manifest to depend on the fixture module at version.
func (p driftScenarioProject) require(t *testing.T, version string) {
	t.Helper()
	gomod := "module example.com/app\n\ngo 1.24\n\nrequire example.com/dep " + version +
		"\n\nreplace example.com/dep => ./dep\n"
	if err := os.WriteFile(p.gomodPath, []byte(gomod), 0o600); err != nil {
		t.Fatal(err)
	}
}

// driftScenarioWalks stands in for the walk machinery's identity reuse: a walk
// of a resolution already recorded IS that walk, so the store gains no record
// and the walk id comes back unchanged.
//
// Modelling it is the point of the third step. The convergence claim — edit,
// scan, revert, and the original run answers again — is a claim about identity
// reuse, and a fake that always minted a new id would let a broken convergence
// pass.
type driftScenarioWalks struct {
	store *testfakes.FakeQueryWalks
	// byRequire maps the version the manifest requires to the walk that recorded
	// that resolution.
	byRequire map[string]walkdomain.WalkRecord
	// gomodPath is the manifest the fake reads, so its answer depends on the tree
	// exactly as the real walk's does.
	gomodPath string
	calls     int
}

func (w *driftScenarioWalks) Execute(_ context.Context, req walkapp.WalkRequest) (walkapp.ExecuteWalkResult, error) {
	w.calls++
	data, err := os.ReadFile(filepath.Clean(w.gomodPath))
	if err != nil {
		return walkapp.ExecuteWalkResult{}, fmt.Errorf("reading the scenario manifest: %w", err)
	}
	for version, rec := range w.byRequire {
		if strings.Contains(string(data), "example.com/dep "+version) {
			w.store.SetSummaries([]walkports.WalkSummary{{ID: rec.ID}})
			return walkapp.ExecuteWalkResult{Record: rec, Reused: !req.Force}, nil
		}
	}
	return walkapp.ExecuteWalkResult{}, fmt.Errorf("no scenario walk for this manifest: %w", os.ErrNotExist)
}

var _ ExecuteWalkUseCase = (*driftScenarioWalks)(nil)

// TestVulnScanScope_EditedManifestIsNotAnsweredFromTheStoredWalk walks the
// reported sequence end to end, through the decision the warm serve depends on:
//
//	1 — an untouched manifest resolves to the stored walk, so the scan answers
//	    from it and its stored run is served, exactly as before;
//	2 — one edited require line, and the stored walk is no longer answered from:
//	    the drift is named with both versions and the scan is re-pointed at a
//	    walk of the build that is actually on disk;
//	3 — the edit reverted, and the original walk answers again — so the original
//	    run serves warm — without a re-measurement.
//
// Step 2 is the defect. Before the comparison existed the scan answered step 2
// from the step-1 walk at exit 0, printing the pre-edit build's coordinates.
func TestVulnScanScope_EditedManifestIsNotAnsweredFromTheStoredWalk(t *testing.T) {
	project := newDriftScenarioProject(t)

	before := driftWalk("walk-before", depNode("example.com/dep@v1.0.0"))
	after := driftWalk("walk-after", depNode("example.com/dep@v1.0.1"))
	store := testfakes.NewFakeQueryWalks()
	store.AddWalk(before)
	store.AddWalk(after)
	walker := &driftScenarioWalks{
		store:     store,
		byRequire: map[string]walkdomain.WalkRecord{"v1.0.0": before, "v1.0.1": after},
	}
	walker.gomodPath = project.gomodPath
	ctr := &Container{QueryWalks: store, ExecuteWalk: walker}

	decide := func(t *testing.T, selected string) (string, string) {
		t.Helper()
		var stderr bytes.Buffer
		walkID, err := scanWalkForCurrentManifest(t.Context(), ctr,
			walkports.WalkSummary{ID: selected}, project.gomodPath, scopeCode, vulnScanFlags{}, &stderr)
		if err != nil {
			t.Fatalf("scanWalkForCurrentManifest: %v", err)
		}
		return walkID, stderr.String()
	}

	// 1 — untouched.
	walkID, narration := decide(t, before.ID)
	if walkID != before.ID {
		t.Fatalf("an untouched manifest was answered from walk %q, want %q", walkID, before.ID)
	}
	if walker.calls != 0 {
		t.Fatalf("an untouched manifest drove %d re-walk(s)", walker.calls)
	}
	if !strings.Contains(narration, "manifest re-resolved") {
		t.Errorf("the served answer does not state what it checked: %q", narration)
	}

	// 2 — one require line edited. The store still holds the step-1 walk and its
	// run; neither may answer.
	project.require(t, "v1.0.1")
	walkID, narration = decide(t, before.ID)
	if walkID == before.ID {
		t.Fatalf("the edited manifest was answered from the pre-edit walk %q", before.ID)
	}
	if walkID != after.ID {
		t.Fatalf("the edited manifest was answered from walk %q, want %q", walkID, after.ID)
	}
	if !strings.Contains(narration, "no longer resolves to walk "+before.ID) ||
		!strings.Contains(narration, "example.com/dep v1.0.0 -> v1.0.1") {
		t.Errorf("the drift was not named as the reason: %q", narration)
	}

	// 3 — reverted. The newest walk is now the step-2 one, so the check drifts
	// again and the re-walk converges by identity onto the original.
	project.require(t, "v1.0.0")
	callsBefore := walker.calls
	walkID, narration = decide(t, after.ID)
	if walkID != before.ID {
		t.Fatalf("the reverted manifest was answered from walk %q, want the original %q", walkID, before.ID)
	}
	if walker.calls != callsBefore+1 {
		t.Errorf("the revert drove %d re-walk(s), want exactly 1", walker.calls-callsBefore)
	}
	if !strings.Contains(narration, "example.com/dep v1.0.1 -> v1.0.0") {
		t.Errorf("the revert's own drift was not named: %q", narration)
	}
}
