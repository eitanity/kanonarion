package application_test

import (
	"context"
	"testing"

	"github.com/eitanity/kanonarion/internal/coordinate"

	application2 "github.com/eitanity/kanonarion/internal/walk/application"
)

// projectWalkRequest is the request `audit` and `walk --gomod` make: a project
// walk rooted at the local main module, which deliberately re-resolves the
// working tree on every run instead of taking the succeeded-walk cache.
func projectWalkRequest(t testing.TB, modulePath, projectDir, goMod string) application2.WalkRequest {
	t.Helper()
	target, err := coordinate.NewLocalCoordinate(modulePath)
	if err != nil {
		t.Fatalf("NewLocalCoordinate: %v", err)
	}
	if goMod == "" {
		goMod = "module " + modulePath + "\n\ngo 1.21\n"
	}
	return application2.WalkRequest{
		Target:          target,
		ProjectMode:     true,
		MainModuleGoMod: []byte(goMod),
		ProjectDir:      projectDir,
	}
}

// projectGoMod is the working tree's go.mod requiring one dependency, so two
// spellings of it stand in for an edit between runs.
func projectGoMod(modulePath, depPath, depVersion string) string {
	return "module " + modulePath + "\n\ngo 1.21\n\nrequire " + depPath + " " + depVersion + "\n"
}

// buildProjectWalker constructs a walker for a project that requires one
// dependency at depVersion, so two calls with different versions stand in for a
// go.mod edit between runs.
func buildProjectWalker(t testing.TB, modulePath, depPath, depVersion string) *application2.Walker {
	t.Helper()
	blobs := newFakeBlobStore()
	rf := newFakeFetcher()
	rf.add(t, modulePath, "v1.0.0",
		"module "+modulePath+"\ngo 1.21\nrequire "+depPath+" "+depVersion+"\n", blobs)
	rf.add(t, depPath, depVersion, "module "+depPath+"\ngo 1.21\n", blobs)

	wf := newWalkerFetcher()
	wf.addRecord(t, modulePath, "v1.0.0")
	wf.addRecord(t, depPath, depVersion)

	return buildWalker(rf, wf, blobs, 1)
}

// TestExecuteWalkUseCase_UnchangedProjectYieldsOneWalk is the regression: two
// consecutive walks of an unchanged checkout must leave ONE walk behind, and the
// second must say it reused the first.
//
// Before this, the project path re-resolved the tree (correctly — the tree can
// change) and then minted a new id for the identical result. Every record keyed
// on the walk id — licences, vulnerability verdicts, SBOMs — became unreachable
// from the next run, so the tool re-derived a full scan because its own cache
// key was fresh by construction rather than because anything had changed.
func TestExecuteWalkUseCase_UnchangedProjectYieldsOneWalk(t *testing.T) {
	const modulePath = "github.com/example/proj"
	projectDir := t.TempDir()

	walker := buildMinimalWalker(t, modulePath, "v1.0.0")
	store := newFakeWalkStore()
	uc := application2.NewExecuteWalkUseCase(walker, store, "test-op", "0.3.0", discardLogger())
	req := projectWalkRequest(t, modulePath, projectDir, "")

	first, err := uc.Execute(context.Background(), req)
	if err != nil {
		t.Fatalf("first Execute: %v", err)
	}
	if first.Reused {
		t.Error("the first walk of a project reported reuse; there was nothing to reuse")
	}
	if first.Record.IdentityHash == "" {
		t.Fatal("the first walk recorded no identity, so nothing can ever match it")
	}

	second, err := uc.Execute(context.Background(), req)
	if err != nil {
		t.Fatalf("second Execute: %v", err)
	}
	if !second.Reused {
		t.Error("the second walk of an unchanged project did not report reuse")
	}
	if second.Record.ID != first.Record.ID {
		t.Errorf("the second walk minted a new id: %s, want %s", second.Record.ID, first.Record.ID)
	}
	if len(store.walks) != 1 {
		t.Errorf("two walks of an unchanged project left %d records, want 1", len(store.walks))
	}
}

// TestExecuteWalkUseCase_ChangedProjectYieldsANewWalk is the other half. Reuse
// that cannot tell a changed project from an unchanged one would serve a stale
// dependency set as the current one, which is worse than the cost it saves.
func TestExecuteWalkUseCase_ChangedProjectYieldsANewWalk(t *testing.T) {
	const modulePath = "github.com/example/proj"
	projectDir := t.TempDir()

	store := newFakeWalkStore()

	const depPath = "github.com/example/dep"

	// First walk: the project resolves one dependency version.
	firstWalker := buildProjectWalker(t, modulePath, depPath, "v1.0.0")
	firstUC := application2.NewExecuteWalkUseCase(firstWalker, store, "test-op", "0.3.0", discardLogger())
	first, err := firstUC.Execute(context.Background(),
		projectWalkRequest(t, modulePath, projectDir, projectGoMod(modulePath, depPath, "v1.0.0")))
	if err != nil {
		t.Fatalf("first Execute: %v", err)
	}

	// Second walk: the go.mod now selects a different version of that dependency.
	secondWalker := buildProjectWalker(t, modulePath, depPath, "v2.0.0")
	secondUC := application2.NewExecuteWalkUseCase(secondWalker, store, "test-op", "0.3.0", discardLogger())
	second, err := secondUC.Execute(context.Background(),
		projectWalkRequest(t, modulePath, projectDir, projectGoMod(modulePath, depPath, "v2.0.0")))
	if err != nil {
		t.Fatalf("second Execute: %v", err)
	}

	if second.Reused {
		t.Error("a project whose dependency version changed reported a reused walk")
	}
	if second.Record.ID == first.Record.ID {
		t.Error("a changed project reused the previous walk id")
	}
	if second.Record.IdentityHash == first.Record.IdentityHash {
		t.Errorf("a changed project produced the same walk identity: %s", second.Record.IdentityHash)
	}
	if len(store.walks) != 2 {
		t.Errorf("a changed project left %d walk records, want 2", len(store.walks))
	}
}

// TestExecuteWalkUseCase_ForceRewalksAnIdenticalProject pins the opt-out. An
// operator gathering release evidence asked for a measurement, and identity
// reuse must not quietly answer with an older one.
func TestExecuteWalkUseCase_ForceRewalksAnIdenticalProject(t *testing.T) {
	const modulePath = "github.com/example/proj"
	projectDir := t.TempDir()

	walker := buildMinimalWalker(t, modulePath, "v1.0.0")
	store := newFakeWalkStore()
	uc := application2.NewExecuteWalkUseCase(walker, store, "test-op", "0.3.0", discardLogger())

	req := projectWalkRequest(t, modulePath, projectDir, "")
	first, err := uc.Execute(context.Background(), req)
	if err != nil {
		t.Fatalf("first Execute: %v", err)
	}

	req.Force = true
	second, err := uc.Execute(context.Background(), req)
	if err != nil {
		t.Fatalf("forced Execute: %v", err)
	}
	if second.Reused {
		t.Error("--force served a reused walk")
	}
	if second.Record.ID == first.Record.ID {
		t.Error("--force did not mint a new walk")
	}
	if len(store.walks) != 2 {
		t.Errorf("--force left %d walk records, want 2", len(store.walks))
	}
}
