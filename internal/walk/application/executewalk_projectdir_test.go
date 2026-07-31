package application_test

import (
	"context"
	"testing"

	"github.com/eitanity/kanonarion/internal/coordinate"

	application2 "github.com/eitanity/kanonarion/internal/walk/application"
)

// TestExecuteWalkUseCase_ProjectWalkRecordsItsDirectory asserts a walk rooted at
// a local project remembers where it was taken from. Without it, a re-scan by
// walk id has no way back to the tree the project compiles, and the same walk
// answers differently depending on which command scans it.
func TestExecuteWalkUseCase_ProjectWalkRecordsItsDirectory(t *testing.T) {
	const modulePath = "github.com/example/proj"
	projectDir := t.TempDir()

	walker := buildMinimalWalker(t, modulePath, "v1.0.0")
	store := newFakeWalkStore()
	uc := application2.NewExecuteWalkUseCase(walker, store, "test-op", "0.3.0", discardLogger())

	target, err := coordinate.NewLocalCoordinate(modulePath)
	if err != nil {
		t.Fatalf("NewLocalCoordinate: %v", err)
	}
	result, err := uc.Execute(context.Background(), application2.WalkRequest{
		Target:          target,
		ProjectMode:     true,
		MainModuleGoMod: []byte("module " + modulePath + "\n\ngo 1.21\n"),
		ProjectDir:      projectDir,
	})
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if result.Record.ProjectDir != projectDir {
		t.Errorf("ProjectDir = %q, want %q", result.Record.ProjectDir, projectDir)
	}
	if stored := store.walks[result.Record.ID]; stored.ProjectDir != projectDir {
		t.Errorf("persisted ProjectDir = %q, want %q", stored.ProjectDir, projectDir)
	}
}

// TestExecuteWalkUseCase_CoordinateWalkRecordsNoDirectory asserts the empty
// value means what it says. A walk of a published coordinate has no project
// root; recording the operator's working directory there would invent a tree
// nothing was rooted at.
func TestExecuteWalkUseCase_CoordinateWalkRecordsNoDirectory(t *testing.T) {
	walker := buildMinimalWalker(t, "github.com/example/m", "v1.0.0")
	store := newFakeWalkStore()
	uc := application2.NewExecuteWalkUseCase(walker, store, "test-op", "0.3.0", discardLogger())

	result, err := uc.Execute(context.Background(), application2.WalkRequest{
		Target: coord("github.com/example/m", "v1.0.0"),
	})
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if result.Record.ProjectDir != "" {
		t.Errorf("ProjectDir = %q, want empty for a coordinate walk", result.Record.ProjectDir)
	}
}
