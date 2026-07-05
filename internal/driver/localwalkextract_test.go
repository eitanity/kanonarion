package driver

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	extractapp "github.com/eitanity/kanonarion/internal/extract/application"
	extractdomain "github.com/eitanity/kanonarion/internal/extract/domain"
	fetchdomain "github.com/eitanity/kanonarion/internal/fetch/domain"
	walkapp "github.com/eitanity/kanonarion/internal/walk/application"
	walkdomain "github.com/eitanity/kanonarion/internal/walk/domain"
)

// fakeWalk records the request it received and returns a canned result/error.
type fakeWalk struct {
	gotReq walkapp.WalkRequest
	rec    walkdomain.WalkRecord
	err    error
}

func (f *fakeWalk) Execute(_ context.Context, req walkapp.WalkRequest) (walkapp.ExecuteWalkResult, error) {
	f.gotReq = req
	if f.err != nil {
		return walkapp.ExecuteWalkResult{}, f.err
	}
	return walkapp.ExecuteWalkResult{Record: f.rec}, nil
}

// fakeExtract records the request it received and returns a canned run/error.
type fakeExtract struct {
	gotReq extractapp.ExtractRequest
	run    extractdomain.ExtractionRun
	err    error
}

func (f *fakeExtract) Execute(_ context.Context, req extractapp.ExtractRequest) (extractdomain.ExtractionRun, error) {
	f.gotReq = req
	if f.err != nil {
		return extractdomain.ExtractionRun{}, f.err
	}
	return f.run, nil
}

// newDriver builds a driver over the fakes with the canonical default stages.
func newDriver(w *fakeWalk, e *fakeExtract) *LocalWalkExtractUseCase {
	uc := &LocalWalkExtractUseCase{
		walk:          w,
		extract:       e,
		defaultStages: []string{"license", "interface", "callgraph", "example"},
	}
	return uc
}

// writeGoMod writes a go.mod with the given module path into a fresh temp dir.
func writeGoMod(t *testing.T, modulePath string) string {
	t.Helper()
	dir := t.TempDir()
	content := "module " + modulePath + "\n\ngo 1.23\n"
	if err := os.WriteFile(filepath.Join(dir, "go.mod"), []byte(content), 0o600); err != nil {
		t.Fatalf("writing go.mod: %v", err)
	}
	return dir
}

func TestRun_HappyPath(t *testing.T) {
	dir := writeGoMod(t, "example.com/widget")
	w := &fakeWalk{rec: walkdomain.WalkRecord{ID: "walk-123"}}
	e := &fakeExtract{run: extractdomain.ExtractionRun{ID: "run-456"}}
	uc := newDriver(w, e)

	res, err := uc.Run(context.Background(), LocalWalkExtractRequest{Dir: dir})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}

	// Walk request: project-rooted at the local module, version "local".
	if w.gotReq.Target.Path != "example.com/widget" {
		t.Errorf("walk target path = %q, want example.com/widget", w.gotReq.Target.Path)
	}
	if w.gotReq.Target.Version != fetchdomain.LocalVersion {
		t.Errorf("walk target version = %q, want %q", w.gotReq.Target.Version, fetchdomain.LocalVersion)
	}
	if !w.gotReq.ProjectMode {
		t.Error("walk request should set ProjectMode")
	}
	if len(w.gotReq.MainModuleGoMod) == 0 {
		t.Error("walk request should carry the main module go.mod bytes")
	}
	if w.gotReq.Scope != walkdomain.WalkScopeComplete {
		t.Errorf("walk scope = %q, want complete", w.gotReq.Scope)
	}

	// Extract request: keyed by the walk ID, default stages.
	if e.gotReq.WalkID != "walk-123" {
		t.Errorf("extract WalkID = %q, want walk-123", e.gotReq.WalkID)
	}
	wantStages := []string{"license", "interface", "callgraph", "example"}
	if !reflect.DeepEqual(e.gotReq.Stages, wantStages) {
		t.Errorf("extract stages = %v, want %v", e.gotReq.Stages, wantStages)
	}

	// Result threads both records through.
	if res.Walk.ID != "walk-123" || res.Extraction.ID != "run-456" {
		t.Errorf("result = walk %q / run %q, want walk-123 / run-456", res.Walk.ID, res.Extraction.ID)
	}
}

func TestRun_ForwardsForceAndExplicitStages(t *testing.T) {
	dir := writeGoMod(t, "example.com/widget")
	w := &fakeWalk{rec: walkdomain.WalkRecord{ID: "w"}}
	e := &fakeExtract{run: extractdomain.ExtractionRun{ID: "r"}}
	uc := newDriver(w, e)

	_, err := uc.Run(context.Background(), LocalWalkExtractRequest{
		Dir:    dir,
		Force:  true,
		Stages: []string{"license"},
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if !w.gotReq.Force {
		t.Error("Force should propagate to the walk request")
	}
	if !e.gotReq.Force {
		t.Error("Force should propagate to the extract request")
	}
	if !reflect.DeepEqual(e.gotReq.Stages, []string{"license"}) {
		t.Errorf("extract stages = %v, want [license]", e.gotReq.Stages)
	}
}

func TestRun_AnalyseLocalRootForwardsProjectDir(t *testing.T) {
	dir := writeGoMod(t, "example.com/widget")
	w := &fakeWalk{rec: walkdomain.WalkRecord{ID: "w"}}
	e := &fakeExtract{run: extractdomain.ExtractionRun{ID: "r"}}
	uc := newDriver(w, e)

	if _, err := uc.Run(context.Background(), LocalWalkExtractRequest{
		Dir:              dir,
		AnalyseLocalRoot: true,
	}); err != nil {
		t.Fatalf("Run: %v", err)
	}
	if !w.gotReq.AnalyseLocalRoot {
		t.Error("AnalyseLocalRoot should propagate to the walk request")
	}
	wantDir, err := filepath.Abs(dir)
	if err != nil {
		t.Fatalf("Abs: %v", err)
	}
	if w.gotReq.ProjectDir != wantDir {
		t.Errorf("ProjectDir = %q, want the absolute working-tree dir %q", w.gotReq.ProjectDir, wantDir)
	}
}

func TestRun_DefaultLeavesRootUnanalysed(t *testing.T) {
	dir := writeGoMod(t, "example.com/widget")
	w := &fakeWalk{rec: walkdomain.WalkRecord{ID: "w"}}
	e := &fakeExtract{run: extractdomain.ExtractionRun{ID: "r"}}
	uc := newDriver(w, e)

	if _, err := uc.Run(context.Background(), LocalWalkExtractRequest{Dir: dir}); err != nil {
		t.Fatalf("Run: %v", err)
	}
	if w.gotReq.AnalyseLocalRoot {
		t.Error("AnalyseLocalRoot must default off (root stays skipped per current behaviour)")
	}
	if w.gotReq.ProjectDir != "" {
		t.Errorf("ProjectDir = %q, want empty when root analysis is off", w.gotReq.ProjectDir)
	}
}

func TestRun_EmptyDirDefaultsToCwd(t *testing.T) {
	dir := writeGoMod(t, "example.com/here")
	t.Chdir(dir) // go1.24 testing helper: restores cwd after the test.

	w := &fakeWalk{rec: walkdomain.WalkRecord{ID: "w"}}
	e := &fakeExtract{run: extractdomain.ExtractionRun{ID: "r"}}
	uc := newDriver(w, e)

	if _, err := uc.Run(context.Background(), LocalWalkExtractRequest{}); err != nil {
		t.Fatalf("Run with empty Dir: %v", err)
	}
	if w.gotReq.Target.Path != "example.com/here" {
		t.Errorf("target path = %q, want example.com/here (cwd go.mod)", w.gotReq.Target.Path)
	}
}

func TestRun_MissingGoModErrors(t *testing.T) {
	uc := newDriver(&fakeWalk{}, &fakeExtract{})
	_, err := uc.Run(context.Background(), LocalWalkExtractRequest{Dir: t.TempDir()})
	if err == nil {
		t.Fatal("expected error when go.mod is absent")
	}
}

func TestRun_GoModWithoutModulePathErrors(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "go.mod"), []byte("go 1.23\n"), 0o600); err != nil {
		t.Fatalf("writing go.mod: %v", err)
	}
	uc := newDriver(&fakeWalk{}, &fakeExtract{})
	_, err := uc.Run(context.Background(), LocalWalkExtractRequest{Dir: dir})
	if err == nil {
		t.Fatal("expected error when go.mod declares no module path")
	}
}

func TestRun_WalkErrorPropagates(t *testing.T) {
	dir := writeGoMod(t, "example.com/widget")
	w := &fakeWalk{err: errors.New("walk boom")}
	e := &fakeExtract{}
	uc := newDriver(w, e)

	_, err := uc.Run(context.Background(), LocalWalkExtractRequest{Dir: dir})
	if err == nil {
		t.Fatal("expected the walk error to propagate")
	}
	if e.gotReq.WalkID != "" {
		t.Error("extract must not run after a walk failure")
	}
}

func TestRun_ExtractErrorPropagates(t *testing.T) {
	dir := writeGoMod(t, "example.com/widget")
	w := &fakeWalk{rec: walkdomain.WalkRecord{ID: "w"}}
	e := &fakeExtract{err: errors.New("extract boom")}
	uc := newDriver(w, e)

	_, err := uc.Run(context.Background(), LocalWalkExtractRequest{Dir: dir})
	if err == nil {
		t.Fatal("expected the extract error to propagate")
	}
}

func TestNewLocalWalkExtractUseCase_CopiesDefaultStages(t *testing.T) {
	stages := []string{"license", "interface"}
	uc := NewLocalWalkExtractUseCase(nil, nil, stages)
	stages[0] = "mutated"
	if uc.defaultStages[0] != "license" {
		t.Errorf("constructor did not copy default stages; got %q after caller mutation", uc.defaultStages[0])
	}
}
