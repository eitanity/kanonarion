package application_test

import (
	"context"
	"errors"
	"testing"

	"github.com/eitanity/kanonarion/internal/local/application"
	"github.com/eitanity/kanonarion/internal/local/domain"
	"github.com/eitanity/kanonarion/internal/local/ports"
)

// fakeSymbolAnalyser implements ports.SymbolAnalyser for tests.
type fakeSymbolAnalyser struct {
	modules []domain.ImportedModule
	err     error
}

func (f *fakeSymbolAnalyser) AnalyseSymbols(_ context.Context, _ string) ([]domain.ImportedModule, error) {
	return f.modules, f.err
}

var _ ports.SymbolAnalyser = (*fakeSymbolAnalyser)(nil)

// snapWithMod builds a fake Snapshot that contains a go.mod for the given module path.
func snapWithMod(modulePath string) domain.Snapshot {
	return domain.NewSnapshot(map[string][]byte{
		"/ws/go.mod":  []byte("module " + modulePath + "\n\ngo 1.21\n"),
		"/ws/main.go": []byte("package main\nfunc main() {}\n"),
	})
}

// -- tests --

func TestLocalContextUseCase_Execute_ImportLevel(t *testing.T) {
	uc := application.NewLocalContextUseCase(
		&fakeSnapshotBuilder{snap: snapWithMod("example.com/app")},
		&fakeImportAnalyser{modules: []domain.ImportedModule{
			{Path: "example.com/dep", Version: "v1.0.0", ImportedPackages: []string{"example.com/dep/pkg"}},
		}},
		nil,
	)

	got, err := uc.Execute(context.Background(), application.LocalContextRequest{
		Root:          "/ws",
		AnalysisLevel: domain.AnalysisLevelImport,
	})
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if got.Root != "/ws" {
		t.Errorf("Root = %q, want /ws", got.Root)
	}
	if got.ModulePath != "example.com/app" {
		t.Errorf("ModulePath = %q, want example.com/app", got.ModulePath)
	}
	if got.AnalysisLevel != domain.AnalysisLevelImport {
		t.Errorf("AnalysisLevel = %q, want import", got.AnalysisLevel)
	}
	if len(got.Modules) != 1 {
		t.Fatalf("Modules = %d, want 1", len(got.Modules))
	}
	if got.Modules[0].Path != "example.com/dep" {
		t.Errorf("Modules[0].Path = %q", got.Modules[0].Path)
	}
}

func TestLocalContextUseCase_Execute_DefaultLevelIsImport(t *testing.T) {
	importCalled := false
	analyser := &fakeImportAnalyser{}
	analyser2 := &callTrackingImportAnalyser{delegate: analyser, called: &importCalled}

	uc := application.NewLocalContextUseCase(
		&fakeSnapshotBuilder{snap: snapWithMod("example.com/app")},
		analyser2,
		nil,
	)

	got, err := uc.Execute(context.Background(), application.LocalContextRequest{Root: "/ws"})
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if got.AnalysisLevel != domain.AnalysisLevelImport {
		t.Errorf("AnalysisLevel = %q, want import (default)", got.AnalysisLevel)
	}
	if !importCalled {
		t.Error("ImportAnalyser not called for default level")
	}
}

func TestLocalContextUseCase_Execute_SymbolLevel(t *testing.T) {
	uc := application.NewLocalContextUseCase(
		&fakeSnapshotBuilder{snap: snapWithMod("example.com/app")},
		&fakeImportAnalyser{},
		&fakeSymbolAnalyser{modules: []domain.ImportedModule{
			{Path: "example.com/dep", Version: "v1.0.0", UsedSymbols: []string{"example.com/dep.Func"}},
		}},
	)

	got, err := uc.Execute(context.Background(), application.LocalContextRequest{
		Root:          "/ws",
		AnalysisLevel: domain.AnalysisLevelSymbol,
	})
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if got.AnalysisLevel != domain.AnalysisLevelSymbol {
		t.Errorf("AnalysisLevel = %q, want symbol", got.AnalysisLevel)
	}
	if len(got.Modules) != 1 || len(got.Modules[0].UsedSymbols) != 1 {
		t.Errorf("Modules = %+v", got.Modules)
	}
}

func TestLocalContextUseCase_Execute_SymbolLevelWithNilAnalyser_Error(t *testing.T) {
	uc := application.NewLocalContextUseCase(
		&fakeSnapshotBuilder{snap: snapWithMod("example.com/app")},
		&fakeImportAnalyser{},
		nil, // no symbol analyser
	)

	_, err := uc.Execute(context.Background(), application.LocalContextRequest{
		Root:          "/ws",
		AnalysisLevel: domain.AnalysisLevelSymbol,
	})
	if err == nil {
		t.Fatal("expected error when symbol analyser is nil")
	}
}

func TestLocalContextUseCase_Execute_ModulesAreSorted(t *testing.T) {
	uc := application.NewLocalContextUseCase(
		&fakeSnapshotBuilder{snap: snapWithMod("example.com/app")},
		&fakeImportAnalyser{modules: []domain.ImportedModule{
			{Path: "github.com/z/z", Version: "v1.0.0"},
			{Path: "github.com/a/a", Version: "v1.0.0"},
			{Path: "github.com/m/m", Version: "v1.0.0"},
		}},
		nil,
	)

	got, err := uc.Execute(context.Background(), application.LocalContextRequest{Root: "/ws"})
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	want := []string{"github.com/a/a", "github.com/m/m", "github.com/z/z"}
	for i, m := range got.Modules {
		if m.Path != want[i] {
			t.Errorf("Modules[%d].Path = %q, want %q", i, m.Path, want[i])
		}
	}
}

func TestLocalContextUseCase_Execute_VersionIDPopulated(t *testing.T) {
	uc := application.NewLocalContextUseCase(
		&fakeSnapshotBuilder{snap: snapWithMod("example.com/app")},
		&fakeImportAnalyser{},
		nil,
	)

	got, err := uc.Execute(context.Background(), application.LocalContextRequest{Root: "/ws"})
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if got.VersionID == "" {
		t.Error("VersionID should be populated from snapshot")
	}
}

// -- error propagation --

func TestLocalContextUseCase_Execute_SnapshotError(t *testing.T) {
	snapErr := errors.New("disk read failed")
	uc := application.NewLocalContextUseCase(
		&fakeSnapshotBuilder{err: snapErr},
		&fakeImportAnalyser{},
		nil,
	)
	_, err := uc.Execute(context.Background(), application.LocalContextRequest{Root: "/ws"})
	if !errors.Is(err, snapErr) {
		t.Errorf("error = %v, want wrapping %v", err, snapErr)
	}
}

func TestLocalContextUseCase_Execute_MissingGoMod_Error(t *testing.T) {
	uc := application.NewLocalContextUseCase(
		&fakeSnapshotBuilder{snap: domain.NewSnapshot(map[string][]byte{
			"/ws/main.go": []byte("package main"),
			// no go.mod
		})},
		&fakeImportAnalyser{},
		nil,
	)
	_, err := uc.Execute(context.Background(), application.LocalContextRequest{Root: "/ws"})
	if err == nil {
		t.Fatal("expected error when snapshot has no go.mod")
	}
}

func TestLocalContextUseCase_Execute_ImportAnalyserError(t *testing.T) {
	impErr := errors.New("go list failed")
	uc := application.NewLocalContextUseCase(
		&fakeSnapshotBuilder{snap: snapWithMod("example.com/app")},
		&fakeImportAnalyser{err: impErr},
		nil,
	)
	_, err := uc.Execute(context.Background(), application.LocalContextRequest{Root: "/ws"})
	if !errors.Is(err, impErr) {
		t.Errorf("error = %v, want wrapping %v", err, impErr)
	}
}

func TestLocalContextUseCase_Execute_SymbolAnalyserError(t *testing.T) {
	symErr := errors.New("packages load failed")
	uc := application.NewLocalContextUseCase(
		&fakeSnapshotBuilder{snap: snapWithMod("example.com/app")},
		&fakeImportAnalyser{},
		&fakeSymbolAnalyser{err: symErr},
	)
	_, err := uc.Execute(context.Background(), application.LocalContextRequest{
		Root:          "/ws",
		AnalysisLevel: domain.AnalysisLevelSymbol,
	})
	if !errors.Is(err, symErr) {
		t.Errorf("error = %v, want wrapping %v", err, symErr)
	}
}

// -- helper: call-tracking import analyser --

type callTrackingImportAnalyser struct {
	delegate *fakeImportAnalyser
	called   *bool
}

func (c *callTrackingImportAnalyser) AnalyseImports(ctx context.Context, root string) ([]domain.ImportedModule, error) {
	*c.called = true
	return c.delegate.AnalyseImports(ctx, root)
}

var _ ports.ImportAnalyser = (*callTrackingImportAnalyser)(nil)
