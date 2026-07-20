package application_test

import (
	"context"
	"errors"
	"testing"

	"github.com/eitanity/kanonarion/internal/coordinate"

	"github.com/eitanity/kanonarion/internal/local/application"
	"github.com/eitanity/kanonarion/internal/local/domain"
	"github.com/eitanity/kanonarion/internal/local/ports"
)

// -- fakes --

type fakeSnapshotBuilder struct {
	snap domain.Snapshot
	err  error
}

func (f *fakeSnapshotBuilder) Build(_ context.Context, _ string) (domain.Snapshot, error) {
	return f.snap, f.err
}

var _ ports.SnapshotBuilder = (*fakeSnapshotBuilder)(nil)

type fakeImportAnalyser struct {
	modules []domain.ImportedModule
	err     error
}

func (f *fakeImportAnalyser) AnalyseImports(_ context.Context, _ string) ([]domain.ImportedModule, error) {
	return f.modules, f.err
}

var _ ports.ImportAnalyser = (*fakeImportAnalyser)(nil)

type fakeVulnLoader struct {
	findings map[coordinate.ModuleCoordinate][]ports.VulnFinding
	err      error
}

func (f *fakeVulnLoader) LoadFindings(_ context.Context, _ []coordinate.ModuleCoordinate) (map[coordinate.ModuleCoordinate][]ports.VulnFinding, error) {
	return f.findings, f.err
}

var _ ports.VulnFindingLoader = (*fakeVulnLoader)(nil)

type fakeProber struct {
	result ports.SymbolProbeResult
	err    error
	called bool
}

func (f *fakeProber) Probe(_ context.Context, _ string) (ports.SymbolProbeResult, error) {
	f.called = true
	return f.result, f.err
}

var _ ports.SymbolTableProber = (*fakeProber)(nil)

// -- helpers --

func makeSnap(modulePath string) domain.Snapshot {
	return domain.NewSnapshot(map[string][]byte{
		"/ws/go.mod":  []byte("module " + modulePath + "\n\ngo 1.21\n"),
		"/ws/main.go": []byte("package main\nfunc main() {}\n"),
	})
}

func mustCoord(t *testing.T, path, ver string) coordinate.ModuleCoordinate {
	t.Helper()
	c, err := coordinate.NewModuleCoordinate(path, ver)
	if err != nil {
		t.Fatalf("NewModuleCoordinate(%q, %q): %v", path, ver, err)
	}
	return c
}

func makeUC(snap *fakeSnapshotBuilder, imp *fakeImportAnalyser, vuln *fakeVulnLoader, prober *fakeProber) *application.LocalReachabilityUseCase {
	return application.NewLocalReachabilityUseCase(snap, imp, vuln, prober)
}

// -- tests --

func TestLocalReachability_NoFindings_SkipsProbe(t *testing.T) {
	prober := &fakeProber{}
	uc := makeUC(
		&fakeSnapshotBuilder{snap: makeSnap("example.com/app")},
		&fakeImportAnalyser{modules: []domain.ImportedModule{
			{Path: "example.com/dep", Version: "v1.0.0"},
		}},
		&fakeVulnLoader{findings: nil},
		prober,
	)

	result, err := uc.Execute(context.Background(), "/ws")
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if prober.called {
		t.Error("prober was called despite no findings — expected fast-path skip")
	}
	if len(result.Modules) != 0 {
		t.Errorf("Modules = %d, want 0", len(result.Modules))
	}
	if result.ProbeKind != "" {
		t.Errorf("ProbeKind = %q, want empty (probe not run)", result.ProbeKind)
	}
}

func TestLocalReachability_SymbolPresent(t *testing.T) {
	coord := mustCoord(t, "example.com/dep", "v1.0.0")
	uc := makeUC(
		&fakeSnapshotBuilder{snap: makeSnap("example.com/app")},
		&fakeImportAnalyser{modules: []domain.ImportedModule{
			{Path: "example.com/dep", Version: "v1.0.0"},
		}},
		&fakeVulnLoader{findings: map[coordinate.ModuleCoordinate][]ports.VulnFinding{
			coord: {{ID: "GHSA-0001", AffectedSymbols: []string{"Vulnerable"}}},
		}},
		&fakeProber{result: ports.SymbolProbeResult{
			Kind: "library",
			BinarySymbols: map[string]struct{}{
				"example.com/dep.Vulnerable": {},
				"example.com/dep.Other":      {},
			},
		}},
	)

	result, err := uc.Execute(context.Background(), "/ws")
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if len(result.Modules) != 1 {
		t.Fatalf("Modules = %d, want 1", len(result.Modules))
	}
	mod := result.Modules[0]
	if len(mod.Findings) != 1 {
		t.Fatalf("Findings = %d, want 1", len(mod.Findings))
	}
	f := mod.Findings[0]
	if f.Verdict != domain.SymbolProbePresent {
		t.Errorf("Verdict = %q, want %q", f.Verdict, domain.SymbolProbePresent)
	}
	if len(f.MatchedSymbols) != 1 || f.MatchedSymbols[0] != "example.com/dep.Vulnerable" {
		t.Errorf("MatchedSymbols = %v, want [example.com/dep.Vulnerable]", f.MatchedSymbols)
	}
}

func TestLocalReachability_SymbolAbsent(t *testing.T) {
	coord := mustCoord(t, "example.com/dep", "v1.0.0")
	uc := makeUC(
		&fakeSnapshotBuilder{snap: makeSnap("example.com/app")},
		&fakeImportAnalyser{modules: []domain.ImportedModule{
			{Path: "example.com/dep", Version: "v1.0.0"},
		}},
		&fakeVulnLoader{findings: map[coordinate.ModuleCoordinate][]ports.VulnFinding{
			coord: {{ID: "GHSA-0002", AffectedSymbols: []string{"Vulnerable"}}},
		}},
		&fakeProber{result: ports.SymbolProbeResult{
			Kind:          "library",
			BinarySymbols: map[string]struct{}{}, // empty — symbol was eliminated
		}},
	)

	result, err := uc.Execute(context.Background(), "/ws")
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	f := result.Modules[0].Findings[0]
	if f.Verdict != domain.SymbolProbeAbsent {
		t.Errorf("Verdict = %q, want %q", f.Verdict, domain.SymbolProbeAbsent)
	}
	if len(f.MatchedSymbols) != 0 {
		t.Errorf("MatchedSymbols = %v, want nil", f.MatchedSymbols)
	}
}

func TestLocalReachability_NoAffectedSymbols_UnknownVerdict(t *testing.T) {
	coord := mustCoord(t, "example.com/dep", "v1.0.0")
	uc := makeUC(
		&fakeSnapshotBuilder{snap: makeSnap("example.com/app")},
		&fakeImportAnalyser{modules: []domain.ImportedModule{
			{Path: "example.com/dep", Version: "v1.0.0"},
		}},
		&fakeVulnLoader{findings: map[coordinate.ModuleCoordinate][]ports.VulnFinding{
			coord: {{ID: "GHSA-0003", AffectedSymbols: nil}},
		}},
		&fakeProber{result: ports.SymbolProbeResult{
			Kind:          "library",
			BinarySymbols: map[string]struct{}{"example.com/dep.Whatever": {}},
		}},
	)

	result, err := uc.Execute(context.Background(), "/ws")
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	f := result.Modules[0].Findings[0]
	if f.Verdict != domain.SymbolProbeUnknown {
		t.Errorf("Verdict = %q, want %q", f.Verdict, domain.SymbolProbeUnknown)
	}
}

func TestLocalReachability_SubpackageSymbolPresent(t *testing.T) {
	// nm emits "github.com/foo/bar/sub.(*Form).Transform"; the CVE AffectedSymbol is
	// "(*Form).Transform" (govulncheck style, no package qualifier).
	coord := mustCoord(t, "github.com/foo/bar", "v1.0.0")
	uc := makeUC(
		&fakeSnapshotBuilder{snap: makeSnap("example.com/app")},
		&fakeImportAnalyser{modules: []domain.ImportedModule{
			{Path: "github.com/foo/bar", Version: "v1.0.0"},
		}},
		&fakeVulnLoader{findings: map[coordinate.ModuleCoordinate][]ports.VulnFinding{
			coord: {{ID: "GHSA-0004", AffectedSymbols: []string{"(*Form).Transform"}}},
		}},
		&fakeProber{result: ports.SymbolProbeResult{
			Kind: "binary",
			BinarySymbols: map[string]struct{}{
				"github.com/foo/bar/sub.(*Form).Transform": {},
			},
		}},
	)

	result, err := uc.Execute(context.Background(), "/ws")
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	f := result.Modules[0].Findings[0]
	if f.Verdict != domain.SymbolProbePresent {
		t.Errorf("Verdict = %q, want present", f.Verdict)
	}
	if len(f.MatchedSymbols) != 1 || f.MatchedSymbols[0] != "github.com/foo/bar/sub.(*Form).Transform" {
		t.Errorf("MatchedSymbols = %v", f.MatchedSymbols)
	}
}

func TestLocalReachability_DeepSubpackageSymbolPresent(t *testing.T) {
	// Two slashes in the subpackage path: "github.com/foo/bar/a/b.Func"
	coord := mustCoord(t, "github.com/foo/bar", "v1.0.0")
	uc := makeUC(
		&fakeSnapshotBuilder{snap: makeSnap("example.com/app")},
		&fakeImportAnalyser{modules: []domain.ImportedModule{
			{Path: "github.com/foo/bar", Version: "v1.0.0"},
		}},
		&fakeVulnLoader{findings: map[coordinate.ModuleCoordinate][]ports.VulnFinding{
			coord: {{ID: "GHSA-0005", AffectedSymbols: []string{"Func"}}},
		}},
		&fakeProber{result: ports.SymbolProbeResult{
			Kind:          "library",
			BinarySymbols: map[string]struct{}{"github.com/foo/bar/a/b.Func": {}},
		}},
	)

	result, err := uc.Execute(context.Background(), "/ws")
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if result.Modules[0].Findings[0].Verdict != domain.SymbolProbePresent {
		t.Errorf("Verdict = %q, want present", result.Modules[0].Findings[0].Verdict)
	}
}

func TestLocalReachability_UnrelatedSymbolNotMatched(t *testing.T) {
	// A symbol from a different module should never match.
	coord := mustCoord(t, "example.com/dep", "v1.0.0")
	uc := makeUC(
		&fakeSnapshotBuilder{snap: makeSnap("example.com/app")},
		&fakeImportAnalyser{modules: []domain.ImportedModule{
			{Path: "example.com/dep", Version: "v1.0.0"},
		}},
		&fakeVulnLoader{findings: map[coordinate.ModuleCoordinate][]ports.VulnFinding{
			coord: {{ID: "GHSA-0006", AffectedSymbols: []string{"Vulnerable"}}},
		}},
		&fakeProber{result: ports.SymbolProbeResult{
			Kind: "library",
			// Symbol is from a different module that happens to contain the same name.
			BinarySymbols: map[string]struct{}{
				"other.com/pkg.Vulnerable": {},
			},
		}},
	)

	result, err := uc.Execute(context.Background(), "/ws")
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if result.Modules[0].Findings[0].Verdict != domain.SymbolProbeAbsent {
		t.Errorf("Verdict = %q, want absent (different module prefix)", result.Modules[0].Findings[0].Verdict)
	}
}

func TestLocalReachability_MultipleSymbolsOnePresent(t *testing.T) {
	coord := mustCoord(t, "example.com/dep", "v1.0.0")
	uc := makeUC(
		&fakeSnapshotBuilder{snap: makeSnap("example.com/app")},
		&fakeImportAnalyser{modules: []domain.ImportedModule{
			{Path: "example.com/dep", Version: "v1.0.0"},
		}},
		&fakeVulnLoader{findings: map[coordinate.ModuleCoordinate][]ports.VulnFinding{
			coord: {{
				ID:              "GHSA-0007",
				AffectedSymbols: []string{"Gone", "StillHere"},
			}},
		}},
		&fakeProber{result: ports.SymbolProbeResult{
			Kind: "library",
			BinarySymbols: map[string]struct{}{
				"example.com/dep.StillHere": {},
				// "example.com/dep.Gone" is absent — DCE'd
			},
		}},
	)

	result, err := uc.Execute(context.Background(), "/ws")
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	f := result.Modules[0].Findings[0]
	if f.Verdict != domain.SymbolProbePresent {
		t.Errorf("Verdict = %q, want present (one of two symbols present)", f.Verdict)
	}
	if len(f.MatchedSymbols) != 1 || f.MatchedSymbols[0] != "example.com/dep.StillHere" {
		t.Errorf("MatchedSymbols = %v, want [example.com/dep.StillHere]", f.MatchedSymbols)
	}
}

func TestLocalReachability_ModulesAreSorted(t *testing.T) {
	coordA := mustCoord(t, "example.com/aaa", "v1.0.0")
	coordZ := mustCoord(t, "example.com/zzz", "v1.0.0")
	uc := makeUC(
		&fakeSnapshotBuilder{snap: makeSnap("example.com/app")},
		&fakeImportAnalyser{modules: []domain.ImportedModule{
			{Path: "example.com/zzz", Version: "v1.0.0"},
			{Path: "example.com/aaa", Version: "v1.0.0"},
		}},
		&fakeVulnLoader{findings: map[coordinate.ModuleCoordinate][]ports.VulnFinding{
			coordZ: {{ID: "GHSA-Z", AffectedSymbols: []string{"Z"}}},
			coordA: {{ID: "GHSA-A", AffectedSymbols: []string{"A"}}},
		}},
		&fakeProber{result: ports.SymbolProbeResult{Kind: "library", BinarySymbols: map[string]struct{}{}}},
	)

	result, err := uc.Execute(context.Background(), "/ws")
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if len(result.Modules) != 2 {
		t.Fatalf("Modules = %d, want 2", len(result.Modules))
	}
	if result.Modules[0].Path != "example.com/aaa" {
		t.Errorf("Modules[0].Path = %q, want example.com/aaa", result.Modules[0].Path)
	}
	if result.Modules[1].Path != "example.com/zzz" {
		t.Errorf("Modules[1].Path = %q, want example.com/zzz", result.Modules[1].Path)
	}
}

func TestLocalReachability_ResultFieldsPopulated(t *testing.T) {
	coord := mustCoord(t, "example.com/dep", "v1.0.0")
	uc := makeUC(
		&fakeSnapshotBuilder{snap: makeSnap("example.com/app")},
		&fakeImportAnalyser{modules: []domain.ImportedModule{
			{Path: "example.com/dep", Version: "v1.0.0"},
		}},
		&fakeVulnLoader{findings: map[coordinate.ModuleCoordinate][]ports.VulnFinding{
			coord: {{
				ID:              "GHSA-0008",
				Aliases:         []string{"CVE-2024-0001"},
				Summary:         "A bad bug",
				AffectedSymbols: []string{"Bad"},
			}},
		}},
		&fakeProber{result: ports.SymbolProbeResult{
			Kind:          "binary",
			BinarySymbols: map[string]struct{}{"example.com/dep.Bad": {}},
		}},
	)

	result, err := uc.Execute(context.Background(), "/ws")
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if result.Root != "/ws" {
		t.Errorf("Root = %q, want /ws", result.Root)
	}
	if result.ModulePath != "example.com/app" {
		t.Errorf("ModulePath = %q, want example.com/app", result.ModulePath)
	}
	if result.ProbeKind != "binary" {
		t.Errorf("ProbeKind = %q, want binary", result.ProbeKind)
	}
	f := result.Modules[0].Findings[0]
	if f.CVEID != "GHSA-0008" {
		t.Errorf("CVEID = %q, want GHSA-0008", f.CVEID)
	}
	if len(f.Aliases) != 1 || f.Aliases[0] != "CVE-2024-0001" {
		t.Errorf("Aliases = %v", f.Aliases)
	}
	if f.Summary != "A bad bug" {
		t.Errorf("Summary = %q, want 'A bad bug'", f.Summary)
	}
}

// -- error propagation --

func TestLocalReachability_SnapshotError(t *testing.T) {
	snapErr := errors.New("disk read failed")
	uc := makeUC(
		&fakeSnapshotBuilder{err: snapErr},
		&fakeImportAnalyser{},
		&fakeVulnLoader{},
		&fakeProber{},
	)
	_, err := uc.Execute(context.Background(), "/ws")
	if !errors.Is(err, snapErr) {
		t.Errorf("error = %v, want wrapping %v", err, snapErr)
	}
}

func TestLocalReachability_ImportAnalyserError(t *testing.T) {
	impErr := errors.New("go list failed")
	uc := makeUC(
		&fakeSnapshotBuilder{snap: makeSnap("example.com/app")},
		&fakeImportAnalyser{err: impErr},
		&fakeVulnLoader{},
		&fakeProber{},
	)
	_, err := uc.Execute(context.Background(), "/ws")
	if !errors.Is(err, impErr) {
		t.Errorf("error = %v, want wrapping %v", err, impErr)
	}
}

func TestLocalReachability_VulnLoaderError(t *testing.T) {
	loadErr := errors.New("store unavailable")
	uc := makeUC(
		&fakeSnapshotBuilder{snap: makeSnap("example.com/app")},
		&fakeImportAnalyser{modules: []domain.ImportedModule{
			{Path: "example.com/dep", Version: "v1.0.0"},
		}},
		&fakeVulnLoader{err: loadErr},
		&fakeProber{},
	)
	_, err := uc.Execute(context.Background(), "/ws")
	if !errors.Is(err, loadErr) {
		t.Errorf("error = %v, want wrapping %v", err, loadErr)
	}
}

func TestLocalReachability_ProberError(t *testing.T) {
	coord := mustCoord(t, "example.com/dep", "v1.0.0")
	probeErr := errors.New("build failed")
	uc := makeUC(
		&fakeSnapshotBuilder{snap: makeSnap("example.com/app")},
		&fakeImportAnalyser{modules: []domain.ImportedModule{
			{Path: "example.com/dep", Version: "v1.0.0"},
		}},
		&fakeVulnLoader{findings: map[coordinate.ModuleCoordinate][]ports.VulnFinding{
			coord: {{ID: "GHSA-X", AffectedSymbols: []string{"Sym"}}},
		}},
		&fakeProber{err: probeErr},
	)
	_, err := uc.Execute(context.Background(), "/ws")
	if !errors.Is(err, probeErr) {
		t.Errorf("error = %v, want wrapping %v", err, probeErr)
	}
}
