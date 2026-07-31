package application_test

import (
	"context"
	"errors"
	"testing"
	"time"

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

type fakeBuildLister struct {
	modules []domain.BuildModule
	err     error
}

func (f *fakeBuildLister) BuildModules(_ context.Context, _ string) ([]domain.BuildModule, error) {
	return f.modules, f.err
}

var _ ports.BuildModuleLister = (*fakeBuildLister)(nil)

type fakeVulnLoader struct {
	findings map[coordinate.ModuleCoordinate][]ports.VulnFinding
	// scanned is the extra set of coordinates the store holds a record for but
	// no findings against. Coordinates in findings are always scanned.
	scanned []coordinate.ModuleCoordinate
	err     error
}

// LoadFindings answers ONLY about the coordinates it was asked about. A fake
// that returned its whole table regardless of the query would answer for
// modules the caller never queried, and a narrowing bug in the caller would
// pass every test in this file.
func (f *fakeVulnLoader) LoadFindings(_ context.Context, coords []coordinate.ModuleCoordinate) (ports.FindingSet, error) {
	if f.err != nil {
		return ports.FindingSet{}, f.err
	}
	asked := make(map[coordinate.ModuleCoordinate]struct{}, len(coords))
	for _, c := range coords {
		asked[c] = struct{}{}
	}
	set := ports.FindingSet{
		Findings: make(map[coordinate.ModuleCoordinate][]ports.VulnFinding),
		Scanned:  make(map[coordinate.ModuleCoordinate]struct{}),
	}
	for c, fs := range f.findings {
		if _, ok := asked[c]; !ok {
			continue
		}
		set.Findings[c] = fs
		set.Scanned[c] = struct{}{}
	}
	for _, c := range f.scanned {
		if _, ok := asked[c]; !ok {
			continue
		}
		set.Scanned[c] = struct{}{}
	}
	return set, nil
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

// fixedClock pins the snapshot stamp so it is a measurement rather than
// whatever the wall clock read.
type fixedClock struct{ t time.Time }

func (c fixedClock) Now() time.Time { return c.t }

var _ ports.Clock = fixedClock{}

var testClockInstant = time.Date(2026, 7, 31, 12, 0, 0, 0, time.UTC)

func makeUC(snap *fakeSnapshotBuilder, build *fakeBuildLister, vuln *fakeVulnLoader, prober *fakeProber) *application.LocalReachabilityUseCase {
	return application.NewLocalReachabilityUseCase(snap, build, vuln, prober, fixedClock{t: testClockInstant})
}

// -- tests --

func TestLocalReachability_NoFindings_SkipsProbe(t *testing.T) {
	prober := &fakeProber{}
	uc := makeUC(
		&fakeSnapshotBuilder{snap: makeSnap("example.com/app")},
		&fakeBuildLister{modules: []domain.BuildModule{
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
		&fakeBuildLister{modules: []domain.BuildModule{
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
		&fakeBuildLister{modules: []domain.BuildModule{
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
		&fakeBuildLister{modules: []domain.BuildModule{
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
		&fakeBuildLister{modules: []domain.BuildModule{
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
		&fakeBuildLister{modules: []domain.BuildModule{
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
		&fakeBuildLister{modules: []domain.BuildModule{
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
		&fakeBuildLister{modules: []domain.BuildModule{
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
		&fakeBuildLister{modules: []domain.BuildModule{
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
		&fakeBuildLister{modules: []domain.BuildModule{
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
		&fakeBuildLister{},
		&fakeVulnLoader{},
		&fakeProber{},
	)
	_, err := uc.Execute(context.Background(), "/ws")
	if !errors.Is(err, snapErr) {
		t.Errorf("error = %v, want wrapping %v", err, snapErr)
	}
}

func TestLocalReachability_BuildListerError(t *testing.T) {
	impErr := errors.New("go list failed")
	uc := makeUC(
		&fakeSnapshotBuilder{snap: makeSnap("example.com/app")},
		&fakeBuildLister{err: impErr},
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
		&fakeBuildLister{modules: []domain.BuildModule{
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
		&fakeBuildLister{modules: []domain.BuildModule{
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

// -- coverage disclosure --

// The probe reads the symbol table of a binary containing the WHOLE build, so
// its finding lookup must be scoped to the whole build too. Scoped to direct
// imports it answered about a smaller set than the artefact it measured and said
// nothing about the difference: measured on a real project, a JWT library
// reached only through a SAML library was absent from the answer entirely, even
// though the store held an Affected finding against exactly that coordinate.
func TestLocalReachability_TransitiveModuleWithFindingIsCovered(t *testing.T) {
	transitive := mustCoord(t, "github.com/golang-jwt/jwt/v4", "v4.5.1")
	uc := makeUC(
		&fakeSnapshotBuilder{snap: makeSnap("example.com/app")},
		&fakeBuildLister{modules: []domain.BuildModule{
			{Path: "github.com/crewjam/saml", Version: "v0.4.0", Direct: true},
			{Path: "github.com/golang-jwt/jwt/v4", Version: "v4.5.1"},
		}},
		&fakeVulnLoader{
			findings: map[coordinate.ModuleCoordinate][]ports.VulnFinding{
				transitive: {{ID: "GO-2025-3553", AffectedSymbols: []string{"Parser.ParseUnverified"}}},
			},
			scanned: []coordinate.ModuleCoordinate{mustCoord(t, "github.com/crewjam/saml", "v0.4.0")},
		},
		&fakeProber{result: ports.SymbolProbeResult{
			Kind:          "binary",
			BinarySymbols: map[string]struct{}{"github.com/golang-jwt/jwt/v4.Parser.ParseUnverified": {}},
		}},
	)

	result, err := uc.Execute(context.Background(), "/ws")
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	var found bool
	for _, m := range result.Modules {
		if m.Path == "github.com/golang-jwt/jwt/v4" {
			found = true
		}
	}
	if !found {
		t.Fatalf("transitive module with a stored finding is missing from the answer: %+v", result.Modules)
	}
	if result.Coverage.BuildModules != 2 || result.Coverage.Queried != 2 {
		t.Errorf("coverage = %+v, want both build modules queried", result.Coverage)
	}
	if len(result.Coverage.Uncovered) != 0 {
		t.Errorf("Uncovered = %+v, want none (both modules have records)", result.Coverage.Uncovered)
	}
}

// A module in the build the store holds no record for is named, with its reason
// and a route to a wider answer. Omitting it silently is what made a ten-module
// reply indistinguishable from a complete one.
func TestLocalReachability_UnscannedBuildModuleIsNamedNotOmitted(t *testing.T) {
	scanned := mustCoord(t, "example.com/dep", "v1.0.0")
	uc := makeUC(
		&fakeSnapshotBuilder{snap: makeSnap("example.com/app")},
		&fakeBuildLister{modules: []domain.BuildModule{
			{Path: "example.com/dep", Version: "v1.0.0", Direct: true},
			{Path: "example.com/never-scanned", Version: "v2.0.0"},
		}},
		&fakeVulnLoader{findings: map[coordinate.ModuleCoordinate][]ports.VulnFinding{
			scanned: {{ID: "GHSA-0009", AffectedSymbols: []string{"Bad"}}},
		}},
		&fakeProber{result: ports.SymbolProbeResult{Kind: "library", BinarySymbols: map[string]struct{}{}}},
	)

	result, err := uc.Execute(context.Background(), "/ws")
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if len(result.Coverage.Uncovered) != 1 {
		t.Fatalf("Uncovered = %+v, want exactly the unscanned module", result.Coverage.Uncovered)
	}
	u := result.Coverage.Uncovered[0]
	if u.Path != "example.com/never-scanned" || u.Version != "v2.0.0" {
		t.Errorf("Uncovered[0] = %+v, want example.com/never-scanned@v2.0.0", u)
	}
	if u.Reason != domain.UncoveredNoStoredRecord {
		t.Errorf("Reason = %q, want the no-record reason", u.Reason)
	}
	if result.Coverage.BuildModules != 2 || result.Coverage.Covered != 1 || result.Coverage.WithFindings != 1 {
		t.Errorf("coverage = %+v", result.Coverage)
	}
	if result.Coverage.TakenAt.IsZero() {
		t.Error("TakenAt is zero: the answer states no age")
	}
}

// A record with no findings is an answer — the module is clean — and must not be
// reported as a module nothing is known about.
func TestLocalReachability_ScannedButCleanModuleIsCoveredNotUncovered(t *testing.T) {
	clean := mustCoord(t, "example.com/clean", "v1.0.0")
	affected := mustCoord(t, "example.com/dep", "v1.0.0")
	uc := makeUC(
		&fakeSnapshotBuilder{snap: makeSnap("example.com/app")},
		&fakeBuildLister{modules: []domain.BuildModule{
			{Path: "example.com/clean", Version: "v1.0.0"},
			{Path: "example.com/dep", Version: "v1.0.0"},
		}},
		&fakeVulnLoader{
			findings: map[coordinate.ModuleCoordinate][]ports.VulnFinding{
				affected: {{ID: "GHSA-0010", AffectedSymbols: []string{"Bad"}}},
			},
			scanned: []coordinate.ModuleCoordinate{clean},
		},
		&fakeProber{result: ports.SymbolProbeResult{Kind: "library", BinarySymbols: map[string]struct{}{}}},
	)

	result, err := uc.Execute(context.Background(), "/ws")
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if len(result.Coverage.Uncovered) != 0 {
		t.Errorf("Uncovered = %+v, want none: a clean record is an answer", result.Coverage.Uncovered)
	}
	if result.Coverage.Covered != 2 || result.Coverage.WithFindings != 1 {
		t.Errorf("coverage = %+v, want 2 covered / 1 with findings", result.Coverage)
	}
}

// A module the build resolves without a version names no coordinate, so nothing
// asked the store about it. That is not the same claim as the store having said
// nothing, and it is recorded rather than dropped at the coordinate check.
func TestLocalReachability_VersionlessBuildModuleIsNamedUncovered(t *testing.T) {
	uc := makeUC(
		&fakeSnapshotBuilder{snap: makeSnap("example.com/app")},
		&fakeBuildLister{modules: []domain.BuildModule{
			{Path: "example.com/replaced", Version: ""},
		}},
		&fakeVulnLoader{},
		&fakeProber{},
	)

	result, err := uc.Execute(context.Background(), "/ws")
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if len(result.Coverage.Uncovered) != 1 ||
		result.Coverage.Uncovered[0].Reason != domain.UncoveredNoCoordinate {
		t.Fatalf("Uncovered = %+v, want the versionless module with the no-coordinate reason", result.Coverage.Uncovered)
	}
	if result.Coverage.Queried != 0 {
		t.Errorf("Queried = %d, want 0", result.Coverage.Queried)
	}
}

// The clock is injectable so the stamp is a measurement rather than whatever the
// wall clock read.
func TestLocalReachability_SnapshotTimeIsStamped(t *testing.T) {
	uc := makeUC(
		&fakeSnapshotBuilder{snap: makeSnap("example.com/app")},
		&fakeBuildLister{},
		&fakeVulnLoader{},
		&fakeProber{},
	)

	result, err := uc.Execute(context.Background(), "/ws")
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if !result.Coverage.TakenAt.Equal(testClockInstant) {
		t.Errorf("TakenAt = %v, want %v", result.Coverage.TakenAt, testClockInstant)
	}
}
