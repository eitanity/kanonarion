package staticcha_test

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/mod/modfile"

	"github.com/eitanity/kanonarion/internal/callgraph/adapters/analyser/staticcha"
	"github.com/eitanity/kanonarion/internal/callgraph/domain"
)

// republishedForkFiles is a module republished under a path it never updated its
// own go.mod to match. It is not a hypothetical: github.com/cortezaproject/gval
// declares module github.com/PaesslerAG/gval, and consumers reach it through a
// replace directive, so every import of it anywhere names the DECLARED path.
var republishedForkFiles = map[string]string{
	"go.mod": "module example.com/upstream\n\ngo 1.17\n",
	"gval.go": `package upstream

import "strings"

// Evaluate is the module's exported entry point.
func Evaluate(s string) string {
	return normalise(s)
}

func normalise(s string) string {
	return strings.TrimSpace(s)
}
`,
}

// TestAnalyse_RepublishedForkAnalysesUnderTheDeclaredModulePath pins the
// membership test to the module path the tree DECLARES.
//
// Testing it against the coordinate matched none of the module's own packages,
// so the target set came back empty and the record read "no packages
// successfully loaded" — the single most common failure line in the store, and
// one that named neither what was sought nor what was found.
func TestAnalyse_RepublishedForkAnalysesUnderTheDeclaredModulePath(t *testing.T) {
	coord := mustTestCoord(t, "example.com/fork", "v1.2.4")
	a := staticcha.New("0.1.0", "", slog.Default())

	rec, err := a.Analyse(context.Background(),
		writeZipToTemp(t, makeZip(t, coord, republishedForkFiles)), coord, domain.AnalysisInputs{})
	if err != nil {
		t.Fatalf("Analyse returned error: %v", err)
	}
	requireGraph(t, rec)

	// The record still answers for the coordinate that was asked about; only the
	// membership question is decided by the declared path.
	if rec.Coordinate != coord {
		t.Errorf("record coordinate = %s, want the coordinate the caller asked about (%s)", rec.Coordinate, coord)
	}

	var evaluate *domain.CallNode
	for i := range rec.Nodes {
		if rec.Nodes[i].Symbol == "Evaluate" {
			evaluate = &rec.Nodes[i]
		}
	}
	if evaluate == nil {
		t.Fatalf("no node for the module's exported entry point; nodes: %v", rec.Nodes)
	}
	if evaluate.IsExternal {
		t.Error("the module's own function was classified as external to it")
	}
	if evaluate.Module != "example.com/upstream" {
		t.Errorf("node module = %q, want the path the tree declares (example.com/upstream)", evaluate.Module)
	}
}

// repoRequirement returns a go.mod require line naming modulePath at the version
// THIS repository requires.
//
// A fixture must never name a version whose presence it does not control. This
// one used to hardcode the x/mod version the repository happened to require,
// which put that version in every developer and CI module cache for free — a
// dependency the fixture never declared and could not keep. The moment the
// repository moved off it, a runner with a cold cache had no copy, the analyser
// loads offline by default and cannot fetch one, and the fixture failed for a
// reason several commits away from the change that caused it.
//
// Reading the repository's own go.mod is the tie that holds: whatever the build
// list requires is in the cache wherever this suite can build at all, and a
// version bump carries the fixture with it. A module the repository does not
// require carries no such guarantee and is refused rather than named.
//
// The module named must have NO requirements of its own. An unpruned graph walks
// every version every go.mod in the closure names, including versions MVS has
// superseded and this repository therefore never downloads: requiring x/mod
// reaches x/tools, which names an older x/mod, and the load fails offline for
// want of a go.mod nobody here has. A leaf ends the walk in one step.
func repoRequirement(t *testing.T, modulePath string) string {
	t.Helper()

	gomod, data := findRepoGoMod(t)
	f, err := modfile.Parse(gomod, data, nil)
	if err != nil {
		t.Fatalf("parsing %s: %v", gomod, err)
	}
	for _, req := range f.Require {
		if req.Mod.Path == modulePath {
			return fmt.Sprintf("require %s %s\n", req.Mod.Path, req.Mod.Version)
		}
	}
	t.Fatalf("%s is not required by %s, so nothing guarantees it is in the module cache; "+
		"name a module this repository actually depends on", modulePath, gomod)
	return ""
}

// findRepoGoMod walks up from the test's working directory — the package source
// directory — to this repository's go.mod, and checks the module path so a
// stray go.mod above the tree cannot answer for it.
func findRepoGoMod(t *testing.T) (string, []byte) {
	t.Helper()

	dir, err := os.Getwd()
	if err != nil {
		t.Fatalf("working directory: %v", err)
	}
	for {
		candidate := filepath.Join(dir, "go.mod")
		if data, err := os.ReadFile(candidate); err == nil { //nolint:gosec // a path this test walked to itself
			if path := modfile.ModulePath(data); path == repoModulePath {
				return candidate, data
			}
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatalf("no go.mod declaring %s above the working directory", repoModulePath)
		}
		dir = parent
	}
}

// repoModulePath is this repository's own module path.
const repoModulePath = "github.com/eitanity/kanonarion"

// incompleteGoSumFiles is a module that ships a go.mod naming a dependency and
// no go.sum line covering it, which is what gopkg.in/yaml.v2 and
// github.com/kr/text both do. go.sum is a MAIN-module obligation, and neither
// module was ever a main module until kanonarion analysed it on its own.
//
// The go directive is below 1.17 on purpose: that is what makes the toolchain
// load the unpruned module graph, so it reads the required module's go.mod and
// refuses for want of the go.sum line. Both real modules declare go 1.15.
//
// The requirement must be a REAL module: the go.sum line the loader demands is
// the one covering that module's go.mod, so a stdlib-only fixture would have
// nothing to demand and would pass however the loader was configured. It must
// also be a leaf — see repoRequirement.
func incompleteGoSumFiles(t *testing.T) map[string]string {
	t.Helper()
	return map[string]string{
		"go.mod": "module example.com/nosum\n\ngo 1.15\n\n" + repoRequirement(t, "golang.org/x/sync"),
		"nosum.go": `package nosum

import "strings"

// Fold is the module's exported entry point.
func Fold(s string) string {
	return strings.ToLower(s)
}
`,
	}
}

// TestAnalyse_ModuleShippingNoGoSumForItsOwnGraphStillLoads is the regression
// for the second-largest group: a module whose published zip does not carry a
// go.sum covering its own module graph used to fail the load before a single
// package was type-checked.
//
// The requirement is read out of this binary's build info, so it names a version
// the build list guarantees is in the module cache; nothing here reaches a
// network, and the analyser could not if it tried — it loads with GOPROXY=off.
func TestAnalyse_ModuleShippingNoGoSumForItsOwnGraphStillLoads(t *testing.T) {
	coord := mustTestCoord(t, "example.com/nosum", "v2.4.0")
	a := staticcha.New("0.1.0", "", slog.Default())

	rec, err := a.Analyse(context.Background(),
		writeZipToTemp(t, makeZip(t, coord, incompleteGoSumFiles(t))), coord, domain.AnalysisInputs{})
	if err != nil {
		t.Fatalf("Analyse returned error: %v", err)
	}
	if strings.Contains(rec.FailureDetail, "missing go.sum entry") {
		t.Fatalf("the load still demands a go.sum the artefact never published: %s", rec.FailureDetail)
	}
	requireGraph(t, rec)
}

// unpinnableImportFiles is a module published before Go modules whose own
// packages import third-party code. Synthesis refuses it — a require-less go.mod
// would send the loader after whatever is latest — and the refusal is the fact
// the record has to carry.
var unpinnableImportFiles = map[string]string{
	"premod.go": `package premod

import "example.com/absent/sub"

// F uses a dependency no build list resolves.
func F() { sub.G() }
`,
}

// TestAnalyse_DeclinedSynthesisNamesItsCauseOnTheRecord holds the message.
//
// The load's own account of this failure is "directory prefix . does not contain
// main module or its selected dependencies", which is three steps downstream of
// anything a reader can act on. The record must name the imports that could not
// be pinned, the build list that failed to pin them, and the flag that supplies
// one.
func TestAnalyse_DeclinedSynthesisNamesItsCauseOnTheRecord(t *testing.T) {
	coord := mustTestCoord(t, "example.com/premod", "v0.0.0-20180430131211-7c2a214ada46")
	a := staticcha.New("0.1.0", "", slog.Default())

	rec, err := a.Analyse(context.Background(),
		writeZipToTemp(t, makeZip(t, coord, unpinnableImportFiles)), coord, domain.AnalysisInputs{})
	if err != nil {
		t.Fatalf("Analyse returned error: %v", err)
	}
	if !domain.RecordIsFailure(rec) {
		t.Fatalf("status %s: a module whose imports cannot be pinned must not report a graph", rec.OverallStatus)
	}
	for _, want := range []string{"no go.mod was synthesised", "example.com/absent/sub", "--from-walk"} {
		if !strings.Contains(rec.FailureDetail, want) {
			t.Errorf("failure detail does not name %q:\n%s", want, rec.FailureDetail)
		}
	}
	// The refusal is answerable — a build list can arrive tomorrow — so it must
	// never be filed as a property of the artefact, which is what would cache it
	// permanently.
	if rec.FailureCause != domain.FailureCauseUnrecorded {
		t.Errorf("failure cause = %q: a refusal for want of require directives states nothing about the artefact, "+
			"and any cause recorded here makes the failure cacheable and therefore permanent", rec.FailureCause)
	}
}

// TestAnalyse_NoPackagesFoundNamesThePlatformFrame keeps a platform-scoped
// answer from reading as an unconditional one. github.com/yusufpapurcu/wmi
// ships its entire Go surface behind a windows build tag: on this host it has no
// packages, and that is a joint fact about the module and the frame.
func TestAnalyse_NoPackagesFoundNamesThePlatformFrame(t *testing.T) {
	coord := mustTestCoord(t, "example.com/winonly", "v1.2.4")
	a := staticcha.New("0.1.0", "", slog.Default())

	files := map[string]string{
		"go.mod": "module example.com/winonly\n\ngo 1.17\n",
		"wmi_windows.go": "//go:build windows\n\npackage winonly\n\n" +
			"// Query is only ever compiled on Windows.\nfunc Query() {}\n",
	}
	rec, err := a.Analyse(context.Background(),
		writeZipToTemp(t, makeZip(t, coord, files)), coord, domain.AnalysisInputs{})
	if err != nil {
		t.Fatalf("Analyse returned error: %v", err)
	}
	if !domain.RecordIsFailure(rec) {
		t.Fatalf("status %s: a module with no package in this frame has no graph", rec.OverallStatus)
	}
	if !strings.Contains(rec.FailureDetail, "/") || !strings.Contains(rec.FailureDetail, "no packages found for ") {
		t.Errorf("failure detail names no platform frame: %s", rec.FailureDetail)
	}
}

// brokenSourceFiles is a module whose own source does not typecheck, so the
// loader reports a position inside the tree it was handed.
var brokenSourceFiles = map[string]string{
	"go.mod": "module example.com/broken\n\ngo 1.17\n",
	"lib/hooks.go": `package lib

// Hook does not compile: nothing declares missing.
func Hook() int {
	return missing()
}
`,
	"ok.go": `package broken

// Fine is here so the load has something to build.
func Fine() int { return 1 }
`,
}

// TestAnalyse_FailureDetailNamesNoStagingDirectory.
//
// The analyser stages a module zip in a per-run temporary directory, and the
// loader reports positions inside it. That path went into failure_detail, which
// is inside the record's canonical hash AND inside the graph digest, so no two
// analyses of one failing module could ever produce the same record: every
// repeat appended a generation, for ever, and two identical graphs compared
// unequal. The directory is deleted when the run ends, so the path identified
// nothing a reader could open either.
func TestAnalyse_FailureDetailNamesNoStagingDirectory(t *testing.T) {
	coord := mustTestCoord(t, "example.com/broken", "v1.0.0")
	a := staticcha.New("0.1.0", "", slog.Default())

	analyse := func() domain.CallGraphRecord {
		t.Helper()
		rec, err := a.Analyse(context.Background(),
			writeZipToTemp(t, makeZip(t, coord, brokenSourceFiles)), coord, domain.AnalysisInputs{})
		if err != nil {
			t.Fatalf("Analyse returned error: %v", err)
		}
		return rec
	}

	first, second := analyse(), analyse()
	if first.FailureDetail == "" {
		t.Fatal("the analysis reported no failure, so this test measures nothing")
	}
	if strings.Contains(first.FailureDetail, os.TempDir()) || strings.Contains(first.FailureDetail, "kanonarion-cg-") {
		t.Errorf("failure_detail names the staging directory: %s", first.FailureDetail)
	}
	// The diagnostic is not weakened: what a reader acts on is the module-relative
	// position and the loader's own sentence.
	if !strings.Contains(first.FailureDetail, "lib/hooks.go:") {
		t.Errorf("failure_detail lost the position a reader can act on: %s", first.FailureDetail)
	}
	if first.FailureDetail != second.FailureDetail {
		t.Errorf("two analyses of one module recorded different failures:\n%s\n%s",
			first.FailureDetail, second.FailureDetail)
	}
	if domain.GraphDigest(first) != domain.GraphDigest(second) {
		t.Error("two analyses of one module produced graphs that compare unequal")
	}

	// Control: two analyses that genuinely differ still differ. The point is to
	// remove a random component of the diagnostic, not to stop recording it.
	other := map[string]string{}
	for k, v := range brokenSourceFiles {
		other[k] = v
	}
	other["ok.go"] += "\n// Extra is a second function, so the graph is a different one.\nfunc Extra() int { return Fine() }\n"
	differs, err := a.Analyse(context.Background(),
		writeZipToTemp(t, makeZip(t, coord, other)), coord, domain.AnalysisInputs{})
	if err != nil {
		t.Fatalf("Analyse returned error: %v", err)
	}
	if domain.GraphDigest(differs) == domain.GraphDigest(first) {
		t.Error("a genuinely different graph compares equal to the first")
	}
}
