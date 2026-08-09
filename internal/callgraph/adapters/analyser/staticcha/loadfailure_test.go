package staticcha_test

import (
	"context"
	"log/slog"
	"strings"
	"testing"

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

// incompleteGoSumFiles is a module that ships a go.mod naming a dependency and
// no go.sum line covering it, which is what gopkg.in/yaml.v2 and
// github.com/kr/text both do. go.sum is a MAIN-module obligation, and neither
// module was ever a main module until kanonarion analysed it on its own.
//
// The go directive is below 1.17 on purpose: that is what makes the toolchain
// load the unpruned module graph, so it reads the required module's go.mod and
// refuses for want of the go.sum line. Both real modules declare go 1.15.
var incompleteGoSumFiles = map[string]string{
	"go.mod": "module example.com/nosum\n\ngo 1.15\n\nrequire golang.org/x/mod v0.37.0\n",
	"nosum.go": `package nosum

import "strings"

// Fold is the module's exported entry point.
func Fold(s string) string {
	return strings.ToLower(s)
}
`,
}

// TestAnalyse_ModuleShippingNoGoSumForItsOwnGraphStillLoads is the regression
// for the second-largest group: a module whose published zip does not carry a
// go.sum covering its own module graph used to fail the load before a single
// package was type-checked.
//
// The required version is one this repository itself depends on, so it is in the
// module cache wherever this suite can build at all; nothing here reaches a
// network.
func TestAnalyse_ModuleShippingNoGoSumForItsOwnGraphStillLoads(t *testing.T) {
	coord := mustTestCoord(t, "example.com/nosum", "v2.4.0")
	a := staticcha.New("0.1.0", "", slog.Default())

	rec, err := a.Analyse(context.Background(),
		writeZipToTemp(t, makeZip(t, coord, incompleteGoSumFiles)), coord, domain.AnalysisInputs{})
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
