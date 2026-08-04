package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/eitanity/kanonarion/internal/cli/testfakes"
	"github.com/eitanity/kanonarion/internal/coordinate"
	walkdomain "github.com/eitanity/kanonarion/internal/walk/domain"
)

// The fixture. sprig at v2.22.0+incompatible is the live instance of the class:
// a module that reached v2 without adopting modules, so the go command ignores
// its go.mod, resolves none of its requirements, and a walk of it records one
// node and no edges. The synthetic coordinates stand in for its real
// dependencies, which are exactly what no answer can show.
const (
	preModulesPath    = "github.com/example/sprigalike"
	preModulesVersion = "v2.22.0+incompatible"
)

func preModulesFixtureCoord(t *testing.T) coordinate.ModuleCoordinate {
	t.Helper()
	c, err := coordinate.NewModuleCoordinate(preModulesPath, preModulesVersion)
	if err != nil {
		t.Fatalf("building the fixture coordinate: %v", err)
	}
	return c
}

// preModulesWalk is the walk the surfaces are swept against: a project root that
// requires the pre-modules module, and nothing under it, because nothing under it
// was ever resolved.
func preModulesWalk(t *testing.T, id string) walkdomain.WalkRecord {
	t.Helper()
	root, err := coordinate.NewModuleCoordinate("example.com/project", "v0.0.0")
	if err != nil {
		t.Fatalf("building the root coordinate: %v", err)
	}
	target := preModulesFixtureCoord(t)
	return walkdomain.WalkRecord{
		ID:            id,
		Target:        root,
		StartedAt:     time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
		OverallStatus: walkdomain.WalkSucceeded,
		Graph: walkdomain.Graph{
			Nodes: []walkdomain.GraphNode{
				{Coordinate: root},
				{Coordinate: target, DirectDependency: true},
			},
			Edges: []walkdomain.GraphEdge{{From: root, To: target}},
		},
		PerNodeResults: map[coordinate.ModuleCoordinate]walkdomain.NodeResult{},
	}
}

// TestPreModulesCoordinateIsRecognised pins the predicate every surface routes
// on, with the control that must be false: a version that merely LOOKS like a
// major-2 pin is resolved normally and must never carry the caveat.
func TestPreModulesCoordinateIsRecognised(t *testing.T) {
	if !preModulesFixtureCoord(t).IsPreModulesIncompatible() {
		t.Error("a +incompatible coordinate was not recognised as pre-modules")
	}
	normal, err := coordinate.NewModuleCoordinate("github.com/example/mod/v2", "v2.22.0")
	if err != nil {
		t.Fatalf("building the control coordinate: %v", err)
	}
	if normal.IsPreModulesIncompatible() {
		t.Error("a properly-suffixed v2 module was reported as pre-modules; every answer " +
			"about it would carry a caveat that does not apply")
	}
	if preModulesCaveat(normal) != "" {
		t.Errorf("a caveat was rendered for a module the limitation does not bind: %q", preModulesCaveat(normal))
	}
}

// TestWalkShowStatesThePreModulesLimitation. One node and no edges is what the
// walk honestly recorded; three lines saying ID, target and status give the
// reader no way to tell that from a module that genuinely requires nothing.
func TestWalkShowStatesThePreModulesLimitation(t *testing.T) {
	// jsonOut is a package-level flag other tests in this package set; the text
	// branch is what this pins, so it is pinned rather than inherited.
	saved := jsonOut
	jsonOut = false
	t.Cleanup(func() { jsonOut = saved })

	uc := testfakes.NewFakeQueryWalks()
	uc.AddWalk(preModulesWalk(t, "01WALKPREMODULES"))

	var stdout, stderr bytes.Buffer
	if err := runWalkShow(context.Background(), "01WALKPREMODULES", uc, &stdout, &stderr); err != nil {
		t.Fatalf("runWalkShow: %v", err)
	}
	assertStatesPreModules(t, "walk-show", stdout.String())
}

// TestDependentsStatesThePreModulesLimitation covers the direction the defect was
// found in: asking who depends on one of the pre-modules module's own
// dependencies. It cannot appear in the answer, because no requirement edge was
// resolved under it, and an answer that does not say so re-attributes its private
// dependencies to whichever consumer absorbed them.
func TestDependentsStatesThePreModulesLimitation(t *testing.T) {
	rec := preModulesWalk(t, "01WALKPREMODULES")
	var stdout bytes.Buffer
	if err := writeDependentsText(&stdout, rec.ID, "linux/amd64", "example.com/other@v1.0.0",
		nil, false, false, false); err != nil {
		t.Fatalf("writeDependentsText: %v", err)
	}
	if err := writeWalkPreModulesCaveat(&stdout, rec.Graph); err != nil {
		t.Fatalf("writeWalkPreModulesCaveat: %v", err)
	}
	assertStatesPreModules(t, "dependents", stdout.String())
	if !strings.Contains(stdout.String(), "dependent of anything") {
		t.Errorf("dependents does not state that a pre-modules module can never appear as a "+
			"dependent:\n%s", stdout.String())
	}
}

// TestDependentsJSONCarriesThePreModulesCaveat pins the machine-readable leg. An
// agent reading the JSON gets the same statement the human does, or it reads an
// empty dependents list as a measurement.
func TestDependentsJSONCarriesThePreModulesCaveat(t *testing.T) {
	rec := preModulesWalk(t, "01WALKPREMODULES")
	var stdout bytes.Buffer
	if err := writeDependentsJSON(&stdout, rec.ID, "linux/amd64", "example.com/other@v1.0.0", nil,
		preModulesCaveatFor(preModulesNodesIn(rec.Graph)...)); err != nil {
		t.Fatalf("writeDependentsJSON: %v", err)
	}
	var out struct {
		PreModulesCaveat *struct {
			Coordinates []string `json:"coordinates"`
			Limitation  string   `json:"limitation"`
			Remedy      string   `json:"remedy"`
		} `json:"pre_modules_caveat"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &out); err != nil {
		t.Fatalf("decoding dependents JSON: %v", err)
	}
	if out.PreModulesCaveat == nil {
		t.Fatalf("dependents JSON carries no pre-modules caveat:\n%s", stdout.String())
	}
	want := preModulesPath + "@" + preModulesVersion
	if len(out.PreModulesCaveat.Coordinates) != 1 || out.PreModulesCaveat.Coordinates[0] != want {
		t.Errorf("caveat names %v, want exactly [%s]", out.PreModulesCaveat.Coordinates, want)
	}
	if out.PreModulesCaveat.Remedy == "" {
		t.Error("the caveat names no remedy, so a reader is told what is missing and not what to do")
	}
}

// TestDependentsJSONOmitsTheCaveatForAnOrdinaryWalk is the control that must be
// non-zero in the other direction: a walk holding no pre-modules module marshals
// exactly as it did before this field existed.
func TestDependentsJSONOmitsTheCaveatForAnOrdinaryWalk(t *testing.T) {
	var stdout bytes.Buffer
	if err := writeDependentsJSON(&stdout, "01WALK", "linux/amd64", "example.com/other@v1.0.0", nil, nil); err != nil {
		t.Fatalf("writeDependentsJSON: %v", err)
	}
	if strings.Contains(stdout.String(), "pre_modules_caveat") {
		t.Errorf("an ordinary answer carries the caveat key:\n%s", stdout.String())
	}
}

// TestContextDependenciesSectionStatesThePreModulesLimitation. "(no direct
// dependencies)" under a +incompatible coordinate is the exact sentence this
// caveat exists to qualify.
func TestContextDependenciesSectionStatesThePreModulesLimitation(t *testing.T) {
	coord := preModulesFixtureCoord(t)
	section := contextDependencies{
		Status:           "Succeeded",
		WalkID:           "01WALKPREMODULES",
		Frame:            "linux/amd64",
		PreModulesCaveat: preModulesCaveatFor(coord),
	}
	var buf bytes.Buffer
	w := &errWriter{w: &buf}
	printFullDependencies(w, section, coord.Path()+"@"+coord.Version())
	if w.err != nil {
		t.Fatalf("printFullDependencies: %v", w.err)
	}
	if !strings.Contains(buf.String(), "(no direct dependencies)") {
		t.Fatalf("fixture did not reach the empty-dependency line:\n%s", buf.String())
	}
	assertStatesPreModules(t, "context --full dependencies", buf.String())
}

// TestVulnShowStatesThePreModulesLimitation. Reachability under a pre-modules
// coordinate is measured over a call graph built from a module whose own
// requirements were never resolved, so a not-reached verdict is bounded by more
// than the completeness axis states.
func TestVulnShowStatesThePreModulesLimitation(t *testing.T) {
	line := preModulesCaveat(preModulesFixtureCoord(t))
	if line == "" {
		t.Fatal("no caveat rendered for the fixture coordinate")
	}
	assertStatesPreModules(t, "vuln-show", line)
}

// TestSetCaveatNamesEveryPreModulesCoordinateOnce is what the audit, sbom,
// interface-diff and licence-compatibility surfaces all print. One line naming
// the set keeps the statement present on a listing without repeating it per row.
func TestSetCaveatNamesEveryPreModulesCoordinateOnce(t *testing.T) {
	coord := preModulesFixtureCoord(t)
	normal, err := coordinate.NewModuleCoordinate("example.com/other", "v1.0.0")
	if err != nil {
		t.Fatalf("building the control coordinate: %v", err)
	}
	var buf bytes.Buffer
	if err := writePreModulesCaveatForSet(&buf, []coordinate.ModuleCoordinate{coord, normal, coord}); err != nil {
		t.Fatalf("writePreModulesCaveatForSet: %v", err)
	}
	assertStatesPreModules(t, "set caveat", buf.String())
	if strings.Count(buf.String(), preModulesPath) != 1 {
		t.Errorf("the coordinate is named %d times, want once:\n%s",
			strings.Count(buf.String(), preModulesPath), buf.String())
	}
	if strings.Contains(buf.String(), "example.com/other") {
		t.Errorf("a normally-resolved module was named in the caveat:\n%s", buf.String())
	}

	// The control: a set with no pre-modules coordinate prints nothing at all.
	var quiet bytes.Buffer
	if err := writePreModulesCaveatForSet(&quiet, []coordinate.ModuleCoordinate{normal}); err != nil {
		t.Fatalf("writePreModulesCaveatForSet: %v", err)
	}
	if quiet.Len() != 0 {
		t.Errorf("a caveat was printed for an answer it does not bind:\n%s", quiet.String())
	}
}

// TestSynthesisedRequiresAreNeverPresentedAsResolvedEdges is the boundary between
// the two halves of this change. Require directives pinned into a synthesised
// go.mod are SCAN INPUTS; presenting them as resolved dependency edges would
// hand back as measurement precisely the thing the walk could not resolve.
func TestSynthesisedRequiresAreNeverPresentedAsResolvedEdges(t *testing.T) {
	rec := preModulesWalk(t, "01WALKPREMODULES")
	target := preModulesFixtureCoord(t)
	for _, e := range rec.Graph.Edges {
		if e.From == target {
			t.Errorf("an edge was resolved out of a pre-modules coordinate: %s -> %s", e.From, e.To)
		}
	}
	var buf bytes.Buffer
	if err := writeWalkPreModulesCaveat(&buf, rec.Graph); err != nil {
		t.Fatalf("writeWalkPreModulesCaveat: %v", err)
	}
	// The caveat states the absence. It must not present the pinned require
	// directives a scan-input synthesis may have written: those are versions
	// kanonarion supplied to a loader, not versions the module system resolved.
	for _, forbidden := range []string{"require (", "synthesised", "pinned"} {
		if strings.Contains(buf.String(), forbidden) {
			t.Errorf("the graph surface states %q, which belongs to scan inputs:\n%s", forbidden, buf.String())
		}
	}
}

// assertStatesPreModules is the sweep's shared acceptance: whatever the surface,
// the output must name the coordinate, name the limitation as an ABSENCE rather
// than a measurement, and name the remedy.
func assertStatesPreModules(t *testing.T, surface, out string) {
	t.Helper()
	for _, want := range []string{
		preModulesPath,
		"pre-modules",
		"ABSENT",
		"/vN",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("%s output does not state %q:\n%s", surface, want, out)
		}
	}
}

// TestAuditRowsYieldTheirPreModulesCoordinates covers the one surface whose rows
// carry their coordinate already joined into a string. The parse has to succeed
// for the caveat to name anything at all, and a row it cannot parse must be
// dropped rather than guessed at.
func TestAuditRowsYieldTheirPreModulesCoordinates(t *testing.T) {
	got := auditPreModulesCoords([]auditModuleResult{
		{Coordinate: preModulesPath + "@" + preModulesVersion},
		{Coordinate: "example.com/other@v1.0.0"},
		{Coordinate: "not-a-coordinate"},
	})
	var buf bytes.Buffer
	if err := writePreModulesCaveatForSet(&buf, got); err != nil {
		t.Fatalf("writePreModulesCaveatForSet: %v", err)
	}
	assertStatesPreModules(t, "audit", buf.String())
	if strings.Contains(buf.String(), "not-a-coordinate") {
		t.Errorf("an unparseable row was named in the caveat:\n%s", buf.String())
	}
	if strings.Contains(buf.String(), "example.com/other") {
		t.Errorf("a normally-resolved row was named in the caveat:\n%s", buf.String())
	}
}
