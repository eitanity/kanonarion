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
	walkports "github.com/eitanity/kanonarion/internal/walk/ports"
)

// The defect this file pins: `dependents` took the newest walk holding the
// coordinate while `vuln-show` ranked by rooting, so the two commands named two
// different walks for one coordinate on one store in one second. Vetting a
// library in isolation makes the library-rooted walk the newest one holding it,
// and that walk has the library's own dependency closure — so the answer to "who
// depends on this" became the library's own dependencies. Measured on the live
// store: `1` where the consumer's build has `9`.
//
// Every fixture here therefore puts the self-rooted walk FIRST, which is where
// recency-ranking would find it.

// containmentFixture builds a store whose summaries are newest-first in the
// order given. Each walk holds its own root plus the coordinates listed.
type containmentWalk struct {
	id    string
	root  coordinate.ModuleCoordinate
	holds []coordinate.ModuleCoordinate
}

func containmentFixture(walks ...containmentWalk) *testfakes.FakeQueryWalks {
	uc := testfakes.NewFakeQueryWalks()
	base := time.Date(2026, 8, 25, 12, 0, 0, 0, time.UTC)
	summaries := make([]walkports.WalkSummary, 0, len(walks))
	for i, w := range walks {
		nodes := []walkdomain.GraphNode{{Coordinate: w.root}}
		edges := make([]walkdomain.GraphEdge, 0, len(w.holds))
		for _, h := range w.holds {
			nodes = append(nodes, walkdomain.GraphNode{Coordinate: h})
			edges = append(edges, walkdomain.GraphEdge{From: w.root, To: h})
		}
		uc.AddWalk(walkdomain.WalkRecord{
			ID: w.id, Target: w.root,
			Graph: walkdomain.Graph{Target: w.root, Nodes: nodes, Edges: edges},
		})
		summaries = append(summaries, walkports.WalkSummary{
			ID: w.id, Target: w.root, Scope: walkdomain.WalkScopeCode,
			StartedAt: base.Add(-time.Duration(i) * time.Hour),
		})
	}
	uc.SetSummaries(summaries)
	return uc
}

const containmentRemedy = "kanonarion dependents X --walk-id <walk of that build>"

// The defect itself. The self-rooted walk is the newest, so recency picks it;
// rooting must pass it over for the older consumer build.
func TestFindWalkContaining_PrefersAConsumerBuildOverTheModulesOwnWalk(t *testing.T) {
	lib := mustCoord(t, "example.com/lib", "v1.0.0")
	app := mustCoord(t, "example.com/app", "v1.0.0")
	dep := mustCoord(t, "example.com/dep", "v1.0.0")

	uc := containmentFixture(
		containmentWalk{id: "walk-vetting", root: lib, holds: []coordinate.ModuleCoordinate{dep}},
		containmentWalk{id: "walk-app", root: app, holds: []coordinate.ModuleCoordinate{lib, dep}},
	)

	found, err := findWalkContaining(context.Background(), uc, lib, containmentRemedy)
	if err != nil {
		t.Fatalf("findWalkContaining: %v", err)
	}
	if found.walkID != "walk-app" {
		t.Errorf("chose walk %q; the newest walk is rooted at the coordinate itself and cannot hold a consumer, so walk-app must answer", found.walkID)
	}
	if found.rule != walkHeldByConsumer {
		t.Errorf("rule = %q, want %q", found.rule, walkHeldByConsumer)
	}
	if found.root != app {
		t.Errorf("root = %s, want %s", found.root, app)
	}
	if found.selfRootedPassedOver != 1 {
		t.Errorf("selfRootedPassedOver = %d, want 1 — the walk that was passed over is what the notice names", found.selfRootedPassedOver)
	}
	if note := found.statement(lib); !strings.Contains(note, "walk-app") || !strings.Contains(note, "passed over") {
		t.Errorf("the notice does not state that a self-rooted walk was passed over: %q", note)
	}
}

// The falsifying case, and the reason the rule is a preference rather than an
// exclusion: a module vetted in isolation and walked nowhere else is legitimately
// answerable only from its own graph. It still answers, and it still says what
// the answer is about.
func TestFindWalkContaining_AnswersFromTheModulesOwnWalkWhenItIsTheOnlyOne(t *testing.T) {
	lib := mustCoord(t, "example.com/lib", "v1.0.0")
	other := mustCoord(t, "example.com/other", "v1.0.0")

	uc := containmentFixture(
		containmentWalk{id: "walk-vetting", root: lib},
		containmentWalk{id: "walk-unrelated", root: other},
	)

	found, err := findWalkContaining(context.Background(), uc, lib, containmentRemedy)
	if err != nil {
		t.Fatalf("a coordinate held only in its own walk became unanswerable: %v", err)
	}
	if found.walkID != "walk-vetting" {
		t.Errorf("chose walk %q, want walk-vetting", found.walkID)
	}
	if found.rule != walkHeldSelfRootedOnly {
		t.Errorf("rule = %q, want %q", found.rule, walkHeldSelfRootedOnly)
	}
	note := found.statement(lib)
	for _, want := range []string{"own dependency graph", "names no consuming build", "walk-vetting"} {
		if !strings.Contains(note, want) {
			t.Errorf("the fallback does not disclose %q: %q", want, note)
		}
	}
}

// Genuine ambiguity refuses and names the candidates, as the vulnerability read
// already does for two consumer frames. Serving whichever build was walked last
// answers one project's question from another project's build.
func TestFindWalkContaining_RefusesWhenTwoBuildsHoldTheCoordinate(t *testing.T) {
	lib := mustCoord(t, "example.com/lib", "v1.0.0")
	app := mustCoord(t, "example.com/app", "v1.0.0")
	svc := mustCoord(t, "example.com/svc", "v1.0.0")

	uc := containmentFixture(
		containmentWalk{id: "walk-app", root: app, holds: []coordinate.ModuleCoordinate{lib}},
		containmentWalk{id: "walk-svc", root: svc, holds: []coordinate.ModuleCoordinate{lib}},
	)

	_, err := findWalkContaining(context.Background(), uc, lib, containmentRemedy)
	if err == nil {
		t.Fatal("two builds hold the coordinate and the search picked one anyway")
	}
	msg := err.Error()
	for _, want := range []string{"walk-app", "walk-svc", "example.com/app@v1.0.0", "example.com/svc@v1.0.0", containmentRemedy} {
		if !strings.Contains(msg, want) {
			t.Errorf("the refusal does not name %q: %s", want, msg)
		}
	}
	if code, ok := ExitCodeFromError(err); !ok || code != ExitConfig {
		t.Errorf("exit code = %d (carried %v), want ExitConfig — a caller must be able to read the refusal off the code", code, ok)
	}
}

// Several walks of ONE build are not an ambiguity: they answer one question and
// recency picks between them, exactly as it did. Without this the fix would
// refuse every coordinate in a project walked more than once.
func TestFindWalkContaining_RepeatedWalksOfOneBuildAreNotAmbiguous(t *testing.T) {
	lib := mustCoord(t, "example.com/lib", "v1.0.0")
	app := mustCoord(t, "example.com/app", "v1.0.0")

	uc := containmentFixture(
		containmentWalk{id: "walk-app-new", root: app, holds: []coordinate.ModuleCoordinate{lib}},
		containmentWalk{id: "walk-app-old", root: app, holds: []coordinate.ModuleCoordinate{lib}},
	)

	found, err := findWalkContaining(context.Background(), uc, lib, containmentRemedy)
	if err != nil {
		t.Fatalf("two walks of one build were treated as two builds: %v", err)
	}
	if found.walkID != "walk-app-new" {
		t.Errorf("chose walk %q, want walk-app-new — recency is still the tiebreak within one build", found.walkID)
	}
}

// The end-to-end shape the ticket was filed on: the library-rooted walk has its
// own closure, so the wrong answer is a plausible number rather than an empty
// list. The command must name the consumer's walk and the consumer's dependents.
func TestDependents_AnswersFromTheConsumerBuildNotTheModulesOwnWalk(t *testing.T) {
	lib := mustCoord(t, "example.com/lib", "v1.0.0")
	app := mustCoord(t, "example.com/app", "v1.0.0")
	inner := mustCoord(t, "example.com/inner", "v1.0.0")
	consumerA := mustCoord(t, "example.com/consumer-a", "v1.0.0")
	consumerB := mustCoord(t, "example.com/consumer-b", "v1.0.0")

	uc := testfakes.NewFakeQueryWalks()
	base := time.Date(2026, 8, 25, 12, 0, 0, 0, time.UTC)
	// The vetting walk: newest, rooted at the library, and inner depends on lib
	// inside it — so recency-ranking answers "1 module depends on lib".
	uc.AddWalk(walkdomain.WalkRecord{
		ID: "walk-vetting", Target: lib,
		Graph: walkdomain.Graph{
			Target: lib,
			Nodes:  []walkdomain.GraphNode{{Coordinate: lib}, {Coordinate: inner}},
			Edges:  []walkdomain.GraphEdge{{From: inner, To: lib}},
		},
	})
	uc.AddWalk(walkdomain.WalkRecord{
		ID: "walk-app", Target: app,
		Graph: walkdomain.Graph{
			Target: app,
			Nodes: []walkdomain.GraphNode{
				{Coordinate: app}, {Coordinate: lib},
				{Coordinate: consumerA, DirectDependency: true}, {Coordinate: consumerB, DirectDependency: true},
			},
			Edges: []walkdomain.GraphEdge{{From: consumerA, To: lib}, {From: consumerB, To: lib}},
		},
	})
	uc.SetSummaries([]walkports.WalkSummary{
		{ID: "walk-vetting", Target: lib, Scope: walkdomain.WalkScopeCode, StartedAt: base},
		{ID: "walk-app", Target: app, Scope: walkdomain.WalkScopeCode, StartedAt: base.Add(-time.Hour)},
	})

	var stdout, stderr bytes.Buffer
	if err := dependentsWith(context.Background(), &Container{QueryWalks: uc}, lib, "",
		false, false, false, &stdout, &stderr); err != nil {
		t.Fatalf("dependentsWith: %v", err)
	}
	out := stdout.String()
	if strings.Contains(out, "walk-vetting") {
		t.Errorf("the answer came from the walk rooted at the queried coordinate:\n%s", out)
	}
	for _, want := range []string{"walk-app", "example.com/consumer-a@v1.0.0", "example.com/consumer-b@v1.0.0"} {
		if !strings.Contains(out, want) {
			t.Errorf("the answer does not name %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "example.com/inner@v1.0.0") {
		t.Errorf("the answer carries a dependent from the library's own graph:\n%s", out)
	}
}

// The JSON surface owes the same fact as the prose: a consumer reading the walk
// id cannot otherwise tell an id the caller pinned from one the tool picked, nor
// a consumer build from the coordinate's own walk.
func TestDependentsJSON_StatesHowTheWalkWasChosen(t *testing.T) {
	lib := mustCoord(t, "example.com/lib", "v1.0.0")
	app := mustCoord(t, "example.com/app", "v1.0.0")

	uc := containmentFixture(
		containmentWalk{id: "walk-vetting", root: lib},
		containmentWalk{id: "walk-app", root: app, holds: []coordinate.ModuleCoordinate{lib}},
	)

	for _, tc := range []struct {
		name     string
		walkID   string
		wantRule string
		wantRoot string
		wantOver int
	}{
		{name: "chosen", wantRule: "consumer-rooted", wantRoot: "example.com/app@v1.0.0", wantOver: 1},
		{name: "pinned", walkID: "walk-vetting", wantRule: "pinned", wantRoot: "example.com/lib@v1.0.0"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			if err := dependentsWith(context.Background(), &Container{QueryWalks: uc}, lib, tc.walkID,
				true, false, false, &stdout, &stderr); err != nil {
				t.Fatalf("dependentsWith: %v", err)
			}
			var out struct {
				WalkSelection walkSelectionJSON `json:"walk_selection"`
			}
			if err := json.Unmarshal(stdout.Bytes(), &out); err != nil {
				t.Fatalf("decoding: %v\n%s", err, stdout.String())
			}
			if out.WalkSelection.Rule != tc.wantRule {
				t.Errorf("rule = %q, want %q", out.WalkSelection.Rule, tc.wantRule)
			}
			if out.WalkSelection.Root != tc.wantRoot {
				t.Errorf("root = %q, want %q", out.WalkSelection.Root, tc.wantRoot)
			}
			if out.WalkSelection.SelfRootedPassedOver != tc.wantOver {
				t.Errorf("self_rooted_passed_over = %d, want %d", out.WalkSelection.SelfRootedPassedOver, tc.wantOver)
			}
		})
	}
}

// The other caller of the search degrades rather than failing, so an ambiguity
// there would be silent — an empty call graph recorded while the store held the
// build lists that would have filled it, and nothing said about either.
func TestDiscoveredBuildList_NamesTheBuildsWhenTheChoiceIsAmbiguous(t *testing.T) {
	lib := mustCoord(t, "example.com/lib", "v1.0.0")
	app := mustCoord(t, "example.com/app", "v1.0.0")
	svc := mustCoord(t, "example.com/svc", "v1.0.0")

	uc := containmentFixture(
		containmentWalk{id: "walk-app", root: app, holds: []coordinate.ModuleCoordinate{lib}},
		containmentWalk{id: "walk-svc", root: svc, holds: []coordinate.ModuleCoordinate{lib}},
	)

	var stderr bytes.Buffer
	inputs := discoveredBuildList(context.Background(), uc, lib, &stderr)
	if inputs.HasBuildList() {
		t.Error("an ambiguous search supplied a build list, so one project's build seeded another's analysis")
	}
	msg := stderr.String()
	for _, want := range []string{"walk-app", "walk-svc", "--from-walk"} {
		if !strings.Contains(msg, want) {
			t.Errorf("the note does not name %q: %s", want, msg)
		}
	}
}
