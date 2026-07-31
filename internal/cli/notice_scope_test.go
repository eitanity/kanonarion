package cli

import (
	"bytes"
	"context"
	"strings"
	"testing"

	"github.com/eitanity/kanonarion/internal/cli/testfakes"
	"github.com/eitanity/kanonarion/internal/coordinate"
	"github.com/eitanity/kanonarion/internal/coordinate/coordinatetest"
	licapp "github.com/eitanity/kanonarion/internal/license/application"
	licdomain "github.com/eitanity/kanonarion/internal/license/domain"
	walkdomain "github.com/eitanity/kanonarion/internal/walk/domain"
)

// A walk id is the only positional notice accepts. Anything else must be
// refused by name rather than accepted and discarded — discarding it is what
// let notice answer a go.mod-scoped question when a walk was asked for.
func TestNoticeArgs_OnlyAWalkID(t *testing.T) {
	const walkID = "01KQDBVW092ER1HNXZ60X27CMD"

	if err := noticeArgs(nil, nil); err != nil {
		t.Errorf("no positional must be accepted (the --gomod/--package forms), got: %v", err)
	}
	if err := noticeArgs(nil, []string{walkID}); err != nil {
		t.Errorf("a walk id must be accepted positionally, got: %v", err)
	}

	err := noticeArgs(nil, []string{"./go.mod"})
	if err == nil {
		t.Fatal("a non-walk-id positional must be refused, not silently discarded")
	}
	if !strings.Contains(err.Error(), "./go.mod") {
		t.Errorf("the refusal must name what was passed, got: %v", err)
	}

	err = noticeArgs(nil, []string{walkID, walkID})
	if err == nil {
		t.Fatal("two positionals must be refused")
	}
}

// A walk id given both positionally and via --walk-id is a conflict. Picking
// one silently is the same defect in a new place, so it is an error.
func TestNoticeCmd_WalkIDGivenTwiceIsAnError(t *testing.T) {
	const walkID = "01KQDBVW092ER1HNXZ60X27CMD"
	cmd := newNoticeCmd(&bytes.Buffer{}, &bytes.Buffer{})
	cmd.SetOut(&bytes.Buffer{})
	cmd.SetErr(&bytes.Buffer{})
	cmd.SetArgs([]string{walkID, "--walk-id", walkID})

	err := cmd.Execute()
	if err == nil {
		t.Fatal("expected an error when the walk id is given twice")
	}
	if !strings.Contains(err.Error(), "twice") {
		t.Errorf("the error must say the id was given twice, got: %v", err)
	}
}

// The scope that produced the output is stated, so a reader of the output alone
// can tell a walk scope from a go.mod scope without re-deriving the invocation.
func TestNoticeWith_StatesTheScope(t *testing.T) {
	coord := coordinatetest.MustNew("example.com/dep", "v1.0.0")
	ctr := &Container{
		QueryWalks: walksWithNodes("W1", coord),
		GenerateNotice: &testfakes.FakeGenerateNotice{Result: licapp.NoticeResult{
			Entries: []licdomain.NoticeEntry{{Coordinate: coord, SPDX: "MIT"}},
		}},
	}
	var stdout, stderr bytes.Buffer
	if err := noticeWith(context.Background(), ctr, "W1", "", "", "", "", &stdout, &stderr); err != nil {
		t.Fatalf("expected success, got: %v", err)
	}
	if !strings.Contains(stderr.String(), "scope: walk W1") {
		t.Errorf("the walk scope must be named on stderr, got: %q", stderr.String())
	}
}

// noticeModuleFmt's three record shapes, parsed. The tab-separated layout is the
// contract between the template and the parser, and a silent misread of it would
// attribute the wrong module — the one error a NOTICE exists to prevent.
func TestParseNoticeModuleRecords_ThreeShapes(t *testing.T) {
	out := []byte(strings.Join([]string{
		"example.com/plain@v1.0.0\t\t",
		"example.com/fork@v2.0.0\texample.com/upstream@v1.5.0\t",
		"\texample.com/local@v1.0.0\t../localfork",
		"\t\t",                         // the main module and stdlib packages
		"example.com/plain@v1.0.0\t\t", // a second package of the same module
	}, "\n"))

	mods, err := parseNoticeModuleRecords(out)
	if err != nil {
		t.Fatalf("parseNoticeModuleRecords: %v", err)
	}
	if len(mods) != 3 {
		t.Fatalf("expected 3 modules (blank dropped, duplicate collapsed), got %d: %+v", len(mods), mods)
	}

	byCompiled := map[string]noticeModule{}
	for _, m := range mods {
		byCompiled[m.coord.String()] = m
	}

	fork, ok := byCompiled["example.com/fork@v2.0.0"]
	if !ok {
		t.Fatalf("the replacement must be the compiled coordinate, got %+v", mods)
	}
	if got := fork.original.String(); got != "example.com/upstream@v1.5.0" {
		t.Errorf("the require entry must be carried alongside, got %q", got)
	}

	// A local-path replace has no compiled coordinate at all: the zero value is
	// how the caller tells it apart, and localPath says what does build.
	var local noticeModule
	for _, m := range mods {
		if m.localPath != "" {
			local = m
		}
	}
	if local.localPath != "../localfork" {
		t.Fatalf("expected a local-path replace record, got %+v", mods)
	}
	if local.coord.Path() != "" {
		t.Errorf("a local-path replace has no fetchable coordinate, got %q", local.coord)
	}
	if got := local.original.String(); got != "example.com/local@v1.0.0" {
		t.Errorf("the require entry must be kept, got %q", got)
	}
}

// A local-path replace must never be handed to the generator: looking a licence
// up under the upstream coordinate would attribute code the build does not
// compile. It is reported for review with the path named instead.
func TestPartitionNoticeModules_LocalReplaceIsReviewedNotAttributed(t *testing.T) {
	upstream := coordinatetest.MustNew("example.com/local", "v1.0.0")
	fork := coordinatetest.MustNew("example.com/fork", "v2.0.0")
	required := coordinatetest.MustNew("example.com/upstream", "v1.5.0")

	coords, replaced, reviews := partitionNoticeModules([]noticeModule{
		{coord: fork, original: required},
		{original: upstream, localPath: "../localfork"},
	})

	if len(coords) != 1 || coords[0] != fork {
		t.Fatalf("only the fetchable replacement may be attributed, got %v", coords)
	}
	if replaced[fork] != required {
		t.Errorf("the requirement the fork stands in for must be carried, got %v", replaced)
	}
	if len(reviews) != 1 {
		t.Fatalf("the local-path replace must be reported for review, got %+v", reviews)
	}
	if reviews[0].Coordinate != upstream {
		t.Errorf("the review item must name the require entry, got %v", reviews[0].Coordinate)
	}
	if !strings.Contains(reviews[0].Reason, "../localfork") {
		t.Errorf("the review reason must name the local path, got %q", reviews[0].Reason)
	}
}

// The walk branch reads the replacement from the stored graph, and reads a
// local-path replace out of the attributable set — the node keeps the original
// require as its Coordinate, so attributing it would cite the upstream project.
func TestResolveNoticeModules_WalkBranchAppliesReplacements(t *testing.T) {
	fork := coordinatetest.MustNew("example.com/fork", "v2.0.0")
	required := coordinatetest.MustNew("example.com/upstream", "v1.5.0")
	localReq := coordinatetest.MustNew("example.com/local", "v1.0.0")

	fqw := testfakes.NewFakeQueryWalks()
	fqw.AddWalk(walkdomain.WalkRecord{ID: "W1", Graph: walkdomain.Graph{Nodes: []walkdomain.GraphNode{
		{Coordinate: fork, OriginalCoordinate: required, ResolutionSource: walkdomain.ResolutionReplace},
		{Coordinate: localReq, LocalPath: "../localfork", ResolutionSource: walkdomain.ResolutionLocalReplace},
	}}})

	mods, scope, err := resolveNoticeModules(context.Background(), "W1", "", "", &Container{QueryWalks: fqw})
	if err != nil {
		t.Fatalf("resolveNoticeModules: %v", err)
	}
	if scope != "walk W1" {
		t.Errorf("scope should name the walk, got %q", scope)
	}
	if len(mods) != 2 {
		t.Fatalf("expected both nodes, got %+v", mods)
	}
	if mods[0].coord != fork || mods[0].original != required {
		t.Errorf("the replaced node must attribute the fork and carry the requirement, got %+v", mods[0])
	}
	if mods[1].coord.Path() != "" || mods[1].original != localReq || mods[1].localPath != "../localfork" {
		t.Errorf("the local-replace node must carry no attributable coordinate, got %+v", mods[1])
	}
}

// The emitted document names the requirement a replacement stands in for, so a
// reader can reconcile it against go.mod — alongside the fork, never instead.
func TestNoticeWith_DocumentNamesTheReplacedRequirement(t *testing.T) {
	fork := coordinatetest.MustNew("example.com/fork", "v2.0.0")
	required := coordinatetest.MustNew("example.com/upstream", "v1.5.0")

	fqw := testfakes.NewFakeQueryWalks()
	fqw.AddWalk(walkdomain.WalkRecord{ID: "W1", Graph: walkdomain.Graph{Nodes: []walkdomain.GraphNode{
		{Coordinate: fork, OriginalCoordinate: required, ResolutionSource: walkdomain.ResolutionReplace},
	}}})
	ctr := &Container{
		QueryWalks: fqw,
		GenerateNotice: &testfakes.FakeGenerateNotice{Result: licapp.NoticeResult{
			Entries: []licdomain.NoticeEntry{{Coordinate: fork, SPDX: "BSD-3-Clause"}},
		}},
	}

	var stdout, stderr bytes.Buffer
	if err := noticeWith(context.Background(), ctr, "W1", "", "", "", "", &stdout, &stderr); err != nil {
		t.Fatalf("expected success, got: %v", err)
	}
	got := stdout.String()
	if !strings.Contains(got, "Module:  example.com/fork@v2.0.0") {
		t.Errorf("the fork must be the attributed module:\n%s", got)
	}
	if !strings.Contains(got, "Replaces: example.com/upstream@v1.5.0") {
		t.Errorf("the requirement it stands in for must be named:\n%s", got)
	}
}

// A review item for a replaced module names the requirement too: the operator
// reads "no licence record" against a coordinate that is in no go.mod they
// wrote, and needs to know which requirement produced it.
func TestNoticeWith_ReviewItemNamesTheReplacedRequirement(t *testing.T) {
	fork := coordinatetest.MustNew("example.com/fork", "v2.0.0")
	required := coordinatetest.MustNew("example.com/upstream", "v1.5.0")

	fqw := testfakes.NewFakeQueryWalks()
	fqw.AddWalk(walkdomain.WalkRecord{ID: "W1", Graph: walkdomain.Graph{Nodes: []walkdomain.GraphNode{
		{Coordinate: fork, OriginalCoordinate: required, ResolutionSource: walkdomain.ResolutionReplace},
	}}})
	ctr := &Container{
		QueryWalks: fqw,
		GenerateNotice: &testfakes.FakeGenerateNotice{Result: licapp.NoticeResult{
			ReviewItems: []licdomain.ReviewItem{{Coordinate: fork, Reason: "no license detected"}},
		}},
	}

	var stdout, stderr bytes.Buffer
	err := noticeWith(context.Background(), ctr, "W1", "", "", "", "", &stdout, &stderr)
	if err == nil {
		t.Fatal("expected a review-required error")
	}
	if !strings.Contains(stderr.String(), "example.com/fork@v2.0.0 (replaces example.com/upstream@v1.5.0)") {
		t.Errorf("the review line must name both, got: %q", stderr.String())
	}
}

// Guards the assumption the local-replace branch rests on: a coordinate's zero
// value is distinguishable from a real one, so "no attributable coordinate" can
// never be mistaken for a module.
func TestNoticeModule_ZeroCoordinateIsDistinguishable(t *testing.T) {
	var zero coordinate.ModuleCoordinate
	if zero.Path() != "" {
		t.Errorf("the zero coordinate must have an empty path, got %q", zero.Path())
	}
}
