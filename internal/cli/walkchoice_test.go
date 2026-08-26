package cli

import (
	"bytes"
	"context"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/eitanity/kanonarion/internal/cli/testfakes"
	"github.com/eitanity/kanonarion/internal/coordinate"
	"github.com/eitanity/kanonarion/internal/coordinate/coordinatetest"
	licdomain "github.com/eitanity/kanonarion/internal/license/domain"
	walkapp "github.com/eitanity/kanonarion/internal/walk/application"
	walkdomain "github.com/eitanity/kanonarion/internal/walk/domain"
	walkports "github.com/eitanity/kanonarion/internal/walk/ports"
)

// selectionProject writes a go.mod requiring jwt at the given version and
// returns the directory holding it.
//
// It is the manifest a project walk was taken from, and the file the default
// frame rule compares a walk's recorded resolution against.
func selectionProject(t *testing.T, modulePath, jwtVersion string) string {
	t.Helper()
	dir := t.TempDir()
	body := "module " + modulePath + "\n\ngo 1.26\n\nrequire (\n\tgithub.com/golang-jwt/jwt/v4 " + jwtVersion + "\n\tgithub.com/spf13/cobra v1.8.1\n)\n"
	if err := os.WriteFile(filepath.Join(dir, "go.mod"), []byte(body), 0o600); err != nil {
		t.Fatalf("writing go.mod: %v", err)
	}
	return dir
}

// selectionWalk builds a project walk rooted at dir that resolved jwt at
// jwtVersion. cobra is carried at a fixed version by every walk, so a walk that
// disagrees with the manifest disagrees on exactly one module.
func selectionWalk(t *testing.T, id, modulePath, dir, jwtVersion string) walkdomain.WalkRecord {
	t.Helper()
	local, err := coordinate.NewLocalCoordinate(modulePath)
	if err != nil {
		t.Fatalf("local coordinate: %v", err)
	}
	return walkdomain.WalkRecord{
		ID:            id,
		Target:        local,
		Scope:         walkdomain.WalkScopeCode,
		OverallStatus: walkdomain.WalkSucceeded,
		ProjectDir:    dir,
		Graph: walkdomain.Graph{
			Target: local,
			Nodes: []walkdomain.GraphNode{
				{Coordinate: local, ResolutionSource: walkdomain.ResolutionLocalMainModule},
				{Coordinate: coordinatetest.MustNew("github.com/golang-jwt/jwt/v4", jwtVersion), ResolutionSource: walkdomain.ResolutionMVS},
				{Coordinate: coordinatetest.MustNew("github.com/spf13/cobra", "v1.8.1"), ResolutionSource: walkdomain.ResolutionMVS},
			},
			BuildEnv: walkdomain.BuildEnv{GOOS: runtime.GOOS, GOARCH: runtime.GOARCH, GoVersion: "go1.26.4"},
		},
	}
}

// selectionStore returns a walk store holding the records, with summaries in the
// order the SQL adapter produces: newest first. recs must be given newest first.
func selectionStore(recs ...walkdomain.WalkRecord) *testfakes.FakeQueryWalks {
	qw := testfakes.NewFakeQueryWalks()
	summaries := make([]walkports.WalkSummary, 0, len(recs))
	for _, rec := range recs {
		qw.AddWalk(rec)
		summaries = append(summaries, walkports.WalkSummary{
			ID:            rec.ID,
			Target:        rec.Target,
			Scope:         rec.Scope,
			OverallStatus: rec.OverallStatus,
			GOOS:          rec.Graph.BuildEnv.GOOS,
			GOARCH:        rec.Graph.BuildEnv.GOARCH,
		})
	}
	qw.SetSummaries(summaries)
	return qw
}

// A walk taken while a manifest was temporarily edited stays the newest row
// forever: walk identity reuses an existing record when the resolution is
// unchanged, and reuse preserves that record's original started_at, so
// re-walking the restored tree cannot make the matching walk newest again.
// Recency-only selection therefore answers about a build that is not on disk,
// and the remedy the tool names cannot displace it.
//
// The default now prefers a walk whose recorded resolution still agrees with the
// manifest, and says which rule it applied.
func TestChooseWalk_PrefersTheWalkThatMatchesTheManifestOverTheNewer(t *testing.T) {
	const modulePath = "example.com/app"
	dir := selectionProject(t, modulePath, "v4.5.1")
	rehearsal := selectionWalk(t, "W-rehearsal", modulePath, dir, "v4.5.2")
	matching := selectionWalk(t, "W-matching", modulePath, dir, "v4.5.1")
	walks := selectionStore(rehearsal, matching)

	summaries, err := walks.ListWalks(context.Background(), walkports.WalkFilter{})
	if err != nil {
		t.Fatalf("ListWalks: %v", err)
	}
	choice := chooseWalk(context.Background(), walks, summaries, "")

	if choice.summary.ID != matching.ID {
		t.Errorf("chose walk %s, want the manifest-matching %s", choice.summary.ID, matching.ID)
	}
	if choice.rule != walkChosenManifestMatch {
		t.Errorf("rule = %v, want walkChosenManifestMatch", choice.rule)
	}
	if got := choice.selection().Rule; got != "manifest-match" {
		t.Errorf("selection rule = %q, want manifest-match", got)
	}
	if note := choice.statement(); !strings.Contains(note, "still agrees with") || !strings.Contains(note, "--walk-id") {
		t.Errorf("statement does not name the rule and the selector: %q", note)
	}
}

// Where nothing on disk matches, the answer still comes from the newest walk —
// recency remains the fallback — but it says so, names what it disagrees with,
// and names a remedy that can actually displace it. `walk --gomod` writes a new
// record here precisely because no stored walk records this resolution.
func TestChooseWalk_FallsBackToRecencyAndNamesWhatDisagrees(t *testing.T) {
	const modulePath = "example.com/app"
	dir := selectionProject(t, modulePath, "v4.5.3")
	newer := selectionWalk(t, "W-newer", modulePath, dir, "v4.5.2")
	older := selectionWalk(t, "W-older", modulePath, dir, "v4.5.1")
	walks := selectionStore(newer, older)

	summaries, _ := walks.ListWalks(context.Background(), walkports.WalkFilter{})
	choice := chooseWalk(context.Background(), walks, summaries, "")

	if choice.summary.ID != newer.ID {
		t.Errorf("chose walk %s, want the most recent %s", choice.summary.ID, newer.ID)
	}
	if choice.rule != walkChosenRecencyNoMatch {
		t.Fatalf("rule = %v, want walkChosenRecencyNoMatch", choice.rule)
	}
	note := choice.statement()
	for _, want := range []string{
		"github.com/golang-jwt/jwt/v4 v4.5.2 -> v4.5.3",
		"kanonarion walk --gomod",
	} {
		if !strings.Contains(note, want) {
			t.Errorf("statement missing %q; got %q", want, note)
		}
	}
	if got := choice.selection().Disagreements; len(got) != 1 {
		t.Errorf("selection disagreements = %v, want one", got)
	}
}

// A walk of a published coordinate has no manifest anywhere on disk, so recency
// is the only rule available. The answer says that rather than implying a
// comparison was made.
func TestChooseWalk_WithoutAManifestSaysWhatItCouldNotCheck(t *testing.T) {
	coord := coordinatetest.MustNew("example.com/m", "v1.0.0")
	mk := func(id string) walkdomain.WalkRecord {
		return walkdomain.WalkRecord{ID: id, Target: coord, OverallStatus: walkdomain.WalkSucceeded}
	}
	walks := selectionStore(mk("W2"), mk("W1"))

	summaries, _ := walks.ListWalks(context.Background(), walkports.WalkFilter{})
	choice := chooseWalk(context.Background(), walks, summaries, "")

	if choice.summary.ID != "W2" {
		t.Errorf("chose %s, want the most recent W2", choice.summary.ID)
	}
	if choice.rule != walkChosenRecencyUnchecked {
		t.Fatalf("rule = %v, want walkChosenRecencyUnchecked", choice.rule)
	}
	if note := choice.statement(); !strings.Contains(note, "records no project directory") {
		t.Errorf("statement does not say what could not be compared: %q", note)
	}
}

// One walk is no choice, so nothing is stated. This is the zero-pair for the
// multiple-candidates statement: a notice printed here would be boilerplate
// everywhere else, and boilerplate is what a reader stops reading.
func TestChooseWalk_SingleWalkStatesNothing(t *testing.T) {
	const modulePath = "example.com/app"
	dir := selectionProject(t, modulePath, "v4.5.1")
	only := selectionWalk(t, "W-only", modulePath, dir, "v4.5.1")
	walks := selectionStore(only)

	summaries, _ := walks.ListWalks(context.Background(), walkports.WalkFilter{})
	choice := chooseWalk(context.Background(), walks, summaries, "")

	if choice.rule != walkChosenSole {
		t.Errorf("rule = %v, want walkChosenSole", choice.rule)
	}
	if note := choice.statement(); note != "" {
		t.Errorf("a single-walk store stated a choice: %q", note)
	}
	if clause := choice.statementClause(); clause != "" {
		t.Errorf("a single-walk store appended a clause: %q", clause)
	}
}

// A narrower walk of the same tree requires fewer modules than the manifest
// names. That is a scope difference, not drift: reading it as drift would
// declare every code-scope walk stale against the go.mod it was taken from.
func TestManifestRequireDisagreement_ScopeDifferenceIsNotDisagreement(t *testing.T) {
	const modulePath = "example.com/app"
	dir := selectionProject(t, modulePath, "v4.5.1")
	rec := selectionWalk(t, "W", modulePath, dir, "v4.5.1")
	// A code-scope walk that never carried cobra at all.
	rec.Graph.Nodes = rec.Graph.Nodes[:2]

	got, err := manifestRequireDisagreement(filepath.Join(dir, "go.mod"), rec)
	if err != nil {
		t.Fatalf("manifestRequireDisagreement: %v", err)
	}
	if len(got) != 0 {
		t.Errorf("disagreements = %v, want none", got)
	}
}

// A manifest naming no module the walk resolved settles nothing, and an empty
// comparison must not be reported as a clean one.
func TestManifestRequireDisagreement_NothingInCommonIsAnError(t *testing.T) {
	const modulePath = "example.com/app"
	dir := selectionProject(t, modulePath, "v4.5.1")
	rec := selectionWalk(t, "W", modulePath, dir, "v4.5.1")
	rec.Graph.Nodes = rec.Graph.Nodes[:1] // the main module alone

	if _, err := manifestRequireDisagreement(filepath.Join(dir, "go.mod"), rec); err == nil {
		t.Fatal("a comparison over nothing returned no error")
	}
}

// The --gomod route defaults its frame through the same rule, which is the route
// the reachability read that exposed this took.
func TestLatestWalkForGoMod_PrefersTheManifestMatchingWalk(t *testing.T) {
	const modulePath = "example.com/app"
	dir := selectionProject(t, modulePath, "v4.5.1")
	rehearsal := selectionWalk(t, "W-rehearsal", modulePath, dir, "v4.5.2")
	matching := selectionWalk(t, "W-matching", modulePath, dir, "v4.5.1")
	walks := selectionStore(rehearsal, matching)

	choice, err := latestWalkForGoMod(context.Background(), walks, filepath.Join(dir, "go.mod"), scopeCode)
	if err != nil {
		t.Fatalf("latestWalkForGoMod: %v", err)
	}
	if choice.summary.ID != matching.ID {
		t.Errorf("--gomod resolved to walk %s, want %s", choice.summary.ID, matching.ID)
	}
	if note := choice.stalenessNote(); !strings.Contains(note, "agree with that walk") {
		t.Errorf("staleness note does not say what was checked: %q", note)
	}
	if clause := choice.statementClause(); !strings.Contains(clause, "--walk-id") {
		t.Errorf("clause does not offer the selector: %q", clause)
	}
}

// -- license-compat --

// compatConflictReport is a licence position with one incompatible dependency.
func compatConflictReport() licdomain.ClosureCompatibilityReport {
	return licdomain.ClosureCompatibilityReport{
		TargetSPDX:  "Apache-2.0",
		DataVersion: "1.0.0",
		Conflicts: []licdomain.CompatibilityConflict{{
			ModulePath:    "example.com/copyleft",
			ModuleVersion: "v1.0.0",
			DepSPDX:       "GPL-3.0-only",
			TargetSPDX:    "Apache-2.0",
			Verdict:       licdomain.VerdictIncompatible,
		}},
	}
}

// compatCleanReport is a licence position with nothing to report.
func compatCleanReport() licdomain.ClosureCompatibilityReport {
	return licdomain.ClosureCompatibilityReport{TargetSPDX: "Apache-2.0", DataVersion: "1.0.0", Clean: true}
}

// publishedWalksWithDifferentPositions builds two walks of one PUBLISHED
// coordinate — which has no manifest anywhere on disk, so recency is the only
// rule the default can apply — giving the newer a clean licence position and the
// older a conflicting one.
func publishedWalksWithDifferentPositions() (*Container, *testfakes.FakeCheckCompatibility, coordinate.ModuleCoordinate) {
	coord := coordinatetest.MustNew("example.com/m", "v1.0.0")
	mk := func(id string) walkdomain.WalkRecord {
		return walkdomain.WalkRecord{ID: id, Target: coord, OverallStatus: walkdomain.WalkSucceeded}
	}
	check := &testfakes.FakeCheckCompatibility{
		ReportByWalk: map[string]licdomain.ClosureCompatibilityReport{
			"W-newer": compatCleanReport(),
			"W-older": compatConflictReport(),
		},
	}
	return &Container{QueryWalks: selectionStore(mk("W-newer"), mk("W-older")), CheckCompatibility: check}, check, coord
}

// The acceptance case: two walks of one target with DIFFERENT licence positions.
// The pinned answer follows the pin, not recency — and the exit code follows it
// too, because the exit code is the part a caller automates against.
func TestLicenseCompat_PinnedWalkAnswersInThatWalkNotTheNewest(t *testing.T) {
	ctr, check, coord := publishedWalksWithDifferentPositions()

	var unpinned bytes.Buffer
	if err := licenseCompatWith(context.Background(), ctr, coord, "Apache-2.0", "", &unpinned, io.Discard); err != nil {
		t.Fatalf("the newest walk is clean, so the default should exit 0: %v", err)
	}
	if got := check.AskedWalkIDs; len(got) != 1 || got[0] != "W-newer" {
		t.Fatalf("the default asked about %v, want the most recent W-newer", got)
	}

	check.AskedWalkIDs = nil
	var pinned bytes.Buffer
	err := licenseCompatWith(context.Background(), ctr, coord, "Apache-2.0", "W-older", &pinned, io.Discard)
	requireExit(t, err, ExitPartial)

	if got := check.AskedWalkIDs; len(got) != 1 || got[0] != "W-older" {
		t.Fatalf("the pinned run asked about %v, want only W-older", got)
	}
	body := pinned.String()
	if !strings.Contains(body, "W-older") {
		t.Errorf("report does not name the pinned walk: %s", body)
	}
	if !strings.Contains(body, "example.com/copyleft") {
		t.Errorf("report does not carry the pinned walk's licence position: %s", body)
	}
	if strings.Contains(body, "no walk was named") {
		t.Errorf("a pinned answer stated that a walk was chosen for the caller: %s", body)
	}
}

// The unpinned answer on that store says the choice was made for the caller, and
// how to make it themselves.
func TestLicenseCompat_UnpinnedAnswerStatesThatItChose(t *testing.T) {
	ctr, _, coord := publishedWalksWithDifferentPositions()

	var out bytes.Buffer
	if err := licenseCompatWith(context.Background(), ctr, coord, "Apache-2.0", "", &out, io.Discard); err != nil {
		t.Fatalf("the newest walk is clean, so this should exit 0: %v", err)
	}
	body := out.String()
	for _, want := range []string{"no walk was named", "the store holds 2", "--walk-id"} {
		if !strings.Contains(body, want) {
			t.Errorf("unpinned answer missing %q; got:\n%s", want, body)
		}
	}
}

// The other face of the same defect, end to end: a rehearsal walk of a
// temporarily-bumped manifest is the newest walk of the project and carries a
// different licence position. The default no longer answers from it, because its
// recorded resolution no longer agrees with the go.mod that walk was taken from.
func TestLicenseCompat_DefaultPrefersTheWalkMatchingTheManifest(t *testing.T) {
	const modulePath = "example.com/app"
	dir := selectionProject(t, modulePath, "v4.5.1")
	rehearsal := selectionWalk(t, "W-rehearsal", modulePath, dir, "v4.5.2")
	restored := selectionWalk(t, "W-restored", modulePath, dir, "v4.5.1")
	check := &testfakes.FakeCheckCompatibility{
		ReportByWalk: map[string]licdomain.ClosureCompatibilityReport{
			rehearsal.ID: compatConflictReport(),
			restored.ID:  compatCleanReport(),
		},
	}
	ctr := &Container{QueryWalks: selectionStore(rehearsal, restored), CheckCompatibility: check}

	var out bytes.Buffer
	if err := licenseCompatWith(context.Background(), ctr, restored.Target, "Apache-2.0", "", &out, io.Discard); err != nil {
		t.Fatalf("the manifest-matching walk is clean, so this should exit 0: %v", err)
	}
	if got := check.AskedWalkIDs; len(got) != 1 || got[0] != restored.ID {
		t.Fatalf("answered from %v, want the manifest-matching %s", got, restored.ID)
	}
	if body := out.String(); !strings.Contains(body, "still agrees with") {
		t.Errorf("the answer does not say which rule picked its walk:\n%s", body)
	}
}

// Zero-pair for the statement above: one walk, no statement.
func TestLicenseCompat_SingleWalkStoreDoesNotStateAChoice(t *testing.T) {
	const modulePath = "example.com/app"
	dir := selectionProject(t, modulePath, "v4.5.1")
	only := selectionWalk(t, "W-only", modulePath, dir, "v4.5.1")
	ctr := &Container{
		QueryWalks:         selectionStore(only),
		CheckCompatibility: &testfakes.FakeCheckCompatibility{Report: licdomain.ClosureCompatibilityReport{TargetSPDX: "Apache-2.0", Clean: true}},
	}

	var out bytes.Buffer
	if err := licenseCompatWith(context.Background(), ctr, only.Target, "Apache-2.0", "", &out, io.Discard); err != nil {
		t.Fatalf("clean closure should exit 0: %v", err)
	}
	if strings.Contains(out.String(), "no walk was named") {
		t.Errorf("a single-walk store stated a choice:\n%s", out.String())
	}
}

// A walk id the store does not hold is refused, and the refusal names the
// command that lists the ids that would work.
func TestLicenseCompat_UnknownWalkIDRefusesNamingTheRemedy(t *testing.T) {
	ctr, _, coord := publishedWalksWithDifferentPositions()

	var out bytes.Buffer
	err := licenseCompatWith(context.Background(), ctr, coord, "Apache-2.0", "W-nope", &out, io.Discard)
	requireExit(t, err, ExitConfig)
	if !strings.Contains(err.Error(), "kanonarion walk-list --target") {
		t.Errorf("refusal does not name the remedy: %v", err)
	}
	if out.Len() != 0 {
		t.Errorf("a refused invocation wrote a report: %s", out.String())
	}
}

// A walk id the store DOES hold, but rooted at another project, is the worse
// mistake: it would answer confidently about a different build. It is refused by
// name.
func TestLicenseCompat_WalkIDRootedElsewhereIsRefused(t *testing.T) {
	const modulePath = "example.com/app"
	dir := selectionProject(t, modulePath, "v4.5.1")
	ours := selectionWalk(t, "W-ours", modulePath, dir, "v4.5.1")
	theirs := selectionWalk(t, "W-theirs", "example.com/other", selectionProject(t, "example.com/other", "v4.5.1"), "v4.5.1")
	walks := selectionStore(ours, theirs)
	ctr := &Container{
		QueryWalks:         walks,
		CheckCompatibility: &testfakes.FakeCheckCompatibility{Report: licdomain.ClosureCompatibilityReport{TargetSPDX: "Apache-2.0", Clean: true}},
	}

	var out bytes.Buffer
	err := licenseCompatWith(context.Background(), ctr, ours.Target, "Apache-2.0", theirs.ID, &out, io.Discard)
	requireExit(t, err, ExitConfig)
	if !strings.Contains(err.Error(), "is rooted at example.com/other") {
		t.Errorf("refusal does not name the walk's own root: %v", err)
	}
}

// The walk id typed positionally is the natural mistake: every sibling command
// that takes one takes it there. The refusal names the flag rather than only
// saying the coordinate did not parse.
func TestLicenseCompat_WalkIDTypedPositionallyNamesTheFlag(t *testing.T) {
	const id = "01KZ42BGN0T95D932JMC1GXX3C"
	err := runLicenseCompat(context.Background(), id, "Apache-2.0", "", io.Discard, io.Discard)
	requireExit(t, err, ExitConfig)
	if !strings.Contains(err.Error(), "--walk-id "+id) {
		t.Errorf("refusal does not name the selector: %v", err)
	}
}

// -- use --

// useWalks builds two walks of ONE published coordinate whose version sets
// differ, which is the case `use` materialises on disk: the newer resolved uuid
// at v1.6.0, the older at v1.3.0.
func useWalks() (*testfakes.FakeQueryWalks, coordinate.ModuleCoordinate) {
	coord := coordinatetest.MustNew("example.com/m", "v1.0.0")
	mk := func(id, uuidVersion string) walkdomain.WalkRecord {
		return walkdomain.WalkRecord{
			ID: id, Target: coord, OverallStatus: walkdomain.WalkSucceeded,
			Graph: walkdomain.Graph{
				Target: coord,
				Nodes: []walkdomain.GraphNode{
					{Coordinate: coord},
					{Coordinate: coordinatetest.MustNew("github.com/google/uuid", uuidVersion)},
				},
			},
		}
	}
	return selectionStore(mk("W-newer", "v1.6.0"), mk("W-older", "v1.3.0")), coord
}

// The acceptance case. `use --recursive` copies the walk's version set into a
// module cache a later build compiles against, so a pin has to reach the bytes:
// the pinned run must copy the pinned walk's set, not the newest walk's.
func TestUse_PinnedWalkSuppliesTheVersionSetNotTheNewest(t *testing.T) {
	walks, coord := useWalks()

	var unpinned bytes.Buffer
	rec, err := useTargetWalk(context.Background(), walks, coord, "", &unpinned)
	if err != nil {
		t.Fatalf("unpinned: %v", err)
	}
	if rec.ID != "W-newer" {
		t.Fatalf("the default copied walk %s, want the most recent W-newer", rec.ID)
	}

	var pinned bytes.Buffer
	rec, err = useTargetWalk(context.Background(), walks, coord, "W-older", &pinned)
	if err != nil {
		t.Fatalf("pinned: %v", err)
	}
	if rec.ID != "W-older" {
		t.Fatalf("the pinned run copied walk %s, want W-older", rec.ID)
	}
	if got := rec.Graph.Nodes[1].Coordinate.Version(); got != "v1.3.0" {
		t.Errorf("pinned run would copy uuid %s, want the pinned walk's v1.3.0", got)
	}
	if strings.Contains(pinned.String(), "no walk was named") {
		t.Errorf("a pinned copy stated that a walk was chosen for the caller: %s", pinned.String())
	}
	if !strings.Contains(pinned.String(), "W-older") {
		t.Errorf("the copy does not name the walk that supplied the bytes: %s", pinned.String())
	}
}

// Unpinned, the copy says which walk supplied the bytes, that the walk was
// chosen rather than named, and how to name one. Nothing else in a `use` run
// records where the cache entries came from.
func TestUse_UnpinnedCopyNamesTheWalkAndHowToPin(t *testing.T) {
	walks, coord := useWalks()

	var stderr bytes.Buffer
	if _, err := useTargetWalk(context.Background(), walks, coord, "", &stderr); err != nil {
		t.Fatalf("useTargetWalk: %v", err)
	}
	for _, want := range []string{
		"==> use: copying the version set of walk W-newer",
		"no walk was named",
		"the store holds 2",
		"--walk-id",
	} {
		if !strings.Contains(stderr.String(), want) {
			t.Errorf("the copy did not state %q; got:\n%s", want, stderr.String())
		}
	}
}

// A walk id the store does not hold is refused before anything is written to a
// cache, and the refusal names the command that lists ids that would work.
func TestUse_UnknownWalkIDRefusesNamingTheRemedy(t *testing.T) {
	walks, coord := useWalks()

	var stderr bytes.Buffer
	_, err := useTargetWalk(context.Background(), walks, coord, "W-nope", &stderr)
	requireExit(t, err, ExitConfig)
	if !strings.Contains(err.Error(), "kanonarion walk-list --target") {
		t.Errorf("refusal does not name the remedy: %v", err)
	}
	if stderr.Len() != 0 {
		t.Errorf("a refused copy announced a walk: %s", stderr.String())
	}
}

// A walk rooted at another target would put another project's version set in
// the cache. It is refused by name.
func TestUse_WalkIDRootedElsewhereIsRefused(t *testing.T) {
	walks, coord := useWalks()
	other := coordinatetest.MustNew("example.com/other", "v2.0.0")
	walks.AddWalk(walkdomain.WalkRecord{ID: "W-theirs", Target: other, OverallStatus: walkdomain.WalkSucceeded})

	var stderr bytes.Buffer
	_, err := useTargetWalk(context.Background(), walks, coord, "W-theirs", &stderr)
	requireExit(t, err, ExitConfig)
	if !strings.Contains(err.Error(), "is rooted at example.com/other") {
		t.Errorf("refusal does not name the walk's own root: %v", err)
	}
}

// -- the walk a run produced --

// A command that walks and then reads what it walked must be handed the record
// the run produced. Identity reuse serves an existing record when the resolution
// is unchanged and keeps its original started_at, so the walk a run produced can
// be older than another walk of the same target — and "the newest walk of this
// coordinate" then names the wrong one.
func TestRunWalk_ReturnsTheRecordTheRunProduced(t *testing.T) {
	coord := coordinatetest.MustNew("example.com/m", "v1.0.0")
	reused := walkdomain.WalkRecord{
		ID: "W-reused", Target: coord, OverallStatus: walkdomain.WalkSucceeded,
		Graph: walkdomain.Graph{Target: coord, BuildEnv: walkdomain.BuildEnv{GOOS: "linux", GOARCH: "amd64"}},
	}
	uc := &testfakes.FakeExecuteWalk{Result: walkapp.ExecuteWalkResult{Record: reused, Reused: true}}

	result, err := runWalk(context.Background(), "example.com/m@v1.0.0", commonWalkFlags{}, false, true, 0,
		"", "", false, walkdomain.WalkScopeCode, walkdomain.WalkDepthFull, "", nil, uc, nil, io.Discard, io.Discard)
	if err != nil {
		t.Fatalf("runWalk: %v", err)
	}
	if result.Record.ID != reused.ID {
		t.Errorf("runWalk returned walk %q, want the record the run resolved to (%q)", result.Record.ID, reused.ID)
	}
	if got := walkSummaryOf(result.Record); got.ID != reused.ID || got.BuildFrame() != "linux/amd64" {
		t.Errorf("summary of the produced record = %+v, want id %q and frame linux/amd64", got, reused.ID)
	}
}

// -- context's dependency section --

// The dependency list is a list for one build, and a project with several walks
// has several. The section runs the same rule as every other defaulting read
// rather than taking the newest walk, and the walk it answered from is on the
// document.
func TestBuildDependencies_AnswersFromTheManifestMatchingWalk(t *testing.T) {
	const modulePath = "example.com/app"
	dir := selectionProject(t, modulePath, "v4.5.1")
	rehearsal := selectionWalk(t, "W-rehearsal", modulePath, dir, "v4.5.2")
	matching := selectionWalk(t, "W-matching", modulePath, dir, "v4.5.1")
	for i := range matching.Graph.Nodes {
		matching.Graph.Nodes[i].DirectDependency = true
	}
	walks := selectionStore(rehearsal, matching)

	got := buildDependencies(context.Background(), matching.Target, walks, basisWalk{})
	if got.WalkID != matching.ID {
		t.Errorf("dependency section answered from walk %q, want the manifest-matching %q", got.WalkID, matching.ID)
	}
	if got.Count != len(matching.Graph.Nodes) {
		t.Errorf("count = %d, want the matching walk's %d direct nodes", got.Count, len(matching.Graph.Nodes))
	}
}

// TestWalkChoice_StatesTheToolchainOnlyWhenTheCandidatesDisagree: the choice
// between two walks that differ on the toolchain decides which standard library
// the answer is about, so it is stated. Where every candidate was resolved by one
// toolchain there is nothing to have chosen, and a line printed anyway is
// boilerplate that teaches a reader to skip the notice.
func TestWalkChoice_StatesTheToolchainOnlyWhenTheCandidatesDisagree(t *testing.T) {
	local, err := coordinate.NewLocalCoordinate("example.com/myapp")
	if err != nil {
		t.Fatalf("local coordinate: %v", err)
	}
	summary := func(id, goVersion string) walkports.WalkSummary {
		return walkports.WalkSummary{
			ID: id, Target: local, Scope: walkdomain.WalkScopeCode,
			OverallStatus: walkdomain.WalkSucceeded,
			GOOS:          "linux", GOARCH: "amd64", GoVersion: goVersion,
		}
	}
	qw := testfakes.NewFakeQueryWalks()

	mixed := chooseWalk(context.Background(), qw,
		[]walkports.WalkSummary{summary("walk-new", "go1.26.6"), summary("walk-old", "go1.26.5")}, "")
	for _, want := range []string{"go1.26.5", "go1.26.6", "standard library"} {
		if !strings.Contains(mixed.statement(), want) {
			t.Errorf("the notice does not name %q:\n%s", want, mixed.statement())
		}
	}
	if !strings.Contains(mixed.statementClause(), "go1.26.6") {
		t.Errorf("the clause does not name the toolchain chosen: %s", mixed.statementClause())
	}

	uniform := chooseWalk(context.Background(), qw,
		[]walkports.WalkSummary{summary("walk-a", "go1.26.6"), summary("walk-b", "go1.26.6")}, "")
	if strings.Contains(uniform.statement(), "standard library") {
		t.Errorf("a single-toolchain target got a toolchain note:\n%s", uniform.statement())
	}
	if strings.Contains(uniform.statementClause(), "standard library") {
		t.Errorf("a single-toolchain target got a toolchain clause: %s", uniform.statementClause())
	}
}
