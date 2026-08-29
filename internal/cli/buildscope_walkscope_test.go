package cli

import (
	"context"
	"path/filepath"
	"strings"
	"testing"

	"github.com/eitanity/kanonarion/internal/cli/testfakes"
	"github.com/eitanity/kanonarion/internal/coordinate"
	"github.com/eitanity/kanonarion/internal/coordinate/coordinatetest"
	vuldomain "github.com/eitanity/kanonarion/internal/vuln/domain"
	walkdomain "github.com/eitanity/kanonarion/internal/walk/domain"
)

// A project is walked in several scopes, and they are different builds: on this
// repo the code walk holds 22 module versions and the tool walk 246, 235 of
// which the code walk does not contain. A read that resolves a walk from a
// go.mod therefore has to ask for the scope it means; recency across all scopes
// answers whichever was walked last.
//
// inScope returns the walk with its scope and platform set, so the summaries the
// store lists carry both axes the selector now filters on.
func inScope(rec walkdomain.WalkRecord, scope walkdomain.WalkScope) walkdomain.WalkRecord {
	rec.Scope = scope
	return rec
}

// onPlatform returns the walk as resolved for another platform, so a test can
// assert that a build for a GOOS this read is not asking about does not answer.
func onPlatform(rec walkdomain.WalkRecord, goos, goarch string) walkdomain.WalkRecord {
	rec.Graph.BuildEnv.GOOS = goos
	rec.Graph.BuildEnv.GOARCH = goarch
	return rec
}

// The scope the caller asked for decides which walk answers, not which walk is
// newest. This is the whole defect: `--tool` was accepted and discarded, and the
// newest walk — a code walk here — answered a question about the tooling
// closure.
func TestLatestWalkForGoMod_AnswersFromTheScopeAsked(t *testing.T) {
	const modulePath = "example.com/app"
	dir := selectionProject(t, modulePath, "v4.5.1")
	code := inScope(selectionWalk(t, "W-code", modulePath, dir, "v4.5.1"), walkdomain.WalkScopeCode)
	tool := inScope(selectionWalk(t, "W-tool", modulePath, dir, "v4.5.1"), walkdomain.WalkScopeTool)
	// Newest first, which is the order the SQL adapter produces: the code walk
	// wins on recency and must still lose on scope.
	walks := selectionStore(code, tool)

	choice, err := latestWalkForGoMod(context.Background(), walks, filepath.Join(dir, "go.mod"), scopeTool)
	if err != nil {
		t.Fatalf("latestWalkForGoMod: %v", err)
	}
	if choice.summary.ID != tool.ID {
		t.Fatalf("--tool resolved to walk %s, want the tool-scope %s", choice.summary.ID, tool.ID)
	}
	if choice.summary.Scope != walkdomain.WalkScopeTool {
		t.Errorf("chosen walk is scope %q, want tool", choice.summary.Scope)
	}
}

// A read with no scope flag asks for the code scope, deterministically —
// whichever scope was walked most recently. Nine of the eleven commands on this
// selector cannot name a scope, so this is the answer they get.
func TestLatestWalkForGoMod_ScopelessReadTakesTheCodeWalkNotTheNewest(t *testing.T) {
	const modulePath = "example.com/app"
	dir := selectionProject(t, modulePath, "v4.5.1")
	tool := inScope(selectionWalk(t, "W-tool", modulePath, dir, "v4.5.1"), walkdomain.WalkScopeTool)
	code := inScope(selectionWalk(t, "W-code", modulePath, dir, "v4.5.1"), walkdomain.WalkScopeCode)
	walks := selectionStore(tool, code) // the tool walk is the newest

	choice, err := latestWalkForGoMod(context.Background(), walks, filepath.Join(dir, "go.mod"), scopeCode)
	if err != nil {
		t.Fatalf("latestWalkForGoMod: %v", err)
	}
	if choice.summary.ID != code.ID {
		t.Fatalf("a scope-less read resolved to walk %s, want the code-scope %s", choice.summary.ID, code.ID)
	}
}

// The falsifying case. With only a tool walk in the store, a scope-less read must
// refuse — it must not acquire a different silent fallback, because a tool walk
// answering "what does my code call" is the same wrong answer the scope filter
// exists to stop.
func TestLatestWalkForGoMod_RefusesRatherThanFallBackToAnotherScope(t *testing.T) {
	const modulePath = "example.com/app"
	dir := selectionProject(t, modulePath, "v4.5.1")
	tool := inScope(selectionWalk(t, "W-tool", modulePath, dir, "v4.5.1"), walkdomain.WalkScopeTool)
	walks := selectionStore(tool)

	choice, err := latestWalkForGoMod(context.Background(), walks, filepath.Join(dir, "go.mod"), scopeCode)
	if err == nil {
		t.Fatalf("a scope-less read answered from the tool walk %s instead of refusing", choice.summary.ID)
	}
	msg := err.Error()
	if !strings.Contains(msg, "no succeeded code project walk") {
		t.Errorf("refusal does not name the scope it looked for: %q", msg)
	}
	if !strings.Contains(msg, "run: kanonarion walk --gomod "+filepath.Join(dir, "go.mod")) {
		t.Errorf("refusal does not name the remedy: %q", msg)
	}
	if strings.Contains(msg, "--gomod "+filepath.Join(dir, "go.mod")+" --tool") {
		t.Errorf("refusal offers the tool remedy for a code-scope miss: %q", msg)
	}
	if !strings.Contains(msg, "tool on ") {
		t.Errorf("refusal does not say a walk of another scope exists: %q", msg)
	}
}

// "No walk of that scope" and "no walk at all" are different situations with the
// same symptom, and only one of them is answered by walking the other scope. The
// refusal has to tell them apart, and the remedy has to carry the scope flag
// that produces the missing walk.
func TestLatestWalkForGoMod_RefusalDistinguishesNoWalkAtAll(t *testing.T) {
	const modulePath = "example.com/app"
	dir := selectionProject(t, modulePath, "v4.5.1")
	walks := selectionStore() // nothing walked this project at all

	_, err := latestWalkForGoMod(context.Background(), walks, filepath.Join(dir, "go.mod"), scopeTool)
	if err == nil {
		t.Fatal("an empty store produced no refusal")
	}
	msg := err.Error()
	if !strings.Contains(msg, "no succeeded project walk for "+modulePath) {
		t.Errorf("refusal does not say the project has no walk at all: %q", msg)
	}
	if strings.Contains(msg, "though the store holds") {
		t.Errorf("refusal claims other walks exist: %q", msg)
	}
	if !strings.Contains(msg, "run: kanonarion walk --gomod "+filepath.Join(dir, "go.mod")+" --tool") {
		t.Errorf("refusal does not name the flag that produces a tool walk: %q", msg)
	}
}

// The platform is pinned on the same terms as the scope. A walk resolved for
// another GOOS selected other files, so it describes another build and does not
// answer here.
func TestLatestWalkForGoMod_RefusesAWalkOfAnotherPlatform(t *testing.T) {
	const modulePath = "example.com/app"
	dir := selectionProject(t, modulePath, "v4.5.1")
	other := otherPlatform()
	foreign := onPlatform(
		inScope(selectionWalk(t, "W-foreign", modulePath, dir, "v4.5.1"), walkdomain.WalkScopeCode),
		other.GOOS, other.GOARCH)
	walks := selectionStore(foreign)

	choice, err := latestWalkForGoMod(context.Background(), walks, filepath.Join(dir, "go.mod"), scopeCode)
	if err == nil {
		t.Fatalf("a read answered from walk %s, resolved for %s", choice.summary.ID, other)
	}
	if msg := err.Error(); !strings.Contains(msg, hostPlatform().String()) || !strings.Contains(msg, "code on "+other.String()) {
		t.Errorf("refusal does not name the platform asked for and the one held: %q", msg)
	}
}

// A count of candidates is a count of something. Once the listing is narrowed,
// "the store holds 1 walk of this target" would be false for a project walked in
// three scopes, so the notices say what they counted.
func TestLatestWalkForGoMod_NotesSayWhichBuildTheCandidatesWere(t *testing.T) {
	const modulePath = "example.com/app"
	dir := selectionProject(t, modulePath, "v4.5.1")
	stale := inScope(selectionWalk(t, "W-stale", modulePath, dir, "v4.5.2"), walkdomain.WalkScopeCode)
	current := inScope(selectionWalk(t, "W-current", modulePath, dir, "v4.5.1"), walkdomain.WalkScopeCode)
	walks := selectionStore(stale, current)

	choice, err := latestWalkForGoMod(context.Background(), walks, filepath.Join(dir, "go.mod"), scopeCode)
	if err != nil {
		t.Fatalf("latestWalkForGoMod: %v", err)
	}
	want := "in the code scope on " + hostPlatform().String()
	if clause := choice.statementClause(); !strings.Contains(clause, want) {
		t.Errorf("statement clause does not say what was counted (%q): %q", want, clause)
	}
	if statement := choice.statement(); !strings.Contains(statement, want) {
		t.Errorf("statement does not say what was counted (%q): %q", want, statement)
	}
	if got := choice.selection().CandidateSet; got != want {
		t.Errorf("selection candidate_set = %q, want %q", got, want)
	}
}

// The disclosure notice names the scope of the walk it chose. It already named
// the walk, the platform, the module count and the toolchain; without the scope
// a discarded --tool reads as ordinary provenance and there is nothing for the
// reader to notice.
func TestBuildScopeFlags_NoticeNamesTheScopeOfTheChosenWalk(t *testing.T) {
	const modulePath = "example.com/app"
	dir := selectionProject(t, modulePath, "v4.5.1")
	code := inScope(selectionWalk(t, "W-code", modulePath, dir, "v4.5.1"), walkdomain.WalkScopeCode)
	tool := inScope(selectionWalk(t, "W-tool", modulePath, dir, "v4.5.1"), walkdomain.WalkScopeTool)
	walks := selectionStore(tool, code)

	f := buildScopeFlags{gomod: filepath.Join(dir, "go.mod"), gomodSet: true}
	sc, err := f.resolve(context.Background(), walks)
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if !strings.Contains(sc.source, "code scope") {
		t.Errorf("scope notice does not name the scope of the walk it chose: %q", sc.source)
	}
	if !strings.Contains(sc.source, code.ID) {
		t.Errorf("scope notice names walk %q, want the code walk %s", sc.source, code.ID)
	}
}

// Control: --walk-id overrides selection entirely. It names a record, so no
// scope or platform filter applies to it, and the notice states the scope that
// record actually carries rather than the one a --gomod read would have asked
// for.
func TestBuildScopeFlags_WalkIDOverridesScopeSelection(t *testing.T) {
	const modulePath = "example.com/app"
	dir := selectionProject(t, modulePath, "v4.5.1")
	code := inScope(selectionWalk(t, "W-code", modulePath, dir, "v4.5.1"), walkdomain.WalkScopeCode)
	tool := inScope(selectionWalk(t, "W-tool", modulePath, dir, "v4.5.1"), walkdomain.WalkScopeTool)
	walks := selectionStore(code, tool)

	f := buildScopeFlags{walkID: tool.ID}
	sc, err := f.resolve(context.Background(), walks)
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if !strings.Contains(sc.source, tool.ID) {
		t.Errorf("--walk-id did not answer from the walk it named: %q", sc.source)
	}
	if !strings.Contains(sc.source, "tool scope") {
		t.Errorf("--walk-id notice does not name the scope of that walk: %q", sc.source)
	}
}

// A walk written before scopes were recorded names none. Showing it as the
// default would state a measurement nobody made.
func TestWalkScopeLabel_UnrecordedIsNotTheDefault(t *testing.T) {
	if got := walkScopeLabel(""); got != "unrecorded scope" {
		t.Errorf("walkScopeLabel(\"\") = %q, want unrecorded scope", got)
	}
	if got := walkScopeLabel(walkdomain.WalkScopeTool); got != "tool scope" {
		t.Errorf("walkScopeLabel(tool) = %q, want tool scope", got)
	}
}

// A refusal that names a walk names its scope. `vuln-show <tool-only module>
// --gomod` reaches this branch: the read asks for the project's code scope, the
// code walk does not contain the module, and "the walk does not contain this
// module" — said of a walk the reader did not choose and whose scope was never
// stated — reads as "nothing measured it".
func TestExplainWalkRecordAbsence_NamesTheScopeAndTheOtherScopes(t *testing.T) {
	const modulePath = "example.com/app"
	dir := selectionProject(t, modulePath, "v4.5.1")
	code := inScope(selectionWalk(t, "W-code", modulePath, dir, "v4.5.1"), walkdomain.WalkScopeCode)
	walks := selectionStore(code)

	runs := testfakes.NewFakeQueryScanRuns()
	absent := coordinatetest.MustNew("example.com/tool-only", "v1.0.0")
	present := coordinatetest.MustNew("example.com/mod", "v1.0.0")
	runs.AddRun(vuldomain.WalkScanRun{
		ID:               "run-1",
		WalkID:           code.ID,
		PipelineVersion:  vulnPipelineVersion,
		PerModuleResults: map[coordinate.ModuleCoordinate]string{present: "hash"},
	})

	err := explainWalkRecordAbsence(context.Background(), runs, walks, absent, code.ID)
	if err == nil {
		t.Fatal("a walk that does not contain the module produced no refusal")
	}
	msg := err.Error()
	if !strings.Contains(msg, "(code scope)") {
		t.Errorf("refusal does not name the scope of the walk it read: %q", msg)
	}
	if !strings.Contains(msg, "walk-list --target "+code.Target.String()) {
		t.Errorf("refusal does not point at the other scopes' walks: %q", msg)
	}
}
