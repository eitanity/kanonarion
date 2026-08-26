package cli

import (
	"context"
	"path/filepath"
	"strings"
	"testing"

	"github.com/eitanity/kanonarion/internal/cli/testfakes"
	"github.com/eitanity/kanonarion/internal/coordinate"
	walkdomain "github.com/eitanity/kanonarion/internal/walk/domain"
)

// Two walks of one project at one scope and one platform can differ only in the
// Go toolchain that resolved them, and they link different standard libraries.
// Recency deciding that axis is how one host reported a project's toolchain
// affected and clean minutes apart: a newer patch release clears advisories, so
// the newer walk answers clean for a toolchain that is not the one being built
// with.
//
// underToolchain returns the walk as resolved by one, so a test can stage the
// pair the live store cannot be made to hold.
func underToolchain(rec walkdomain.WalkRecord, version string) walkdomain.WalkRecord {
	rec.Graph.BuildEnv.GoVersion = version
	return rec
}

// selectionTarget is the project coordinate a --gomod read resolves to.
func selectionTarget(t *testing.T, modulePath string) coordinate.ModuleCoordinate {
	t.Helper()
	coord, err := coordinate.NewLocalCoordinate(modulePath)
	if err != nil {
		t.Fatalf("local coordinate: %v", err)
	}
	return coord
}

// readWalk runs the selection a --gomod read makes, over a build the test states
// rather than one probed from this host.
func readWalk(t *testing.T, walks *testfakes.FakeQueryWalks, modulePath, dir string, env walkBuildEnv) walkChoice {
	t.Helper()
	choice, err := selectProjectWalkToRead(
		context.Background(), walks, selectionTarget(t, modulePath), scopeCode, env, filepath.Join(dir, "go.mod"))
	if err != nil {
		t.Fatalf("selectProjectWalkToRead: %v", err)
	}
	return choice
}

// The falsifying case, staged: the NEWEST walk was resolved by a toolchain the
// project no longer resolves, and an older one was resolved by the toolchain it
// does. The older walk answers. Recency loses this axis outright, because the
// right walk is already in the candidate set and serving the wrong one describes
// a standard library the reader does not link.
func TestSelectProjectWalkToRead_PrefersTheToolchainTheProjectResolvesOverTheNewest(t *testing.T) {
	const modulePath = "example.com/app"
	dir := selectionProject(t, modulePath, "v4.5.1")
	newest := underToolchain(selectionWalk(t, "W-newest", modulePath, dir, "v4.5.1"), "go1.26.5")
	matching := underToolchain(selectionWalk(t, "W-matching", modulePath, dir, "v4.5.1"), "go1.26.6")
	walks := selectionStore(newest, matching) // newest first, as the adapter orders

	choice := readWalk(t, walks, modulePath, dir, hostEnvUnder("go1.26.6"))

	if choice.summary.ID != matching.ID {
		t.Fatalf("answered from walk %s (%s), want the go1.26.6 walk %s",
			choice.summary.ID, choice.summary.Toolchain(), matching.ID)
	}
	if clause := choice.toolchainDivergenceClause(); clause != "" {
		t.Errorf("a walk under the resolved toolchain still reported a divergence: %q", clause)
	}
	if got := choice.selection().ToolchainDivergence; got != "" {
		t.Errorf("selection reports a divergence for a matching walk: %q", got)
	}
	if want := "under go1.26.6"; !strings.Contains(choice.candidateSet, want) {
		t.Errorf("candidate set does not name the toolchain it narrowed on (%q): %q", want, choice.candidateSet)
	}
}

// Where NO candidate was resolved by the toolchain the project resolves today,
// the read still answers — from the newest, as before — and states which
// standard library that answer is about. The failure this replaces was a silent
// choice, not an answer, so refusing here would cost the reader the answer and
// tell them nothing the sentence does not.
func TestSelectProjectWalkToRead_NoCandidateUnderThatToolchainStillAnswersAndSaysSo(t *testing.T) {
	const modulePath = "example.com/app"
	dir := selectionProject(t, modulePath, "v4.5.1")
	newest := underToolchain(selectionWalk(t, "W-newest", modulePath, dir, "v4.5.1"), "go1.26.5")
	older := underToolchain(selectionWalk(t, "W-older", modulePath, dir, "v4.5.1"), "go1.26.5")
	walks := selectionStore(newest, older)

	choice := readWalk(t, walks, modulePath, dir, hostEnvUnder("go1.26.6"))

	if choice.summary.ID != newest.ID {
		t.Fatalf("answered from walk %s, want the newest %s", choice.summary.ID, newest.ID)
	}
	const want = "that project resolves go1.26.6 today: this answer describes go1.26.5's standard library, " +
		"not the one a build taken there now would use"
	if notes := choice.basisNotes(); !strings.Contains(notes, want) {
		t.Errorf("the basis does not name both toolchains:\n got %q\nwant it to contain %q", notes, want)
	}
	if got := choice.selection().ToolchainDivergence; got != want {
		t.Errorf("selection toolchain_divergence = %q, want %q", got, want)
	}
	// A widened listing counted every toolchain, so the set it names must not
	// claim it counted one.
	if strings.Contains(choice.candidateSet, "under go") {
		t.Errorf("a widened candidate set names a toolchain it did not narrow on: %q", choice.candidateSet)
	}
}

// A walk that recorded no toolchain at all is a divergence too, and gets its own
// sentence: rendering it as the recorded case would claim the answer describes a
// standard library called "".
func TestSelectProjectWalkToRead_AnUnrecordedToolchainIsStatedNotBlanked(t *testing.T) {
	const modulePath = "example.com/app"
	dir := selectionProject(t, modulePath, "v4.5.1")
	old := underToolchain(selectionWalk(t, "W-old", modulePath, dir, "v4.5.1"), "")
	walks := selectionStore(old)

	choice := readWalk(t, walks, modulePath, dir, hostEnvUnder("go1.26.6"))

	notes := choice.basisNotes()
	if !strings.Contains(notes, "that project resolves go1.26.6 today") ||
		!strings.Contains(notes, walkBuildToolchainUnrecorded) {
		t.Errorf("the basis does not state the unrecorded toolchain: %q", notes)
	}
	if strings.Contains(notes, "describes 's standard library") {
		t.Errorf("the basis rendered an empty toolchain as a version: %q", notes)
	}
}

// Control: a target whose walks share the toolchain the project resolves selects
// exactly as it did, and says nothing new.
func TestSelectProjectWalkToRead_OneAgreeingToolchainSaysNothingNew(t *testing.T) {
	const modulePath = "example.com/app"
	dir := selectionProject(t, modulePath, "v4.5.1")
	newest := underToolchain(selectionWalk(t, "W-newest", modulePath, dir, "v4.5.1"), "go1.26.6")
	older := underToolchain(selectionWalk(t, "W-older", modulePath, dir, "v4.5.1"), "go1.26.6")
	walks := selectionStore(newest, older)

	choice := readWalk(t, walks, modulePath, dir, hostEnvUnder("go1.26.6"))

	if choice.summary.ID != newest.ID {
		t.Fatalf("answered from walk %s, want the newest %s", choice.summary.ID, newest.ID)
	}
	if clause := choice.toolchainDivergenceClause(); clause != "" {
		t.Errorf("agreeing toolchains produced a divergence line: %q", clause)
	}
}

// Control: a probe that could not answer pins nothing. A guessed toolchain would
// exclude every walk it was meant to find, and a divergence stated against a
// toolchain nobody measured is a claim with nothing behind it.
func TestSelectProjectWalkToRead_AFailedProbePinsNothingAndClaimsNothing(t *testing.T) {
	const modulePath = "example.com/app"
	dir := selectionProject(t, modulePath, "v4.5.1")
	newest := underToolchain(selectionWalk(t, "W-newest", modulePath, dir, "v4.5.1"), "go1.26.5")
	older := underToolchain(selectionWalk(t, "W-older", modulePath, dir, "v4.5.1"), "go1.26.6")
	walks := selectionStore(newest, older)

	choice := readWalk(t, walks, modulePath, dir, hostEnv())

	if choice.summary.ID != newest.ID {
		t.Fatalf("answered from walk %s, want the newest %s", choice.summary.ID, newest.ID)
	}
	if clause := choice.toolchainDivergenceClause(); clause != "" {
		t.Errorf("an unprobed toolchain produced a divergence line: %q", clause)
	}
	if strings.Contains(choice.candidateSet, "under") {
		t.Errorf("an unprobed toolchain narrowed the candidate set: %q", choice.candidateSet)
	}
}

// Control: the scope and platform contract is unchanged. A store holding only
// another platform's walk still refuses, and still names the scope — widening on
// the toolchain must not become a fallback on the two axes that refuse.
func TestSelectProjectWalkToRead_WideningNeverRelaxesScopeOrPlatform(t *testing.T) {
	const modulePath = "example.com/app"
	dir := selectionProject(t, modulePath, "v4.5.1")
	other := otherPlatform()
	foreign := underToolchain(onPlatform(
		inScope(selectionWalk(t, "W-foreign", modulePath, dir, "v4.5.1"), walkdomain.WalkScopeCode),
		other.GOOS, other.GOARCH), "go1.26.6")
	walks := selectionStore(foreign)

	choice, err := selectProjectWalkToRead(context.Background(), walks, selectionTarget(t, modulePath),
		scopeCode, hostEnvUnder("go1.26.6"), filepath.Join(dir, "go.mod"))
	if err == nil {
		t.Fatalf("a read answered from walk %s, resolved for %s", choice.summary.ID, other)
	}
	msg := err.Error()
	if !strings.Contains(msg, "no succeeded code project walk") {
		t.Errorf("refusal does not name the scope it looked for: %q", msg)
	}
	if !strings.Contains(msg, "code on "+other.String()) {
		t.Errorf("refusal does not name the build the store holds: %q", msg)
	}
}
