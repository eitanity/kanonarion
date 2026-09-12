package cli

import (
	"context"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/eitanity/kanonarion/internal/cli/testfakes"
	"github.com/eitanity/kanonarion/internal/coordinate"
	vuldomain "github.com/eitanity/kanonarion/internal/vuln/domain"
	walkdomain "github.com/eitanity/kanonarion/internal/walk/domain"
	walkports "github.com/eitanity/kanonarion/internal/walk/ports"
)

// walkReadingCommands are the commands that select a stored walk through
// latestWalkForGoMod. Each one has to be able to say which platform's walk it
// means: a walk taken for a declared target is otherwise writable and never
// readable.
var walkReadingCommands = []string{
	"context",
	"callers",
	"callees",
	"implementers",
	"examples-find",
	"symbol-context",
	"symbol-find",
	"usage",
	"vuln-show",
	"reachability",
	"dependents",
}

// TestWalkReadingCommands_DeclareTheBuildTarget is the defect as a property. A
// read selects its walk by platform, so a read that cannot name a platform can
// only ever ask for this host's — and the walk taken for any other target is
// unreachable through it however it was recorded.
func TestWalkReadingCommands_DeclareTheBuildTarget(t *testing.T) {
	tree := commandsByPath(newRootCmd(io.Discard, io.Discard))
	for _, path := range walkReadingCommands {
		cmd, ok := tree[path]
		if !ok {
			t.Fatalf("%s is not in the command tree; the sweep is checking a command that no longer exists", path)
		}
		for _, flag := range []string{"target", "goos", "goarch"} {
			if cmd.Flags().Lookup(flag) == nil {
				t.Errorf("%s declares no --%s, so it cannot read a walk taken for another platform", path, flag)
			}
		}
	}
}

// TestWalkReadingCommands_SpellTheTargetTheSameWayTheResolvingOnesDo pins the
// help text to one registration. Three spellings of one declaration that drift
// apart between the writing and the reading side is the same defect in the other
// direction: the caller records with one flag and cannot read with it.
func TestWalkReadingCommands_SpellTheTargetTheSameWayTheResolvingOnesDo(t *testing.T) {
	tree := commandsByPath(newRootCmd(io.Discard, io.Discard))
	walkCmd, ok := tree["walk"]
	if !ok {
		t.Fatal("walk is not in the command tree")
	}
	for _, flag := range []string{"target", "goos", "goarch"} {
		want := walkCmd.Flags().Lookup(flag).Usage
		for _, path := range walkReadingCommands {
			got := tree[path].Flags().Lookup(flag).Usage
			if got != want {
				t.Errorf("%s: --%s reads %q, walk reads %q", path, flag, got, want)
			}
		}
	}
}

// TestTargetFlagHint_IsEmptyUntilOneIsDeclared holds the two halves of the
// remedy rule: an undeclared read prints what it printed before, byte for byte,
// and a declared one prints the canonical pair whichever spelling was typed.
func TestTargetFlagHint_IsEmptyUntilOneIsDeclared(t *testing.T) {
	withDeclaredTarget(t, "")
	if got := targetFlagHint(); got != "" {
		t.Errorf("an undeclared read added %q to its remedies", got)
	}

	withDeclaredTarget(t, "windows/amd64")
	if got := targetFlagHint(); got != " --target windows/amd64" {
		t.Errorf("hint = %q, want \" --target windows/amd64\"", got)
	}
}

// TestResolveReadTarget_DefaultPathCostsNothing is the friction guarantee on the
// reading side: with no flag, nothing is located on disk and no `go tool dist
// list` is spawned. A go binary that does not exist would fail loudly if the
// toolchain were reached, and a directory that does not exist would fail if a
// manifest were resolved.
func TestResolveReadTarget_DefaultPathCostsNothing(t *testing.T) {
	withDeclaredTarget(t, "wasip1/wasm")

	err := resolveReadTarget(context.Background(), buildTargetFlags{}, "callers", false,
		filepath.Join(t.TempDir(), "no-such-dir", "go.mod"))
	if err != nil {
		t.Fatalf("the default path reached the toolchain or the filesystem: %v", err)
	}
	if declaredTarget.Declared() {
		t.Errorf("a read that declared nothing inherited %s from the invocation before it", declaredTarget)
	}
}

// TestResolveReadTarget_RefusesADeclarationThatWouldFilterNothing: a target
// named on a form that selects no walk by manifest filters nothing. Accepting it
// would print the same bytes as if the caller had never typed it, which is the
// silent-discard shape this CLI refuses everywhere else.
func TestResolveReadTarget_RefusesADeclarationThatWouldFilterNothing(t *testing.T) {
	withDeclaredTarget(t, "")

	err := resolveReadTarget(context.Background(), buildTargetFlags{target: "windows/amd64"},
		"callers", false, "")

	if err == nil {
		t.Fatal("a target that could filter nothing was accepted")
	}
	for _, want := range []string{"callers", "--target/--goos/--goarch", "--gomod"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("refusal does not name %q: %v", want, err)
		}
	}
	if declaredTarget.Declared() {
		t.Errorf("a refused declaration was settled anyway: %s", declaredTarget)
	}
}

// TestResolveReadTarget_SettlesADeclarationTheReadCanActOn is the other half:
// where the read does select a walk by manifest, the pair is validated against
// the toolchain in the project's own directory and settled, so the selection
// and every remedy printed below it are about the platform the caller named.
func TestResolveReadTarget_SettlesADeclarationTheReadCanActOn(t *testing.T) {
	requireGoOnPath(t)
	withDeclaredTarget(t, "")

	dir := t.TempDir()
	gomod := filepath.Join(dir, "go.mod")
	if err := os.WriteFile(gomod, []byte("module example.com/sel\n\ngo 1.21\n"), 0o600); err != nil {
		t.Fatalf("writing go.mod: %v", err)
	}

	if err := resolveReadTarget(context.Background(), buildTargetFlags{target: "windows/amd64"},
		"context --gomod", true, gomod); err != nil {
		t.Fatalf("a pair this toolchain builds for was refused on a read: %v", err)
	}
	if declaredTarget.String() != "windows/amd64" {
		t.Errorf("declared target settled as %s, want windows/amd64", declaredTarget)
	}
	if got := targetFlagHint(); got != " --target windows/amd64" {
		t.Errorf("the remedies below this read would print %q", got)
	}

	err := resolveReadTarget(context.Background(), buildTargetFlags{target: "windows/riscv64"},
		"context --gomod", true, gomod)
	if err == nil {
		t.Fatal("an unlisted pair was accepted on a read")
	}
	if !strings.Contains(err.Error(), "go tool dist list") {
		t.Errorf("refusal does not name the remedy: %v", err)
	}
	if declaredTarget.Declared() {
		t.Errorf("a refused target was settled anyway: %s", declaredTarget)
	}
}

// TestNoProjectWalkOfScope_RemedyCarriesTheDeclaredTarget is the defect itself,
// asserted on the string rather than on the behaviour.
//
// The refusal keeps naming both platforms — the one asked for and the one the
// store holds — because that is what makes it legible. What it must also do is
// print a remedy that REACHES the answer: without the declaration, running what
// the tool printed records a walk for this host and leaves the declared-target
// walk exactly as unreadable as it was.
func TestNoProjectWalkOfScope_RemedyCarriesTheDeclaredTarget(t *testing.T) {
	const modulePath = "example.com/tgtfix"
	local, err := coordinate.NewLocalCoordinate(modulePath)
	if err != nil {
		t.Fatalf("local coordinate: %v", err)
	}
	held := otherPlatform()
	qw := testfakes.NewFakeQueryWalks()
	qw.SetSummaries([]walkports.WalkSummary{{
		ID: "walk-held", Target: local, Scope: walkdomain.WalkScopeCode,
		OverallStatus: walkdomain.WalkSucceeded,
		GOOS:          held.GOOS, GOARCH: held.GOARCH,
	}})

	withDeclaredTarget(t, "windows/amd64")
	msg := noProjectWalkOfScope(context.Background(), qw, local, scopeCode, hostPlatform(), "./go.mod").Error()

	if !strings.Contains(msg, "kanonarion walk --gomod ./go.mod --target windows/amd64") {
		t.Errorf("the printed remedy does not carry the declared target, so running it cannot reach the answer: %s", msg)
	}
	if !strings.Contains(msg, hostPlatform().String()) || !strings.Contains(msg, held.String()) {
		t.Errorf("the refusal no longer names both the platform asked for and the one the store holds: %s", msg)
	}

	withDeclaredTarget(t, "")
	plain := noProjectWalkOfScope(context.Background(), qw, local, scopeCode, hostPlatform(), "./go.mod").Error()
	if strings.Contains(plain, "--target") {
		t.Errorf("a read that declared nothing printed a target in its remedy: %s", plain)
	}
}

// TestStalenessRemedies_CarryTheDeclaredTarget covers the three remedies a read
// that DID answer still prints. Each one tells the reader to re-walk the
// project, and each one has to mean the platform they asked about.
func TestStalenessRemedies_CarryTheDeclaredTarget(t *testing.T) {
	withDeclaredTarget(t, "windows/amd64")

	got := manifestStalenessNote("./go.mod")
	if !strings.Contains(got, "kanonarion walk --gomod ./go.mod --target windows/amd64") {
		t.Errorf("manifest staleness remedy records a host walk: %s", got)
	}

	drifted := walkChoice{
		rule:          walkChosenRecencyNoMatch,
		manifestPath:  "./go.mod",
		disagreements: []string{"example.com/a v1.0.0 -> v1.1.0"},
		summary:       walkports.WalkSummary{ID: "walk-1"},
	}
	if note := drifted.stalenessNote(); !strings.Contains(note, "kanonarion walk --gomod ./go.mod --target windows/amd64") {
		t.Errorf("drift staleness remedy records a host walk: %s", note)
	}
	drifted.candidates = 2
	if notice := drifted.statement(); !strings.Contains(notice, "kanonarion walk --gomod ./go.mod --target windows/amd64") {
		t.Errorf("drift selection notice records a host walk: %s", notice)
	}

	withDeclaredTarget(t, "")
	if got := manifestStalenessNote("./go.mod"); strings.Contains(got, "--target") {
		t.Errorf("a read that declared nothing printed a target: %s", got)
	}
}

// TestReachabilityRemedies_CarryTheDeclaredTarget sweeps the reachability
// surface's printable remedies. Every line naming a project-form walk or scan is
// runnable advice, and reachability is one of the commands that can now declare
// a target — so a line that dropped it would send the reader to re-measure this
// host and meet the same refusal again.
func TestReachabilityRemedies_CarryTheDeclaredTarget(t *testing.T) {
	coord, err := coordinate.NewModuleCoordinate("example.com/dep", "v1.2.3")
	if err != nil {
		t.Fatalf("coordinate: %v", err)
	}

	withDeclaredTarget(t, "windows/amd64")
	for _, r := range printableRemedies(coord, "walk-1") {
		for _, line := range r.lines {
			if !strings.Contains(line, "--gomod") {
				continue
			}
			if !strings.Contains(line, "--target windows/amd64") {
				t.Errorf("printed remedy drops the declared target: %q", line)
			}
		}
	}

	withDeclaredTarget(t, "")
	for _, r := range printableRemedies(coord, "walk-1") {
		for _, line := range r.lines {
			if strings.Contains(line, "--target") {
				t.Errorf("a read that declared nothing printed a target: %q", line)
			}
		}
	}
}

// TestUnscanHint_CarriesTheDeclaredTarget: the roll-up's one walk hint is a
// static table entry, and the declaration is not. Appending it is what keeps the
// hint about the build the reader asked for.
func TestUnscanHint_CarriesTheDeclaredTarget(t *testing.T) {
	var reason vuldomain.UnscanReason
	for r, d := range unscanDisplays {
		if d.hintTakesTarget {
			reason = r
		}
	}
	if reason == "" {
		t.Fatal("no unscan reason carries a walk hint; the sweep has nothing to check")
	}

	withDeclaredTarget(t, "windows/amd64")
	if got := unscanDisplayFor(reason).hint; !strings.HasSuffix(got, "--target windows/amd64") {
		t.Errorf("hint does not carry the declared target: %s", got)
	}

	withDeclaredTarget(t, "")
	if got := unscanDisplayFor(reason).hint; strings.Contains(got, "--target") {
		t.Errorf("a read that declared nothing printed a target: %s", got)
	}
}
