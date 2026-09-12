package cli

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/eitanity/kanonarion/internal/adapters/goenv"
	"github.com/eitanity/kanonarion/internal/cli/testfakes"
	"github.com/eitanity/kanonarion/internal/coordinate"
	walkdomain "github.com/eitanity/kanonarion/internal/walk/domain"
	walkports "github.com/eitanity/kanonarion/internal/walk/ports"
)

// withDeclaredTarget settles the invocation's target for one test and puts it
// back, so a test that declares one cannot leak it into the next.
func withDeclaredTarget(t *testing.T, pair string) goenv.Target {
	t.Helper()
	prev := declaredTarget
	t.Cleanup(func() { declaredTarget = prev })
	if pair == "" {
		declaredTarget = goenv.Target{}
		return declaredTarget
	}
	parsed, err := goenv.ParseTarget(pair)
	if err != nil {
		t.Fatalf("ParseTarget(%q): %v", pair, err)
	}
	declaredTarget = parsed
	return parsed
}

// requireGoOnPath skips a test that measures what a real go command answers.
func requireGoOnPath(t *testing.T) {
	t.Helper()
	if _, err := exec.LookPath("go"); err != nil {
		t.Skip("the go toolchain is not on PATH; this test measures what it supports")
	}
}

// TestBuildTargetFlags_ReadTheDeclaration holds the three spellings and the two
// combinations that mean two things at once.
func TestBuildTargetFlags_ReadTheDeclaration(t *testing.T) {
	for _, tc := range []struct {
		name  string
		flags buildTargetFlags
		want  string
		fail  string
	}{
		{name: "nothing declared", flags: buildTargetFlags{}, want: "undeclared"},
		{name: "pair", flags: buildTargetFlags{target: "wasip1/wasm"}, want: "wasip1/wasm"},
		{name: "halves", flags: buildTargetFlags{goos: "windows", goarch: "arm64"}, want: "windows/arm64"},
		{name: "both forms", flags: buildTargetFlags{target: "linux/amd64", goos: "windows"}, fail: "pass one of them"},
		{name: "half a pair", flags: buildTargetFlags{goos: "windows"}, fail: "without a GOARCH"},
		{name: "not a pair", flags: buildTargetFlags{target: "wasip1"}, fail: "not GOOS/GOARCH"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := tc.flags.parse()
			if tc.fail != "" {
				if err == nil {
					t.Fatalf("parse() = %s, want a refusal saying %q", got, tc.fail)
				}
				if !strings.Contains(err.Error(), tc.fail) {
					t.Errorf("refusal %q does not say %q", err, tc.fail)
				}
				return
			}
			if err != nil {
				t.Fatalf("parse(): %v", err)
			}
			if got.String() != tc.want {
				t.Errorf("parse() = %s, want %s", got, tc.want)
			}
		})
	}
}

// TestUnsupportedTargetError_NamesThePairAndTheRemedy is the fail-closed
// refusal. The toolchain refuses an unknown pair too, but names neither GOOS nor
// GOARCH when it does, so the pair that was rejected and the command that lists
// the real ones are the whole of what makes this actionable.
func TestUnsupportedTargetError_NamesThePairAndTheRemedy(t *testing.T) {
	rejected, err := goenv.ParseTarget("windows/riscv64")
	if err != nil {
		t.Fatalf("ParseTarget: %v", err)
	}
	offered := []goenv.Target{}
	for _, pair := range []string{"linux/amd64", "linux/riscv64", "windows/386", "windows/amd64", "darwin/arm64"} {
		p, perr := goenv.ParseTarget(pair)
		if perr != nil {
			t.Fatalf("ParseTarget(%q): %v", pair, perr)
		}
		offered = append(offered, p)
	}

	msg := unsupportedTargetError(rejected, offered).Error()

	for _, want := range []string{"windows/riscv64", "go tool dist list", "5 pairs"} {
		if !strings.Contains(msg, want) {
			t.Errorf("refusal does not name %q: %s", want, msg)
		}
	}
	if !strings.Contains(msg, "windows/amd64") {
		t.Errorf("refusal offers nothing near the pair the caller meant: %s", msg)
	}
	if strings.Contains(msg, "darwin/arm64") {
		t.Errorf("refusal listed a pair sharing neither half, which is noise: %s", msg)
	}
}

// TestResolveBuildTarget_DefaultPathAsksTheToolchainNothing is the friction
// guarantee as a property: with no flag the run must not spawn `go tool dist
// list`. A go binary that does not exist would fail loudly if it did.
func TestResolveBuildTarget_DefaultPathAsksTheToolchainNothing(t *testing.T) {
	withDeclaredTarget(t, "wasip1/wasm")

	if err := resolveBuildTarget(context.Background(), buildTargetFlags{}, filepath.Join(t.TempDir(), "no-such-go"), ""); err != nil {
		t.Fatalf("the default path reached the toolchain: %v", err)
	}
	if declaredTarget.Declared() {
		t.Errorf("a run that declared nothing inherited %s from the one before it", declaredTarget)
	}
}

// TestResolveBuildTarget_ValidatesAgainstTheToolchain closes the loop on the
// real go command: a listed pair is accepted and settled, an unlisted one is
// refused and settles nothing.
func TestResolveBuildTarget_ValidatesAgainstTheToolchain(t *testing.T) {
	requireGoOnPath(t)
	withDeclaredTarget(t, "")

	if err := resolveBuildTarget(context.Background(), buildTargetFlags{target: "windows/amd64"}, "", ""); err != nil {
		t.Fatalf("a pair this toolchain builds for was refused: %v", err)
	}
	if declaredTarget.String() != "windows/amd64" {
		t.Errorf("declared target settled as %s, want windows/amd64", declaredTarget)
	}

	err := resolveBuildTarget(context.Background(), buildTargetFlags{target: "windows/riscv64"}, "", "")
	if err == nil {
		t.Fatal("an unlisted pair was accepted")
	}
	if !strings.Contains(err.Error(), "go tool dist list") {
		t.Errorf("refusal does not name the remedy: %v", err)
	}
	if declaredTarget.Declared() {
		t.Errorf("a refused target was settled anyway: %s", declaredTarget)
	}
}

// TestTargetClause_NamesTheTargetOnlyWhenItIsTheCause: the toolchain's own
// sentence about a cross-target resolution names neither GOOS nor GOARCH — it
// names a cgo linking mode, or a build constraint inside a dependency five
// levels down — so the clause is what points at the cause. A host resolution
// fails for its own reasons and must not be blamed on a target.
func TestTargetClause_NamesTheTargetOnlyWhenItIsTheCause(t *testing.T) {
	withDeclaredTarget(t, "")
	if got := targetClause(); got != "" {
		t.Errorf("an undeclared run blamed a target: %q", got)
	}

	host := goenv.Host()
	withDeclaredTarget(t, host.String())
	if got := targetClause(); got != "" {
		t.Errorf("a target naming this host blamed itself: %q", got)
	}

	withDeclaredTarget(t, "wasip1/wasm")
	if got := targetClause(); !strings.Contains(got, "wasip1/wasm") {
		t.Errorf("clause does not name the declared target: %q", got)
	}
}

// TestCurrentWalkBuildEnv_FiltersOnTheDeclaredTarget is the selection half of
// the declaration: a read filters on the platform the invocation named, so the
// walk it answers from is one its own resolution would have produced.
func TestCurrentWalkBuildEnv_FiltersOnTheDeclaredTarget(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "go.mod"), []byte("module example.com/sel\n\ngo 1.21\n"), 0o600); err != nil {
		t.Fatalf("writing go.mod: %v", err)
	}

	withDeclaredTarget(t, "")
	if got := currentWalkBuildEnv(context.Background(), "", dir, nil).platform; got != hostPlatform() {
		t.Errorf("an undeclared read filtered on %s, want the host %s", got, hostPlatform())
	}

	declared := withDeclaredTarget(t, "windows/arm64")
	got := currentWalkBuildEnv(context.Background(), "", dir, nil).platform
	want := walkports.BuildEnvFilter{GOOS: declared.GOOS(), GOARCH: declared.GOARCH()}
	if got != want {
		t.Errorf("a read declaring %s filtered on %s", declared, got)
	}
}

// TestSelectProjectWalkToScan_ADeclaredTargetFindsItsOwnWalkAndNoOther is the
// property the two halves add up to: a walk taken for a declared target is found
// by a later read declaring the same target, and a read taking the host default
// does not find it.
func TestSelectProjectWalkToScan_ADeclaredTargetFindsItsOwnWalkAndNoOther(t *testing.T) {
	const modulePath = "example.com/myapp"
	local, err := coordinate.NewLocalCoordinate(modulePath)
	if err != nil {
		t.Fatalf("local coordinate: %v", err)
	}
	declared := otherPlatform()
	qw := testfakes.NewFakeQueryWalks()
	qw.SetSummaries([]walkports.WalkSummary{{
		ID: "walk-declared-target", Target: local, Scope: walkdomain.WalkScopeCode,
		OverallStatus: walkdomain.WalkSucceeded,
		GOOS:          declared.GOOS, GOARCH: declared.GOARCH,
	}})

	got, err := selectProjectWalkToScan(context.Background(), qw, local, scopeCode,
		walkBuildEnv{platform: declared}, "./go.mod")
	if err != nil {
		t.Fatalf("a read declaring %s did not find the walk taken for it: %v", declared, err)
	}
	if got.ID != "walk-declared-target" {
		t.Errorf("selected %s, want walk-declared-target", got.ID)
	}

	if _, err := selectProjectWalkToScan(context.Background(), qw, local, scopeCode, hostEnv(), "./go.mod"); err == nil {
		t.Errorf("a host-default read answered from a walk taken for %s", declared)
	}
}

// TestResolveBuildTarget_AValidationItCouldNotRunIsARefusal: a declared target
// whose check could not run is refused rather than accepted unchecked. Accepting
// it would restore exactly the silent wrong answer the validation exists to
// remove, on the one path where the caller cannot see the check did not happen.
func TestResolveBuildTarget_AValidationItCouldNotRunIsARefusal(t *testing.T) {
	withDeclaredTarget(t, "")

	err := resolveBuildTarget(context.Background(), buildTargetFlags{target: "windows/amd64"},
		filepath.Join(t.TempDir(), "no-such-go"), "")

	if err == nil {
		t.Fatal("a target that could not be validated was accepted")
	}
	// An unreadable declaration is refused before the toolchain is asked at all.
	if perr := resolveBuildTarget(context.Background(), buildTargetFlags{target: "wasip1"}, "", ""); perr == nil ||
		!strings.Contains(perr.Error(), "not GOOS/GOARCH") {
		t.Errorf("a malformed pair was not refused by shape: %v", perr)
	}
	if !strings.Contains(err.Error(), "windows/amd64") {
		t.Errorf("refusal does not name the target it could not check: %v", err)
	}
	if declaredTarget.Declared() {
		t.Errorf("an unvalidated target was settled anyway: %s", declaredTarget)
	}
}
