package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/eitanity/kanonarion/internal/cli/testfakes"
	"github.com/eitanity/kanonarion/internal/coordinate/coordinatetest"
	walkdomain "github.com/eitanity/kanonarion/internal/walk/domain"
	walkports "github.com/eitanity/kanonarion/internal/walk/ports"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
)

// --target means GOOS/GOARCH on every command that shows it. walk-list and
// license-compat used it for a module coordinate and an SPDX id; those are now
// --module and --target-license, with --target kept only as a hidden alias.
func TestVisibleTargetFlagIsAlwaysTheBuildTarget(t *testing.T) {
	const buildTarget = "build target as GOOS/GOARCH"
	for path, cmd := range commandsByPath(newRootCmd(&bytes.Buffer{}, &bytes.Buffer{})) {
		f := cmd.Flags().Lookup("target")
		if f == nil || f.Hidden {
			continue
		}
		if !strings.HasPrefix(f.Usage, buildTarget) {
			t.Errorf("%s --target is visible and means %q, not the build target", path, f.Usage)
		}
	}
}

// The alias is hidden and the new spelling is what --help shows.
func TestRenamedFlags_HelpShowsOnlyTheNewSpelling(t *testing.T) {
	cmds := commandsByPath(newRootCmd(&bytes.Buffer{}, &bytes.Buffer{}))
	for path, newName := range map[string]string{"walk-list": "module", "license-compat": "target-license"} {
		cmd := cmds[path]
		if cmd == nil {
			t.Fatalf("no %s command", path)
		}
		if f := cmd.Flags().Lookup(newName); f == nil || f.Hidden {
			t.Errorf("%s --%s is not a visible flag", path, newName)
		}
		old := cmd.Flags().Lookup("target")
		if old == nil || !old.Hidden {
			t.Errorf("%s --target must stay accepted as a hidden alias, got %+v", path, old)
		}
	}
	if f := cmds["walk-list"].Flags().Lookup("goos"); f == nil || f.Hidden {
		t.Error("walk-list --goos is not a visible flag")
	}
	if f := cmds["walk-list"].Flags().Lookup("goarch"); f == nil || f.Hidden {
		t.Error("walk-list --goarch is not a visible flag")
	}
}

// aliasCmd is a bare command carrying one renamed flag, so resolve is exercised
// on cobra's own parse of the arguments.
func aliasCmd(t *testing.T, args ...string) (*cobra.Command, *string, *deprecatedAlias) {
	t.Helper()
	cmd := &cobra.Command{Use: "probe", RunE: func(*cobra.Command, []string) error { return nil }}
	var current string
	cmd.Flags().StringVar(&current, "module", "", "new spelling")
	alias := registerDeprecatedAlias(cmd, "target", "module")
	if err := cmd.ParseFlags(args); err != nil {
		t.Fatalf("parsing %v: %v", args, err)
	}
	return cmd, &current, alias
}

func TestDeprecatedAlias_NewSpellingIsSilent(t *testing.T) {
	cmd, current, alias := aliasCmd(t, "--module", "a@v1")
	var stderr bytes.Buffer
	got, err := alias.resolve(cmd, *current, &stderr)
	if err != nil || got != "a@v1" {
		t.Fatalf("resolve = %q, %v; want a@v1, nil", got, err)
	}
	if stderr.Len() != 0 {
		t.Errorf("the new spelling warned: %q", stderr.String())
	}
}

func TestDeprecatedAlias_OldSpellingWorksAndWarnsNamingTheNew(t *testing.T) {
	cmd, current, alias := aliasCmd(t, "--target", "a@v1")
	var stderr bytes.Buffer
	got, err := alias.resolve(cmd, *current, &stderr)
	if err != nil || got != "a@v1" {
		t.Fatalf("resolve = %q, %v; want a@v1, nil", got, err)
	}
	if !strings.Contains(stderr.String(), "--target is deprecated") || !strings.Contains(stderr.String(), "use --module") {
		t.Errorf("warning does not name both spellings: %q", stderr.String())
	}
}

func TestDeprecatedAlias_BothSpellingsRefuse(t *testing.T) {
	for _, args := range [][]string{
		{"--target", "a@v1", "--module", "b@v1"},
		{"--module", "a@v1", "--target", "a@v1"}, // equal values still refuse
		{"--target", "", "--module", ""},
	} {
		cmd, current, alias := aliasCmd(t, args...)
		var stderr bytes.Buffer
		_, err := alias.resolve(cmd, *current, &stderr)
		requireExit(t, err, ExitConfig)
		if !strings.Contains(err.Error(), "pass --module only") {
			t.Errorf("%v: refusal does not name the spelling to keep: %v", args, err)
		}
	}
}

// renamedFlagCases are every renamed flag, run through the real command tree
// against an empty store: the two spellings must agree on stdout and exit code,
// and only the old one writes to stderr beyond what the new one does.
func TestRenamedFlags_AliasAgreesWithTheNewSpellingOnStdout(t *testing.T) {
	cases := []struct {
		name     string
		newArgs  []string
		oldArgs  []string
		bothArgs []string
		newFlag  string
	}{
		{
			name:     "walk-list",
			newArgs:  []string{"walk-list", "--module", "example.com/m@v1.0.0", "--json"},
			oldArgs:  []string{"walk-list", "--target", "example.com/m@v1.0.0", "--json"},
			bothArgs: []string{"walk-list", "--target", "example.com/m@v1.0.0", "--module", "example.com/m@v1.0.0", "--json"},
			newFlag:  "--module",
		},
		{
			name:     "license-compat",
			newArgs:  []string{"license-compat", "example.com/m@v1.0.0", "--target-license", "Apache-2.0", "--json"},
			oldArgs:  []string{"license-compat", "example.com/m@v1.0.0", "--target", "Apache-2.0", "--json"},
			bothArgs: []string{"license-compat", "example.com/m@v1.0.0", "--target", "MIT", "--target-license", "Apache-2.0", "--json"},
			newFlag:  "--target-license",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("KANONARION_STORE", t.TempDir())
			newOut, newErr, newCode := runCLI(t, tc.newArgs...)
			oldOut, oldErr, oldCode := runCLI(t, tc.oldArgs...)
			if newOut != oldOut || newCode != oldCode {
				t.Fatalf("spellings disagree:\nnew (%d): %q\nold (%d): %q", newCode, newOut, oldCode, oldOut)
			}
			if strings.Contains(newErr, "deprecated") {
				t.Errorf("the new spelling warned: %q", newErr)
			}
			if !strings.Contains(oldErr, "deprecated") || !strings.Contains(oldErr, "use "+tc.newFlag) {
				t.Errorf("the old spelling did not warn naming %s: %q", tc.newFlag, oldErr)
			}
			if strings.Contains(oldOut, "deprecated") {
				t.Errorf("the warning reached stdout: %q", oldOut)
			}
			isolateInvocationState(t)
			var bothOut bytes.Buffer
			err := Run(tc.bothArgs, &bothOut, &bytes.Buffer{})
			if code := ExitCodeForError(err); code != ExitConfig || bothOut.Len() != 0 {
				t.Errorf("both spellings: exit %d stdout %q, want exit %d and nothing on stdout", code, bothOut.String(), ExitConfig)
			}
			if err == nil || !strings.Contains(err.Error(), "pass "+tc.newFlag+" only") {
				t.Errorf("both spellings: refusal does not name %s: %v", tc.newFlag, err)
			}
		})
	}
}

func platformWalks() []walkports.WalkSummary {
	at := time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)
	mk := func(id, goos, goarch string, minutes int) walkports.WalkSummary {
		return walkports.WalkSummary{
			ID: id, Target: coordinatetest.MustNew("example.com/m", "v1.0.0"),
			StartedAt: at.Add(time.Duration(-minutes) * time.Minute), OverallStatus: walkdomain.WalkSucceeded,
			GOOS: goos, GOARCH: goarch,
		}
	}
	return []walkports.WalkSummary{
		mk("W-LINUX", "linux", "amd64", 1),
		mk("W-WIN", "windows", "amd64", 2),
		mk("W-WINARM", "windows", "arm64", 3),
		mk("W-UNRECORDED", "", "", 4),
	}
}

// --goos/--goarch keep exactly the rows whose recorded platform matches, which
// is the count a hand filter over the unfiltered --json gives.
func TestWalkList_PlatformFilterMatchesAHandFilter(t *testing.T) {
	isolateInvocationState(t)
	withDeclaredTarget(t, "")
	jsonOut = true
	uc := testfakes.NewFakeQueryWalks()
	uc.SetSummaries(platformWalks())

	var all bytes.Buffer
	if err := runWalkList(context.Background(), "", "", "", "", buildTargetFlags{}, "", 0, 0, false, false, uc, &all, &bytes.Buffer{}); err != nil {
		t.Fatalf("unfiltered: %v", err)
	}
	var filtered bytes.Buffer
	platform := buildTargetFlags{goos: "windows", goarch: "amd64"}
	if err := runWalkList(context.Background(), "", "", "", "", platform, "", 0, 0, false, false, uc, &filtered, &bytes.Buffer{}); err != nil {
		t.Fatalf("filtered: %v", err)
	}

	var allDoc, filteredDoc struct {
		Records []walkports.WalkSummary `json:"records"`
	}
	if err := json.Unmarshal(all.Bytes(), &allDoc); err != nil {
		t.Fatalf("decoding unfiltered: %v", err)
	}
	if err := json.Unmarshal(filtered.Bytes(), &filteredDoc); err != nil {
		t.Fatalf("decoding filtered: %v", err)
	}
	var hand []string
	for _, r := range allDoc.Records {
		if r.GOOS == "windows" && r.GOARCH == "amd64" {
			hand = append(hand, r.ID)
		}
	}
	var got []string
	for _, r := range filteredDoc.Records {
		got = append(got, r.ID)
	}
	if strings.Join(got, ",") != strings.Join(hand, ",") || len(got) != 1 {
		t.Errorf("--goos windows --goarch amd64 kept %v, the hand filter keeps %v", got, hand)
	}
}

func TestWalkList_PlatformFilterIsValidatedAsABuildTarget(t *testing.T) {
	isolateInvocationState(t)
	withDeclaredTarget(t, "")
	if env, err := walkListPlatform(context.Background(), buildTargetFlags{}); err != nil || env != nil {
		t.Errorf("no flag: got %v, %v; want no filter", env, err)
	}
	if _, err := walkListPlatform(context.Background(), buildTargetFlags{goos: "windows"}); err == nil ||
		!strings.Contains(err.Error(), "without a GOARCH") {
		t.Errorf("half a pair was not refused by name: %v", err)
	}
	if _, err := walkListPlatform(context.Background(), buildTargetFlags{goos: "windows", goarch: "amd65"}); err == nil ||
		!strings.Contains(err.Error(), "not one this Go toolchain builds for") {
		t.Errorf("an unlisted pair was not refused: %v", err)
	}
}

// A zero result under the platform filter names the filter that emptied it.
func TestWalkList_PlatformZeroNamesThePlatform(t *testing.T) {
	isolateInvocationState(t)
	withDeclaredTarget(t, "")
	uc := testfakes.NewFakeQueryWalks()
	uc.SetSummaries(platformWalks())
	var out bytes.Buffer
	platform := buildTargetFlags{goos: "plan9", goarch: "amd64"}
	if err := runWalkList(context.Background(), "", "", "", "", platform, "", 20, 0, false, false, uc, &out, &bytes.Buffer{}); err != nil {
		t.Fatalf("runWalkList: %v", err)
	}
	if !strings.Contains(out.String(), `platform "plan9/amd64"`) {
		t.Errorf("zero notice does not name the platform filter: %q", out.String())
	}
}

// A GOOS/GOARCH pair typed where the module goes is refused naming
// --goos/--goarch with the halves filled in, rather than answered as a
// malformed coordinate. A path that is not a pair keeps the coordinate refusal.
func TestWalkList_PlatformTypedAsAModuleNamesTheGOOSFlags(t *testing.T) {
	uc := testfakes.NewFakeQueryWalks()
	uc.SetSummaries(platformWalks())
	err := runWalkList(context.Background(), "windows/amd64", "", "", "", buildTargetFlags{}, "", 20, 0, false, false, uc, &bytes.Buffer{}, &bytes.Buffer{})
	requireExit(t, err, ExitConfig)
	if !strings.Contains(err.Error(), "--goos windows --goarch amd64") || !strings.Contains(err.Error(), "--module") {
		t.Errorf("refusal does not name the platform filter: %v", err)
	}
	err = runWalkList(context.Background(), "example/mod", "", "", "", buildTargetFlags{}, "", 20, 0, false, false, uc, &bytes.Buffer{}, &bytes.Buffer{})
	if err == nil || !strings.Contains(err.Error(), "invalid module coordinate") || strings.Contains(err.Error(), "--goos") {
		t.Errorf("a module path without a version was called a platform: %v", err)
	}
}

// Every printed remedy that lists the walks of one module spells the filter
// --module, and the line it prints parses as a walk-list invocation.
func TestWalkListRemedies_NameTheModuleFlag(t *testing.T) {
	coord := coordinatetest.MustNew("example.com/m", "v1.0.0")
	choice := walkChoice{candidates: 2, rule: walkChosenRecencyUnchecked, summary: walkports.WalkSummary{ID: "W1", Target: coord}}
	uc := testfakes.NewFakeQueryWalks()
	uc.AddWalk(walkdomain.WalkRecord{ID: "ELSEWHERE", Target: coordinatetest.MustNew("example.com/other", "v1.0.0")})
	_, missErr := resolvePinnedWalk(context.Background(), uc, "MISSING", coord)
	_, elsewhereErr := resolvePinnedWalk(context.Background(), uc, "ELSEWHERE", coord)
	if missErr == nil || elsewhereErr == nil {
		t.Fatalf("resolvePinnedWalk did not refuse: %v, %v", missErr, elsewhereErr)
	}
	for name, msg := range map[string]string{
		"selection notice":      choice.statement(),
		"pinned walk miss":      missErr.Error(),
		"pinned walk elsewhere": elsewhereErr.Error(),
	} {
		i := strings.Index(msg, "kanonarion walk-list ")
		if i < 0 {
			t.Errorf("%s names no walk-list invocation: %q", name, msg)
			continue
		}
		fields := strings.Fields(msg[i+len("kanonarion "):])
		args := fields[:3]
		if args[1] != "--module" || args[2] != coord.String() {
			t.Errorf("%s prints %v, want walk-list --module %s", name, args, coord)
		}
		cmd := newWalkListCmd(&bytes.Buffer{}, &bytes.Buffer{})
		if err := cmd.ParseFlags(args[1:]); err != nil {
			t.Errorf("%s prints an invocation walk-list does not parse: %v", name, err)
		}
		cmd.Flags().Visit(func(f *pflag.Flag) {
			if f.Hidden {
				t.Errorf("%s prints the hidden alias --%s", name, f.Name)
			}
		})
	}
}

// --walk-id names one walk, so every row filter beside it is refused rather
// than ignored: an ignored --goos windows would hand back a linux walk.
func TestWalkList_WalkIDRefusesEveryRowFilter(t *testing.T) {
	t.Setenv("KANONARION_STORE", t.TempDir())
	for _, extra := range [][]string{
		{"--module", "example.com/m@v1.0.0"},
		{"--target", "example.com/m@v1.0.0"},
		{"--goos", "windows"},
		{"--goarch", "amd64"},
		{"--goos", "windows", "--goarch", "amd64"},
		{"--since", "2026-01-01T00:00:00Z"},
		{"--status", "succeeded"},
		{"--scope", "code"},
		{"--tool"},
		{"--latest"},
		{"--latest-success"},
		{"--status", ""}, // given empty is still given
	} {
		isolateInvocationState(t)
		args := append([]string{"walk-list", "--walk-id", "W1"}, extra...)
		var out bytes.Buffer
		err := Run(args, &out, &bytes.Buffer{})
		if code := ExitCodeForError(err); code != ExitConfig || out.Len() != 0 {
			t.Errorf("%v: exit %d stdout %q, want exit %d and nothing on stdout", extra, code, out.String(), ExitConfig)
			continue
		}
		if !strings.Contains(err.Error(), "--walk-id names one walk; it cannot be combined with "+extra[0]) {
			t.Errorf("%v: refusal does not name the flag: %v", extra, err)
		}
	}
}

// Paging and output flags still apply to one named walk: the miss is the
// walk-id miss (exit 4), not the combination refusal.
func TestWalkList_WalkIDKeepsPagingAndOutputFlags(t *testing.T) {
	t.Setenv("KANONARION_STORE", t.TempDir())
	for _, extra := range [][]string{{}, {"--json"}, {"--limit", "5"}, {"--offset", "0"}, {"--json", "--limit", "0"}} {
		isolateInvocationState(t)
		args := append([]string{"walk-list", "--walk-id", "W1"}, extra...)
		err := Run(args, &bytes.Buffer{}, &bytes.Buffer{})
		if code := ExitCodeForError(err); code != ExitNotFound || strings.Contains(err.Error(), "cannot be combined") {
			t.Errorf("%v: exit %d (%v), want the walk-id miss at exit %d", extra, code, err, ExitNotFound)
		}
	}
}

// Every walk-list flag is either a row filter (refused beside --walk-id) or a
// paging flag (kept), so a filter added later cannot be silently ignored.
func TestWalkList_EveryFlagIsClassifiedForWalkID(t *testing.T) {
	cmd := commandsByPath(newRootCmd(&bytes.Buffer{}, &bytes.Buffer{}))["walk-list"]
	kept := map[string]bool{"walk-id": true, "limit": true, "offset": true}
	filters := map[string]bool{}
	for _, f := range walkListRowFilters {
		filters[f] = true
	}
	cmd.LocalFlags().VisitAll(func(f *pflag.Flag) {
		if !kept[f.Name] && !filters[f.Name] {
			t.Errorf("walk-list --%s is neither a row filter nor a paging flag; classify it for --walk-id", f.Name)
		}
	})
}

// Every text view prints the platform after scope=, in the frame wording, so
// the rows say what --goos/--goarch would match.
func TestWalkList_TextRowsPrintThePlatform(t *testing.T) {
	isolateInvocationState(t)
	withDeclaredTarget(t, "")
	jsonOut = false
	uc := testfakes.NewFakeQueryWalks()
	uc.SetSummaries(platformWalks())
	uc.AddWalk(walkdomain.WalkRecord{
		ID: "W-WIN", Target: coordinatetest.MustNew("example.com/m", "v1.0.0"),
		Graph: walkdomain.Graph{BuildEnv: walkdomain.BuildEnv{GOOS: "windows", GOARCH: "amd64"}},
	})
	uc.AddWalk(walkdomain.WalkRecord{ID: "W-UNRECORDED", Target: coordinatetest.MustNew("example.com/m", "v1.0.0")})
	uc.AddWalk(walkdomain.WalkRecord{ID: "W-LOCAL", Target: coordinatetest.MustNew("example.com/app", "local")})

	run := func(walkID string, latestSuccess bool) string {
		var out bytes.Buffer
		if err := runWalkList(context.Background(), "", "", "", "", buildTargetFlags{}, walkID, 20, 0, false, latestSuccess, uc, &out, &bytes.Buffer{}); err != nil {
			t.Fatalf("runWalkList(%q, %v): %v", walkID, latestSuccess, err)
		}
		return out.String()
	}
	list := run("", false)
	for _, want := range []string{
		"W-LINUX  example.com/m@v1.0.0  ", "  scope=  platform=linux/amd64  depth=",
		"  platform=windows/amd64  ", "  platform=windows/arm64  ", "  platform=not-platform-scoped  ",
	} {
		if !strings.Contains(list, want) {
			t.Errorf("listing lacks %q:\n%s", want, list)
		}
	}
	if got := run("W-WIN", false); !strings.Contains(got, "  platform=windows/amd64  depth=") {
		t.Errorf("--walk-id row lacks its platform: %q", got)
	}
	if got := run("W-UNRECORDED", false); !strings.Contains(got, "  platform=not-platform-scoped  depth=") {
		t.Errorf("--walk-id row of a module-rooted walk: %q", got)
	}
	if got := run("W-LOCAL", false); !strings.Contains(got, "  platform=unrecorded  depth=") {
		t.Errorf("--walk-id row of a project walk with no platform: %q", got)
	}
	if got := run("", true); !strings.Contains(got, "W-LINUX") || !strings.Contains(got, "  platform=linux/amd64  depth=") {
		t.Errorf("--latest-success row lacks its platform: %q", got)
	}
}

// A module filter that is not a coordinate names the flag the caller typed.
func TestWalkList_BadModuleNamesTheFlagTyped(t *testing.T) {
	t.Setenv("KANONARION_STORE", t.TempDir())
	for flag, want := range map[string]string{
		"--module": `--module: invalid module coordinate "example/mod"`,
		"--target": `--target: invalid module coordinate "example/mod"`,
	} {
		isolateInvocationState(t)
		err := Run([]string{"walk-list", flag, "example/mod"}, &bytes.Buffer{}, &bytes.Buffer{})
		if ExitCodeForError(err) != ExitConfig || err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%s example/mod: %v, want exit %d naming %q", flag, err, ExitConfig, want)
		}
	}
}
