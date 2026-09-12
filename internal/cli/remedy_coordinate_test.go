package cli

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	cgdomain "github.com/eitanity/kanonarion/internal/callgraph/domain"
	"github.com/eitanity/kanonarion/internal/coordinate"
	"github.com/eitanity/kanonarion/internal/coordinate/coordinatetest"
	fetchdomain "github.com/eitanity/kanonarion/internal/fetch/domain"
)

// acquiringCommands are the subcommands that must go and GET a module's bytes
// before they can do anything. Handed a coordinate at the synthetic "local"
// version they exit non-zero, because that version names a working tree and no
// fetch can ever satisfy it — "run 'kanonarion fetch' first" is a second dead
// end, not a recovery.
//
// The set is written down rather than inferred because there is no flag on a
// cobra command that says "this one fetches", and a remedy that names one of
// these with a project coordinate is the defect this file exists to catch.
var acquiringCommands = []string{
	"callgraph", "fetch", "walk", "interface", "license", "capability", "examples", "latest", "use",
}

// A set of names that no longer resolve would pass every assertion below while
// checking nothing.
func TestAcquiringCommands_AllNameARealSubcommand(t *testing.T) {
	for _, name := range acquiringCommands {
		if err := parseInvocation(t, "kanonarion "+name+" example.com/mod@v1.0.0"); err != nil {
			t.Errorf("%q is not a subcommand that takes a module coordinate: %v", name, err)
		}
	}
}

// assertRunnableFor pushes one built remedy through the CLI's parser and refuses
// the combination the class is about: a project coordinate handed to a command
// that fetches.
func assertRunnableFor(t *testing.T, coord coordinate.ModuleCoordinate, line string) {
	t.Helper()
	if err := parseInvocation(t, line); err != nil {
		t.Errorf("remedy %q is rejected by the CLI's own parser: %v", line, err)
		return
	}
	if !coord.IsLocal() {
		return
	}
	fields := splitInvocation(line)
	if len(fields) < 2 {
		t.Errorf("remedy %q names no subcommand", line)
		return
	}
	if !slices.Contains(acquiringCommands, fields[1]) {
		return
	}
	// The coordinate matters, not the command alone: "kanonarion walk --gomod
	// ./go.mod" names an acquiring command and is exactly the right advice for a
	// project, because it hands over a tree rather than a version to resolve.
	for _, arg := range fields[2:] {
		if arg != coord.String() && !strings.HasSuffix(arg, "@"+coordinate.LocalVersion) {
			continue
		}
		t.Errorf("remedy %q hands the project coordinate %s to %q, which resolves a published version: that invocation exits non-zero and its own next step ('kanonarion fetch') cannot succeed either",
			line, coord, fields[1])
	}
}

// A builder that cannot produce a placeholder closes only half the class: two
// sites wrote the line out by hand, and no unit test over a builder can see
// those. This walks the shipped source and refuses the shape anywhere.
func TestNoSourceFileWritesAPlaceholderRemedy(t *testing.T) {
	const bad = "kanonarion local " + cgdomain.LocalDirPlaceholder
	root := filepath.Join("..", "..")
	scanned := 0
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if name := d.Name(); name == ".git" || name == "dist" || name == "testdata" {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		// #nosec G304,G122 -- path comes from walking this repo's own source tree
		b, rerr := os.ReadFile(path)
		if rerr != nil {
			return fmt.Errorf("reading %s: %w", path, rerr)
		}
		scanned++
		if strings.Contains(string(b), bad) {
			t.Errorf("%s writes %q, a line no reader can run", path, bad)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walking the source tree: %v", err)
	}
	// A walk that found nothing would pass while checking nothing.
	if scanned < 100 {
		t.Fatalf("scanned only %d source files; the walk is not reaching the tree", scanned)
	}
}

// assertRemedyLine is what every line presented to a reader must pass. It adds
// the half assertRunnableFor cannot make: a line carrying "<dir>" parses fine
// and is still unrunnable, which is how eight sites shipped one. A line that is
// not a command is an instruction saying why none can be given, and it still has
// to name the command it is about.
func assertRemedyLine(t *testing.T, coord coordinate.ModuleCoordinate, line string) {
	t.Helper()
	if strings.Contains(line, cgdomain.LocalDirPlaceholder) {
		t.Errorf("remedy %q prints %s: a reader cannot run a line with a placeholder in it",
			line, cgdomain.LocalDirPlaceholder)
		return
	}
	if !strings.HasPrefix(line, "kanonarion ") {
		if !strings.Contains(line, "kanonarion ") {
			t.Errorf("remedy %q neither runs nor names a command", line)
		}
		return
	}
	assertRunnableFor(t, coord, line)
}

// Every refusal that tells a reader to re-derive a call graph goes through the
// two builders below, so this is the whole class in one test: both coordinate
// kinds, both the plain and the forced form, with and without a working tree in
// hand. The guard that stood here accepted a placeholder, which is why eight
// call sites shipped one.
func TestReanalysisRemedy_IsRunnableAndNeverAPlaceholder(t *testing.T) {
	const dir = "/srv/checkouts/project"
	builders := map[string]func(coordinate.ModuleCoordinate, string) string{
		"plain":  cgdomain.ReanalysisInstruction,
		"forced": cgdomain.ForcedReanalysisInstruction,
	}
	for _, coord := range []coordinate.ModuleCoordinate{
		coordinatetest.MustNew("github.com/cortezaproject/corteza/server", coordinate.LocalVersion),
		coordinatetest.MustNew("github.com/spf13/cobra", "v1.8.1"),
		coordinatetest.MustNew("github.com/Masterminds/sprig", "v2.22.0+incompatible"),
	} {
		for name, build := range builders {
			for _, d := range []string{"", dir} {
				t.Run(coord.String()+"/"+name+"/dir="+d, func(t *testing.T) {
					assertRemedyLine(t, coord, build(coord, d))
				})
			}
		}
	}
}

// The three answers the builder can give, pinned by shape so a change to any of
// them is deliberate.
func TestReanalysisRemedy_SaysWhichOfThreeThingsItKnows(t *testing.T) {
	local := coordinatetest.MustNew("github.com/cortezaproject/corteza/server", coordinate.LocalVersion)
	published := coordinatetest.MustNew("github.com/spf13/cobra", "v1.8.1")
	const dir = "/srv/checkouts/project"

	// A published coordinate has no working tree, so the directory is ignored and
	// the line does not move whichever way it is called.
	for _, d := range []string{"", dir} {
		if got, want := cgdomain.ReanalysisInstruction(published, d),
			"kanonarion callgraph github.com/spf13/cobra@v1.8.1"; got != want {
			t.Errorf("ReanalysisInstruction(published, %q) = %q, want %q", d, got, want)
		}
		if got, want := cgdomain.ForcedReanalysisInstruction(published, d),
			"kanonarion callgraph github.com/spf13/cobra@v1.8.1 --force"; got != want {
			t.Errorf("ForcedReanalysisInstruction(published, %q) = %q, want %q", d, got, want)
		}
	}

	// A local coordinate whose tree is known names it, and the line runs.
	if got, want := cgdomain.ReanalysisInstruction(local, dir), "kanonarion local "+dir; got != want {
		t.Errorf("ReanalysisInstruction(local, dir) = %q, want %q", got, want)
	}
	if got, want := cgdomain.ForcedReanalysisInstruction(local, dir), "kanonarion local "+dir+" --force"; got != want {
		t.Errorf("ForcedReanalysisInstruction(local, dir) = %q, want %q", got, want)
	}
	assertRunnableFor(t, local, cgdomain.ReanalysisInstruction(local, dir))

	// A local coordinate whose tree is not known says so, and must not open with a
	// bare "kanonarion local": that is a valid invocation which analyses whatever
	// directory the reader is standing in.
	for _, got := range []string{
		cgdomain.ReanalysisInstruction(local, ""),
		cgdomain.ForcedReanalysisInstruction(local, ""),
	} {
		if strings.HasPrefix(got, "kanonarion ") {
			t.Errorf("%q reads as a command line to copy", got)
		}
		if !strings.Contains(got, "kanonarion local") {
			t.Errorf("%q names no command at all", got)
		}
	}
	if got := cgdomain.ForcedReanalysisInstruction(local, ""); !strings.Contains(got, "--force") {
		t.Errorf("the forced form dropped its flag: %q", got)
	}
}

// IncompleteGraphRemedy is the other printed remedy that re-derives a graph, so
// it owes the same guarantee across every cause it branches on.
func TestIncompleteGraphRemedy_NeverPrintsAPlaceholder(t *testing.T) {
	for _, coord := range []coordinate.ModuleCoordinate{
		coordinatetest.MustNew("example.com/app", coordinate.LocalVersion),
		coordinatetest.MustNew("github.com/spf13/cobra", "v1.8.1"),
	} {
		for _, cause := range []cgdomain.FailureCause{
			cgdomain.FailureCauseModule, cgdomain.FailureCauseEnvironment, "",
		} {
			for _, detail := range []string{"", "missing go.sum entry for x; to add it: go mod tidy"} {
				for _, dir := range []string{"", "/srv/checkouts/project"} {
					got := cgdomain.IncompleteGraphRemedy(coord, cause, detail, dir)
					if strings.Contains(got, cgdomain.LocalDirPlaceholder) {
						t.Errorf("IncompleteGraphRemedy(%s, %q, dir=%q) prints %s:\n%s",
							coord, cause, dir, cgdomain.LocalDirPlaceholder, got)
					}
				}
			}
		}
	}
}

// The composed-read conflict prints its remedy from inside the store, where
// nothing downstream can correct it. A project coordinate reaches it whenever
// two working trees were analysed under one name.
func TestCallGraphConflictRemedy_IsRunnableForEitherCoordinateKind(t *testing.T) {
	fields := cgdomain.ConflictFields()
	for _, coord := range []coordinate.ModuleCoordinate{
		coordinatetest.MustNew("example.com/app", coordinate.LocalVersion),
		coordinatetest.MustNew("github.com/spf13/cobra", "v1.8.1"),
	} {
		for _, f := range fields {
			t.Run(coord.String()+"/"+f, func(t *testing.T) {
				// Both halves of the per-site decision: a conflict whose records agree
				// on the tree they were analysed in names it, one that cannot does not
				// pretend to.
				for _, root := range []string{"", "/srv/checkouts/app"} {
					c := cgdomain.CallGraphConflict{Coordinate: coord, Field: f, AnalysisRoot: root}
					lines := c.Remedy().Lines
					if len(lines) == 0 {
						t.Fatal("a conflict that refuses a read names no way out of it")
					}
					for _, line := range lines {
						assertRemedyLine(t, coord, line)
						// A conflict whose records agree on the tree can always name it, so
						// falling back to the unnamed-tree answer means the root was not
						// threaded through.
						if root != "" && coord.IsLocal() && strings.Contains(line, cgdomain.UnnamedWorkingTreeLead) {
							t.Errorf("remedy %q says no tree is recorded while the conflict names %s", line, root)
						}
					}
				}
			})
		}
	}
}

// Every extraction stage that needs a module's bytes refuses a missing one
// through this one builder, so a project coordinate reaches it from all five.
func TestNotFetchedRemedy_IsRunnableForEitherCoordinateKind(t *testing.T) {
	for _, coord := range []coordinate.ModuleCoordinate{
		coordinatetest.MustNew("example.com/app", coordinate.LocalVersion),
		coordinatetest.MustNew("github.com/spf13/cobra", "v1.8.1"),
	} {
		t.Run(coord.String(), func(t *testing.T) {
			assertRunnableFor(t, coord, quotedInvocation(t, fetchdomain.NotFetchedRemedy(coord)))
		})
	}
}

// The remedy is a sentence around one command; the guard above checks commands.
func quotedInvocation(t *testing.T, remedy string) string {
	t.Helper()
	_, after, ok := strings.Cut(remedy, "'")
	if !ok {
		t.Fatalf("remedy %q names no quoted command", remedy)
	}
	cmd, _, ok := strings.Cut(after, "'")
	if !ok {
		t.Fatalf("remedy %q leaves its command unclosed", remedy)
	}
	return cmd
}
