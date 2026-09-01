package cli

import (
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

// Every refusal that tells a reader to re-derive a call graph goes through the
// two builders below, so this is the whole class in one test: both coordinate
// kinds, both the plain and the forced form.
func TestReanalysisCommand_IsRunnableForEitherCoordinateKind(t *testing.T) {
	for _, coord := range []coordinate.ModuleCoordinate{
		coordinatetest.MustNew("github.com/cortezaproject/corteza/server", coordinate.LocalVersion),
		coordinatetest.MustNew("github.com/spf13/cobra", "v1.8.1"),
		coordinatetest.MustNew("github.com/Masterminds/sprig", "v2.22.0+incompatible"),
	} {
		t.Run(coord.String(), func(t *testing.T) {
			assertRunnableFor(t, coord, cgdomain.ReanalysisCommand(coord, ""))
			assertRunnableFor(t, coord, cgdomain.ForcedReanalysisCommand(coord, ""))
			assertRunnableFor(t, coord, cgdomain.ReanalysisCommand(coord, "/srv/checkouts/project"))
		})
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
				c := cgdomain.CallGraphConflict{Coordinate: coord, Field: f}
				lines := c.Remedy().Lines
				if len(lines) == 0 {
					t.Fatal("a conflict that refuses a read names no way out of it")
				}
				for _, line := range lines {
					assertRunnableFor(t, coord, line)
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
