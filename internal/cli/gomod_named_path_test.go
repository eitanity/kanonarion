package cli

import (
	"bytes"
	"strings"
	"testing"
)

// The path a caller NAMES is the one that must exist.
//
// It was the one path never checked: an explicit --gomod was returned unread
// while the ./go.mod default was stat'd. A command that reads the file failed on
// its own, but one that only takes the path's DIRECTORY — `go list ./...` after
// a chdir — never touched it, and answered in full about whatever was beside it.
// Each case below puts a real go.mod in the working directory, so a run that
// silently fell back to the default would look like success.

// commandsTakingANamedGoMod names, for each surface, the arguments that reach
// the resolver. `context` renders a document from the directory; `notice`
// resolves its module set the same way and exits on the result.
var commandsTakingANamedGoMod = []struct {
	name string
	args []string
}{
	{name: "context", args: []string{"context"}},
	{name: "notice", args: []string{"notice"}},
	{name: "godebug", args: []string{"godebug"}},
	{name: "directives", args: []string{"directives"}},
	{name: "fips", args: []string{"fips"}},
}

func runWithNamedGoMod(t *testing.T, args []string, gomod string) (string, error) {
	t.Helper()
	var stdout, stderr bytes.Buffer
	full := append(append([]string{}, args...), "--gomod", gomod, "--store-root", t.TempDir())
	err := Run(full, &stdout, &stderr)
	return stdout.String(), err
}

func TestNamedGoModThatIsNotThereIsRefusedBeforeAnyWork(t *testing.T) {
	for _, c := range commandsTakingANamedGoMod {
		t.Run(c.name, func(t *testing.T) {
			// A valid manifest IS present: only the named path is missing, and
			// its directory exists. That is the shape that used to answer.
			chdirWithGoMod(t, "module example.com/myapp\n\ngo 1.21\n")

			stdout, err := runWithNamedGoMod(t, c.args, "./no-such-file.mod")
			if err == nil {
				t.Fatal("a --gomod naming no file must not produce an answer")
			}
			if code := ExitCodeForError(err); code != ExitConfig {
				t.Errorf("exit code = %d, want %d: a bad flag value is a broken invocation", code, ExitConfig)
			}
			if stdout != "" {
				t.Errorf("a refused invocation emitted a document (%d bytes):\n%s", len(stdout), stdout)
			}
			msg := err.Error()
			for _, want := range []string{"--gomod", "./no-such-file.mod"} {
				if !strings.Contains(msg, want) {
					t.Errorf("the refusal does not name %q: %v", want, msg)
				}
			}
		})
	}
}

// TestNamedGoModSwallowingASiblingFlagIsRefused is how a real caller meets this.
// --gomod takes the next token as its value, so a mistyped sibling flag becomes
// the path; unchecked, the command resolved "." and answered in full.
func TestNamedGoModSwallowingASiblingFlagIsRefused(t *testing.T) {
	chdirWithGoMod(t, "module example.com/myapp\n\ngo 1.21\n")

	var stdout, stderr bytes.Buffer
	err := Run([]string{"context", "--gomod", "--size-only", "--store-root", t.TempDir()}, &stdout, &stderr)
	if err == nil {
		t.Fatal("--gomod --size-only must not be answered as a context request")
	}
	if code := ExitCodeForError(err); code != ExitConfig {
		t.Errorf("exit code = %d, want %d", code, ExitConfig)
	}
	if stdout.Len() != 0 {
		t.Errorf("a swallowed flag produced a document:\n%s", stdout.String())
	}
	if !strings.Contains(err.Error(), "--size-only") {
		t.Errorf("the refusal does not show what was taken as the path: %v", err)
	}
}

// TestNamedGoModDirectoryIsRefused closes the same hole from the other side: a
// directory stats fine, and the commands that use only the path's directory
// would have answered about it.
func TestNamedGoModDirectoryIsRefused(t *testing.T) {
	chdirWithGoMod(t, "module example.com/myapp\n\ngo 1.21\n")

	stdout, err := runWithNamedGoMod(t, []string{"context"}, ".")
	if err == nil {
		t.Fatal("a --gomod naming a directory must not produce an answer")
	}
	if stdout != "" {
		t.Errorf("a refused invocation emitted a document:\n%s", stdout)
	}
	if !strings.Contains(err.Error(), "is a directory") {
		t.Errorf("the refusal does not say what was wrong with the path: %v", err)
	}
}

// TestNamedGoModThatExistsStillResolves guards against closing the hole by
// refusing everything: the named path is returned unchanged when it is there.
func TestNamedGoModThatExistsStillResolves(t *testing.T) {
	chdirWithGoMod(t, "module example.com/myapp\n\ngo 1.21\n")

	got, err := resolveGoModPath("./go.mod")
	if err != nil {
		t.Fatalf("a --gomod naming a real manifest must resolve: %v", err)
	}
	if got != "./go.mod" {
		t.Errorf("got %q, want %q — the resolver must not rewrite the caller's path", got, "./go.mod")
	}
}
