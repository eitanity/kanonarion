package cli

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/spf13/cobra"
)

// A read must not create the store it reads from.
//
// `--store-root ./typo-store` used to build a store at that path and then
// answer from it: "the store holds no scan run at all", exit 0, no warning.
// That sentence is true of a store created a millisecond earlier and false
// about the store the operator meant, and the directory left behind is real —
// one reached 128 MB in a working tree before anyone noticed it.
//
// Every case below asserts the DIRECTORY IS ABSENT afterwards, not merely that
// the exit code moved. A build that still creates the store and then refuses
// would satisfy an exit-code assertion and leave the whole defect in place.

// missingRoot returns a path inside a fresh temp directory that does not exist,
// together with the parent, so a test can also see that nothing else appeared.
func missingRoot(t *testing.T) (root, parent string) {
	t.Helper()
	parent = t.TempDir()
	root = filepath.Join(parent, "typo-store")
	if _, err := os.Stat(root); !os.IsNotExist(err) {
		t.Fatalf("the missing root %s already exists: %v", root, err)
	}
	return root, parent
}

// assertNothingCreated fails unless root is still absent and its parent is
// still empty. The parent is checked too because the defect is a path the
// caller did not mean: a fix that moved creation one directory up would still
// be the same bug.
func assertNothingCreated(t *testing.T, root, parent string) {
	t.Helper()
	if _, err := os.Stat(root); !os.IsNotExist(err) {
		entries, _ := os.ReadDir(root)
		names := make([]string, 0, len(entries))
		for _, e := range entries {
			names = append(names, e.Name())
		}
		t.Errorf("the read created the store root %s it was told to read from; it holds %v", root, names)
	}
	entries, err := os.ReadDir(parent)
	if err != nil {
		t.Fatalf("reading %s: %v", parent, err)
	}
	if len(entries) != 0 {
		names := make([]string, 0, len(entries))
		for _, e := range entries {
			names = append(names, e.Name())
		}
		t.Errorf("the read created %v under %s", names, parent)
	}
}

// TestRun_ReadAgainstAMissingStoreRootCreatesNothing covers one read from each
// surface — a listing, a record read, and a graph query — because they reach
// the store by different routes and only the seam they share was fixed.
func TestRun_ReadAgainstAMissingStoreRootCreatesNothing(t *testing.T) {
	cases := []struct {
		name string
		args []string
	}{
		{"listing", []string{"vuln-scan-list"}},
		{"record read", []string{"walk-show", "01JX0000000000000000000000"}},
		{"graph query", []string{"callers", "example.com/mod.Foo"}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			root, parent := missingRoot(t)

			var stdout, stderr bytes.Buffer
			err := Run(append(tc.args, "--store-root", root), &stdout, &stderr)

			assertNothingCreated(t, root, parent)

			if err == nil {
				t.Fatalf("a read against a store root that does not exist succeeded; stdout=%q", stdout.String())
			}
			if code := ExitCodeForError(err); code != ExitConfig {
				t.Errorf("exit code = %d, want %d (a precondition the command never got past)", code, ExitConfig)
			}
			// The refusal has to be actionable: the whole failure mode is a
			// path the caller did not mean, so the path and the way out of it
			// both have to be in the message.
			if !strings.Contains(err.Error(), root) {
				t.Errorf("the refusal does not name the path it looked at: %v", err)
			}
			if !strings.Contains(err.Error(), "kanonarion inspect") {
				t.Errorf("the refusal does not name a command that creates a store: %v", err)
			}
		})
	}
}

// `--store-root` consumes the next token, so `--store-root --help` makes
// "--help" the store root and the help is never printed. That is the flag
// parser working as specified; it was only harmful because a read created. It
// needs no special case — once a read refuses a root that is not there, the
// invocation fails with that refusal instead of leaving a directory called
// `--help` behind.
func TestRun_StoreRootSwallowingHelpCreatesNoDirectory(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)

	var stdout, stderr bytes.Buffer
	err := Run([]string{"vuln-scan-list", "--store-root", "--help"}, &stdout, &stderr)
	if err == nil {
		t.Fatalf("`--store-root --help` succeeded; stdout=%q", stdout.String())
	}

	if entries, rerr := os.ReadDir(dir); rerr != nil {
		t.Fatalf("reading %s: %v", dir, rerr)
	} else if len(entries) != 0 {
		names := make([]string, 0, len(entries))
		for _, e := range entries {
			names = append(names, e.Name())
		}
		t.Errorf("`--store-root --help` created %v in the working directory", names)
	}
}

// Control: a command that writes records still creates the root it writes
// into, so a first run on a clean machine needs no preparatory step.
//
// `config init` is the offline member of that class — it writes config.yaml
// into the store root and contacts nothing — so it can assert the control
// without a network fetch. `walk`, `inspect`, `fetch` and `extract` are held
// to the same rule by TestStoreIntent_TheWritingCommandsDeclareCreate below.
func TestRun_WriteAgainstAMissingStoreRootCreatesIt(t *testing.T) {
	root, _ := missingRoot(t)

	var stdout, stderr bytes.Buffer
	if err := Run([]string{"config", "init", "--store-root", root}, &stdout, &stderr); err != nil {
		t.Fatalf("a write against a store root that does not exist was refused: %v (stderr=%q)", err, stderr.String())
	}
	if _, err := os.Stat(filepath.Join(root, "config.yaml")); err != nil {
		t.Errorf("the write did not create the store root it writes into: %v", err)
	}
}

// Control: a store root that EXISTS answers exactly as it did before. The gate
// is about creation, so an empty store still reports itself empty and exits 0.
func TestRun_ReadAgainstAnExistingStoreRootIsUnchanged(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if err := Run([]string{"vuln-scan-list", "--store-root", t.TempDir()}, &stdout, &stderr); err != nil {
		t.Fatalf("a read against an existing store root was refused: %v", err)
	}
	if !strings.Contains(stdout.String(), "no scan run") {
		t.Errorf("stdout = %q, want the empty-store answer", stdout.String())
	}
}

// The polarity is the point: a command that says nothing about the store
// refuses. Getting this backwards would reintroduce the defect for every
// command added after this one.
func TestStoreIntent_UndeclaredCommandsRefuse(t *testing.T) {
	if got := storeIntentOf(&cobra.Command{Use: "undeclared"}); got != StoreIntentRead {
		t.Errorf("a command with no annotation resolves to %q, want %q: a new command must fail safe rather than mint a store", got, StoreIntentRead)
	}
	if got := storeIntentOf(&cobra.Command{
		Use:         "misdeclared",
		Annotations: map[string]string{annotationStoreIntent: "sometimes"},
	}); got != StoreIntentRead {
		t.Errorf("a command with an unknown intent resolves to %q, want %q", got, StoreIntentRead)
	}
	if got := storeIntentOf(nil); got != StoreIntentRead {
		t.Errorf("a nil command resolves to %q, want %q", got, StoreIntentRead)
	}
}

// The four commands named as having to work on a clean machine with no
// preparatory step, held to that by name so a later edit cannot quietly demote
// one of them to a read and break the first run.
func TestStoreIntent_TheWritingCommandsDeclareCreate(t *testing.T) {
	want := map[string]bool{"walk": true, "inspect": true, "fetch": true, "extract": true}

	seen := map[string]string{}
	for _, c := range RegisteredCommands() {
		if len(c.Path) == 1 && want[c.Path[0]] {
			seen[c.Path[0]] = c.StoreIntent
		}
	}
	for name := range want {
		switch intent, ok := seen[name]; {
		case !ok:
			t.Errorf("`kanonarion %s` is not registered", name)
		case intent != StoreIntentCreate:
			t.Errorf("`kanonarion %s` declares %q, want %q: a first run on a clean machine must not need a preparatory step", name, intent, StoreIntentCreate)
		}
	}
}
