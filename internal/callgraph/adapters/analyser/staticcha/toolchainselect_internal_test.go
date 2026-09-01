package staticcha

import (
	"context"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/eitanity/kanonarion/internal/callgraph/domain"
	"github.com/eitanity/kanonarion/internal/coordinate"
)

// childEnvs is every environment the analysis handed a Go child, in the order
// they were recorded. Asserting on these rather than on the outcome is the point:
// the guarantee this mechanism has to keep is about what the subprocess was
// given, and an outcome can be right for the wrong reason.
type childEnvs []map[string]string

// toolchainHarness stands up one analysis whose Go child is a script: it records
// the environment it was handed, reports whether it can see a versioned toolchain
// on its own PATH, and fails with the go command's own too-new sentence when
// tooNew is set.
//
// The host's real ~/sdk and module cache are replaced with empty directories, so
// what is on disk is entirely the test's statement and a developer's own
// toolchain collection cannot make a run pass or fail.
func toolchainHarness(t *testing.T, goDirective string, tooNew bool) (*Analyser, string, func() childEnvs) {
	t.Helper()
	home, envDir, goDir := t.TempDir(), t.TempDir(), t.TempDir()
	tree := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("GOMODCACHE", t.TempDir())
	t.Setenv("GOENV", "off")
	t.Setenv("KANONARION_CHILD_ENV_DIR", envDir)

	write(t, filepath.Join(tree, "go.mod"), "module example.com/probe\n\ngo "+goDirective+"\n")
	write(t, filepath.Join(tree, "a.go"), "package probe\n")

	refusal := ""
	if tooNew {
		refusal = "echo 'go: go.mod requires go >= 1.99.0 (running go 1.26.5; GOTOOLCHAIN=local)' >&2\n"
	}
	script := "#!/bin/sh\n" +
		"f=$(mktemp \"$KANONARION_CHILD_ENV_DIR/child.XXXXXX\")\n" +
		"env > \"$f\"\n" +
		"echo \"KANONARION_SHIM_RESOLVED=$(command -v go1.99.0 || true)\" >> \"$f\"\n" +
		refusal +
		"exit 1\n"
	fakeGo := filepath.Join(goDir, "go")
	if err := os.WriteFile(fakeGo, []byte(script), 0o700); err != nil { // #nosec G306 -- a binary this test execs must be executable
		t.Fatalf("writing fake go: %v", err)
	}

	read := func() childEnvs {
		t.Helper()
		entries, err := os.ReadDir(envDir)
		if err != nil {
			t.Fatalf("reading recorded environments: %v", err)
		}
		var out childEnvs
		for _, e := range entries {
			raw, rerr := os.ReadFile(filepath.Join(envDir, e.Name())) // #nosec G304 -- written by this test into its own t.TempDir()
			if rerr != nil {
				t.Fatalf("reading %s: %v", e.Name(), rerr)
			}
			env := map[string]string{}
			for _, line := range strings.Split(string(raw), "\n") {
				if k, v, ok := strings.Cut(line, "="); ok {
					env[k] = v
				}
			}
			out = append(out, env)
		}
		if len(out) == 0 {
			t.Fatal("the loader never ran a child, so nothing about its environment was measured")
		}
		return out
	}
	return New("0.0.0-test", fakeGo, slog.New(slog.NewTextHandler(io.Discard, nil))), tree, read
}

// fakeSDK writes a directory this host's toolchain search accepts as an unpacked
// Go toolchain of the named version.
func fakeSDK(t *testing.T, dir, version string) {
	t.Helper()
	write(t, filepath.Join(dir, "VERSION"), version+"\ntime 2026-08-11T00:40:52Z\n")
	if err := os.MkdirAll(filepath.Join(dir, "bin"), 0o750); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "bin", "go"), []byte("#!/bin/sh\nexit 0\n"), 0o700); err != nil { // #nosec G306 -- a toolchain command must be executable to be one
		t.Fatalf("writing bin/go: %v", err)
	}
}

func analyse(t *testing.T, a *Analyser, tree string) domain.CallGraphRecord {
	t.Helper()
	coord, err := coordinate.NewModuleCoordinate("example.com/probe", coordinate.LocalVersion)
	if err != nil {
		t.Fatalf("coordinate: %v", err)
	}
	rec, err := a.AnalyseDir(context.Background(), tree, coord)
	if err != nil {
		t.Fatalf("AnalyseDir: %v", err)
	}
	return rec
}

// TestAnalyseDir_UsesAToolchainAlreadyOnThisHostWhenTheDirectiveExceedsTheInstalledOne
// is the defect: every analysis child is pinned so it can never download a
// toolchain, and that pin also refused a toolchain sitting unpacked on the same
// disk. A module whose go directive is one point release ahead of the host was
// therefore unanalysable, however well equipped the host actually was.
//
// The assertion is on the two environments the children were handed, not on the
// graph. The first child is pinned as it always was. The second is given the
// toolchain directory in front of its PATH and the one selection mode that can
// use it and still cannot download — and both children keep the offline posture
// the pin exists to serve.
func TestAnalyseDir_UsesAToolchainAlreadyOnThisHostWhenTheDirectiveExceedsTheInstalledOne(t *testing.T) {
	a, tree, recorded := toolchainHarness(t, "1.99.0", true)
	home, err := os.UserHomeDir()
	if err != nil {
		t.Fatalf("UserHomeDir: %v", err)
	}
	fakeSDK(t, filepath.Join(home, "sdk", "go1.99.0"), "go1.99.0")

	analyse(t, a, tree)

	envs := recorded()
	var pinned, switched map[string]string
	for _, env := range envs {
		switch env["GOTOOLCHAIN"] {
		case "local":
			pinned = env
		case "path":
			switched = env
		default:
			t.Errorf("a child was given GOTOOLCHAIN=%q; no analysis child may negotiate its own toolchain",
				env["GOTOOLCHAIN"])
		}
	}
	if pinned == nil {
		t.Error("no child ran under the pinned toolchain; the cheapest path must still be tried first")
	}
	if switched == nil {
		t.Fatalf("the analysis never retried under a toolchain on this host: %d child environment(s) recorded", len(envs))
	}
	if switched["KANONARION_SHIM_RESOLVED"] == "" {
		t.Errorf("the retried child could not find go1.99.0 on its own PATH=%q; the go command looks for a "+
			"toolchain by that name and nothing else", switched["PATH"])
	}
	for _, env := range envs {
		if env["GOPROXY"] != "off" || env["GOSUMDB"] != "off" {
			t.Errorf("a child was given GOPROXY=%q GOSUMDB=%q; the switch must not open the network",
				env["GOPROXY"], env["GOSUMDB"])
		}
	}
}

// TestAnalyseDir_LeavesTheInstalledToolchainAloneWhenItSatisfiesTheDirective is
// the control that must not move. A toolchain is on disk here too, and it must
// stay unused: the installed one answers, and an analysis that reached past it
// would change every record on every host that has ever switched toolchains.
func TestAnalyseDir_LeavesTheInstalledToolchainAloneWhenItSatisfiesTheDirective(t *testing.T) {
	a, tree, recorded := toolchainHarness(t, "1.21", false)
	home, err := os.UserHomeDir()
	if err != nil {
		t.Fatalf("UserHomeDir: %v", err)
	}
	fakeSDK(t, filepath.Join(home, "sdk", "go1.99.0"), "go1.99.0")

	analyse(t, a, tree)

	for _, env := range recorded() {
		if env["GOTOOLCHAIN"] != "local" {
			t.Errorf("a child was given GOTOOLCHAIN=%q, want local: nothing asked for another toolchain",
				env["GOTOOLCHAIN"])
		}
	}
}

// TestAnalyseDir_NamesKanonarionAsThePinnerWhenNoToolchainIsOnDisk. Without this
// the reader is shown GOTOOLCHAIN=local inside the go command's sentence and
// cannot tell their own shell from this tool's posture, so they go looking in the
// wrong place. The refusal has to say who pinned it, what would satisfy it, and
// how to obtain that.
func TestAnalyseDir_NamesKanonarionAsThePinnerWhenNoToolchainIsOnDisk(t *testing.T) {
	a, tree, recorded := toolchainHarness(t, "1.99.0", true)

	rec := analyse(t, a, tree)

	for _, want := range []string{
		"kanonarion pins the toolchain",
		"go >= 1.99.0",
		"golang.org/dl/go1.99.0",
		"go.mod requires go >= 1.99.0",
	} {
		if !strings.Contains(rec.FailureDetail, want) {
			t.Errorf("the refusal does not mention %q:\n%s", want, rec.FailureDetail)
		}
	}
	if rec.FailureCause != domain.FailureCauseEnvironment {
		t.Errorf("cause = %v, want environment: a toolchain this host lacks is not a property of the module",
			rec.FailureCause)
	}
	for _, env := range recorded() {
		if env["GOTOOLCHAIN"] != "local" {
			t.Errorf("a child was given GOTOOLCHAIN=%q with nothing on disk to switch to", env["GOTOOLCHAIN"])
		}
	}
}
