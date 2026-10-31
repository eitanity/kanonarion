package consumer_test

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"testing"

	"code.eitanity.com/kanonarion/pkg/kanonarion"
)

// noCallGraphEnv makes this binary an application that does not serve the
// call-graph child: it refuses the argv as a main with no such command would.
const noCallGraphEnv = "KANONARION_CONSUMER_NO_CALLGRAPH"

// noCallGraphMessage is that refusal, which the parent records on the stage.
const noCallGraphMessage = `unknown command "callgraph"`

// TestMain is this test binary's main, shaped as an importing application's:
// it registers its backends, then serves the call-graph child when the driver
// starts this executable as one. Answered before the tests run, or a child
// would run the whole suite again.
func TestMain(m *testing.M) {
	for _, b := range []kanonarion.Backend{probeBackend(), filesBackend()} {
		if err := kanonarion.RegisterBackend(b); err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			os.Exit(1)
		}
	}
	if len(os.Args) > 1 && os.Args[1] == "callgraph" {
		if os.Getenv(noCallGraphEnv) != "" {
			fmt.Fprintf(os.Stderr, "error: %s\n", noCallGraphMessage)
			os.Exit(2)
		}
		os.Exit(kanonarion.ServeCallGraphChild(os.Args[1:], os.Stdout, os.Stderr))
	}
	code := m.Run()
	for _, dir := range []string{builtDir, govulncheckDir} {
		if dir != "" {
			_ = os.RemoveAll(dir)
		}
	}
	os.Exit(code)
}

var (
	buildOnce sync.Once
	builtDir  string
	builtBin  string
	buildErr  error
)

// kanonarionBinary builds the CLI from this checkout once per test binary.
func kanonarionBinary(t *testing.T) string {
	t.Helper()
	buildOnce.Do(func() {
		builtDir, buildErr = os.MkdirTemp("", "kanonarion-consumer-*")
		if buildErr != nil {
			return
		}
		builtBin = filepath.Join(builtDir, "kanonarion")
		cmd := exec.Command("go", "build", "-o", builtBin, "./cmd/kanonarion")
		cmd.Dir = filepath.Join("..", "..")
		var out []byte
		if out, buildErr = cmd.CombinedOutput(); buildErr != nil {
			buildErr = errors.Join(buildErr, errors.New(string(out)))
		}
	})
	if buildErr != nil {
		t.Fatalf("building kanonarion: %v", buildErr)
	}
	return builtBin
}

// runKanonarion runs the built CLI on storeRoot with env added, returning its
// stdout, stderr and exit code.
func runKanonarion(t *testing.T, storeRoot string, env []string, args ...string) (string, string, int) {
	t.Helper()
	cmd := exec.Command(kanonarionBinary(t), append([]string{"--store-root", storeRoot}, args...)...) // #nosec G204 -- the binary this test built
	cmd.Env = append(os.Environ(), env...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	err := cmd.Run()
	var exit *exec.ExitError
	code := 0
	switch {
	case errors.As(err, &exit):
		code = exit.ExitCode()
	case err != nil:
		t.Fatalf("running kanonarion %v: %v", args, err)
	}
	return stdout.String(), stderr.String(), code
}
