package consumer_test

import (
	"bytes"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"testing"
)

// childBinaryEnv names the kanonarion binary this test binary stands in for
// when a driver spawns it as its call-graph child. A consumer's own binary
// embeds the CLI; this one forwards to a built one instead, because it may
// import nothing but pkg/kanonarion.
const childBinaryEnv = "KANONARION_CONSUMER_CHILD_BINARY"

func TestMain(m *testing.M) {
	if bin := os.Getenv(childBinaryEnv); bin != "" && len(os.Args) > 1 && os.Args[1] == "callgraph" {
		os.Exit(forward(bin, os.Args[1:]))
	}
	code := m.Run()
	if builtDir != "" {
		_ = os.RemoveAll(builtDir)
	}
	os.Exit(code)
}

// forward runs bin with args on this process's streams and returns its exit
// code.
func forward(bin string, args []string) int {
	cmd := exec.Command(bin, args...) // #nosec G204 G702 -- the binary this test built
	cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr
	err := cmd.Run()
	var exit *exec.ExitError
	switch {
	case err == nil:
		return 0
	case errors.As(err, &exit):
		return exit.ExitCode()
	default:
		return 1
	}
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
