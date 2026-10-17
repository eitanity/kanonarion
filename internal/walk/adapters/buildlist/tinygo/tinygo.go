// Package tinygo asks the tinygo command what a TinyGo target means: its
// platform, build tags and the GOROOT it builds with. kanonarion keeps its own
// go list and govulncheck and runs them under the frame this returns.
package tinygo

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"sync"

	"github.com/eitanity/kanonarion/internal/adapters/childproc"
	"github.com/eitanity/kanonarion/internal/adapters/goenv"
)

// ErrNotOnPath is the refusal for a declaration with no tinygo to ask.
var ErrNotOnPath = errors.New("declaring --tinygo needs the tinygo command on PATH")

// UnknownTargetError is the refusal for a target the tinygo command has no
// definition of.
type UnknownTargetError struct{ Target string }

func (e *UnknownTargetError) Error() string {
	return fmt.Sprintf("tinygo does not know the target %q: run `tinygo targets` for the names it offers", e.Target)
}

// Probe returns the frame binary defines for target. binary may be empty for
// "tinygo" on PATH. A success is memoised per resolved binary and target for
// the process; a failure is not, since it describes the moment.
//
// info's goroot is never read: it names a root TinyGo does not build with, so
// GOROOT is taken from where `tinygo list` finds the runtime package.
func Probe(ctx context.Context, binary, target string) (goenv.TinyGo, error) {
	if binary == "" {
		binary = "tinygo"
	}
	bin, err := exec.LookPath(binary)
	if err != nil {
		return goenv.TinyGo{}, ErrNotOnPath
	}
	key := bin + "\x00" + target
	if f, ok := load(key); ok {
		return f, nil
	}
	versionOut, err := run(ctx, bin, "version")
	if err != nil {
		return goenv.TinyGo{}, err
	}
	version, goVersion, err := parseVersion(versionOut)
	if err != nil {
		return goenv.TinyGo{}, err
	}
	infoOut, err := run(ctx, bin, "info", "-json", "-target="+target)
	if err != nil {
		// A non-zero exit is tinygo finding no definition of the target; one the
		// cancellation caused is not, and keeps its own error.
		var exit *exec.ExitError
		if errors.As(err, &exit) && ctx.Err() == nil {
			return goenv.TinyGo{}, &UnknownTargetError{Target: target}
		}
		return goenv.TinyGo{}, err
	}
	var info struct {
		GOOS       string   `json:"goos"`
		GOARCH     string   `json:"goarch"`
		GOARM      string   `json:"goarm"`
		LLVMTriple string   `json:"llvm_triple"`
		BuildTags  []string `json:"build_tags"`
	}
	if jerr := json.Unmarshal(infoOut, &info); jerr != nil {
		return goenv.TinyGo{}, fmt.Errorf("tinygo info -json -target=%s printed output that is not its JSON: %w", target, jerr)
	}
	listOut, err := run(ctx, bin, "list", "-target="+target, "-json", "runtime")
	if err != nil {
		return goenv.TinyGo{}, err
	}
	goroot, err := parseGOROOT(listOut)
	if err != nil {
		return goenv.TinyGo{}, fmt.Errorf("tinygo list -target=%s -json runtime: %w", target, err)
	}
	// TINYGOROOT holds TinyGo's own packages and target definitions; the call
	// graph analyses the first with bodies and reads the second for its C flags.
	rootOut, err := run(ctx, bin, "env", "TINYGOROOT")
	if err != nil {
		return goenv.TinyGo{}, err
	}
	f, err := goenv.NewTinyGo(target, version, goVersion, info.GOOS, info.GOARCH, info.GOARM, goroot,
		strings.TrimSpace(string(rootOut)), info.LLVMTriple, info.BuildTags)
	if err != nil {
		return goenv.TinyGo{}, fmt.Errorf("tinygo described the target %q incompletely: %w", target, err)
	}
	store(key, f)
	return f, nil
}

// run executes one probe. It inherits the caller's environment unchanged: these
// are TinyGo's own questions about itself, not analysis children.
func run(ctx context.Context, bin string, args ...string) ([]byte, error) {
	cmd := childproc.CommandContext(ctx, bin, args...) // #nosec G204 -- bin is the resolved tinygo binary, args are literals and the declared target
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("tinygo %s: %w: %s", strings.Join(args, " "), err, strings.TrimSpace(stderr.String()))
	}
	return out, nil
}

var versionLine = regexp.MustCompile(`^tinygo version (\S+) .*using go version (go\S+)`)

// parseVersion reads `tinygo version 0.42.0 linux/amd64 (using go version
// go1.27.2 and LLVM version 22.1.4)` for the TinyGo and Go versions.
func parseVersion(out []byte) (version, goVersion string, err error) {
	m := versionLine.FindStringSubmatch(strings.TrimSpace(string(out)))
	if m == nil {
		return "", "", fmt.Errorf("tinygo version printed %q, which names no TinyGo and Go version", strings.TrimSpace(string(out)))
	}
	return m[1], m[2], nil
}

// parseGOROOT is the parent of the src directory that holds the runtime
// package TinyGo lists.
func parseGOROOT(out []byte) (string, error) {
	var pkg struct{ Dir string }
	if err := json.NewDecoder(bytes.NewReader(out)).Decode(&pkg); err != nil {
		return "", fmt.Errorf("output is not a package's JSON: %w", err)
	}
	src := filepath.Dir(pkg.Dir)
	if pkg.Dir == "" || filepath.Base(src) != "src" {
		return "", fmt.Errorf("the runtime package is at %q, which is not under a GOROOT's src", pkg.Dir)
	}
	return filepath.Dir(src), nil
}

var (
	probeMu sync.Mutex
	probes  = map[string]goenv.TinyGo{}
)

func load(key string) (goenv.TinyGo, bool) {
	probeMu.Lock()
	defer probeMu.Unlock()
	f, ok := probes[key]
	return f, ok
}

func store(key string, f goenv.TinyGo) {
	probeMu.Lock()
	defer probeMu.Unlock()
	probes[key] = f
}
