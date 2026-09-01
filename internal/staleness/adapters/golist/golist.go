// Package golist answers the staleness context's latest-version question for a
// whole set of modules in one call, by asking the go command.
//
// The standing rule is that where the go command can answer a question about
// what a build contains, that answer is correct by definition. "What is the
// newest version of every module in this build list" is exactly such a question,
// and `go list -m -u -json` answers it in one batched, module-cache-aware call
// for the whole closure. Resolving it instead one proxy request at a time was
// hundreds of times slower on the same target AND lost answers, because the
// request pattern is the one a public proxy throttles.
//
// What this adapter does NOT answer is the newer-major question. `go list -m -u`
// deliberately does not cross a major boundary — a module a whole major behind
// is at the newest version of its own path, and the go command says so — so the
// /vN probe stays kanonarion's own and stays on the per-path port.
package golist

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/eitanity/kanonarion/internal/adapters/childproc"
	"github.com/eitanity/kanonarion/internal/adapters/goenv"
	"github.com/eitanity/kanonarion/internal/staleness/ports"
)

// ErrNoUpdateCheck reports that the environment forbids module fetching, so the
// go command would answer WITHOUT checking for updates.
//
// This refusal is the whole reason this adapter exists as a named type rather
// than a call site. Under GOPROXY=off `go list -m -u -json` exits 0, writes
// nothing to stderr, and simply omits the "Update" key from every module —
// output that is byte-identical to "every one of these modules is current".
// Ported naively, that reports a whole dependency closure as up to date on a run
// that checked nothing, which is a confident wrong answer about the entire
// population and far worse than the slow sweep it replaces.
//
// So the adapter refuses instead of answering. Offline, the ledger is what
// answers: a recorded lookup inside the staleness TTL is served with its own
// lookup time, and a module without one is refused rather than called current.
var ErrNoUpdateCheck = fmt.Errorf("%w: `go list -m -u` would report every module as current without checking",
	goenv.ErrNetworkForbidden)

// Resolver is a ports.BatchLatestResolver backed by `go list -m -u -json`.
type Resolver struct {
	// dir is the directory the go command runs in. It must be inside the module
	// whose build list the requested paths came from, because -m resolves paths
	// against that module's build list and nothing else.
	dir string
	// goproxy, when non-empty, is handed to the child process as GOPROXY so the
	// --goproxy override applies to the batched answer as well as to the probe.
	// Empty means the child reads GOPROXY exactly as this process does.
	goproxy string
	// timeout bounds the whole batched call. It is a field so the refusal path
	// can be driven in a test without waiting.
	timeout time.Duration
}

var _ ports.BatchLatestResolver = (*Resolver)(nil)

// batchTimeout bounds one batched resolution. It is generous by the standard of
// a single metadata request because it covers the whole closure — the measured
// warm figure for a 552-module build list on this project's road-test target is
// under five seconds — and it exists only so a wedged child cannot hang a
// command indefinitely.
const batchTimeout = 5 * time.Minute

// New returns a Resolver running the go command in dir. goproxy is the
// --goproxy override, or empty to let the child read the environment.
func New(dir, goproxy string) *Resolver {
	return &Resolver{dir: dir, goproxy: goproxy, timeout: batchTimeout}
}

// goListModule is the subset of `go list -m -json` this adapter reads.
type goListModule struct {
	Path    string     `json:"Path"`
	Version string     `json:"Version"`
	Time    *time.Time `json:"Time"`
	Main    bool       `json:"Main"`
	Update  *struct {
		Path    string     `json:"Path"`
		Version string     `json:"Version"`
		Time    *time.Time `json:"Time"`
	} `json:"Update"`
	Deprecated string `json:"Deprecated"`
}

// LatestBatch resolves the latest version of every path in one go command.
//
// A path the go command did not report is simply absent from the map. That is
// the contract the port states and it is load-bearing: absence means "not
// answered", and the caller falls back to a per-path lookup rather than reading
// it as "current".
func (r *Resolver) LatestBatch(ctx context.Context, paths []string) (map[string]ports.BatchLatest, error) {
	if len(paths) == 0 {
		return map[string]ports.BatchLatest{}, nil
	}
	// The refusal comes BEFORE the call, not after inspecting its output,
	// because the output of a run that checked nothing is indistinguishable from
	// the output of a run where nothing needed updating. See ErrNoUpdateCheck.
	if r.networkForbidden() {
		return nil, ErrNoUpdateCheck
	}

	ctx, cancel := context.WithTimeout(ctx, r.timeout)
	defer cancel()

	args := append([]string{"list", "-m", "-u", "-json", "-mod=readonly"}, paths...)
	cmd := childproc.CommandContext(ctx, "go", args...) // #nosec G204 -- args are module paths resolved by the go command itself from this project's own build list
	cmd.Dir = r.dir
	cmd.Env = r.childEnv()
	out, err := cmd.Output()
	if err != nil {
		return nil, r.execError(args, err)
	}

	return parseGoListModules(out)
}

// parseGoListModules reads the concatenated JSON objects `go list -m -json`
// writes. The main module is skipped: it has no published latest and is not a
// dependency of itself.
func parseGoListModules(out []byte) (map[string]ports.BatchLatest, error) {
	answers := make(map[string]ports.BatchLatest)
	dec := json.NewDecoder(bytes.NewReader(out))
	for {
		var m goListModule
		if derr := dec.Decode(&m); errors.Is(derr, io.EOF) {
			break
		} else if derr != nil {
			return nil, fmt.Errorf("reading `go list -m -u -json` output: %w", derr)
		}
		if m.Path == "" || m.Main {
			continue
		}
		answers[m.Path] = batchLatestOf(m)
	}
	return answers, nil
}

// batchLatestOf reads one module's answer.
//
// An absent Update key means the module is at its newest version, so the latest
// IS the version in the build list — read from the same record rather than
// filled in by the caller from its own pin, which would let a coordinate the
// build list resolved differently answer for itself.
func batchLatestOf(m goListModule) ports.BatchLatest {
	version, published := m.Version, m.Time
	if m.Update != nil {
		version, published = m.Update.Version, m.Update.Time
	}
	b := ports.BatchLatest{
		LatestInfo: ports.LatestInfo{Version: version},
		Deprecated: m.Deprecated,
		Updated:    m.Update != nil,
	}
	// A date is never fabricated: a module the go command supplied no time for
	// keeps the zero time, which every renderer states as no date.
	if published != nil {
		b.Time = published.UTC()
	}
	return b
}

// networkForbidden reports whether the effective GOPROXY for the child forbids
// fetching. The --goproxy override is read under the same grammar as the
// environment, so `--goproxy off` refuses exactly as GOPROXY=off does.
func (r *Resolver) networkForbidden() bool {
	if strings.TrimSpace(r.goproxy) != "" {
		return goenv.FirstProxyEntry(r.goproxy) == "off"
	}
	return goenv.NetworkForbidden()
}

// childEnv is the environment for the go command. It is this process's, plus
// the --goproxy override when one was given, so the flag governs the batched
// answer and the per-path probe alike rather than only the latter.
func (r *Resolver) childEnv() []string {
	if strings.TrimSpace(r.goproxy) == "" {
		return nil
	}
	return append(os.Environ(), "GOPROXY="+r.goproxy)
}

// execError names what went wrong in the go command's own words. A batched
// resolution that could not be made is an ERROR, never an empty answer: the
// caller must not read "no modules came back" as "no module has an update".
func (r *Resolver) execError(args []string, err error) error {
	if errors.Is(err, exec.ErrNotFound) {
		return fmt.Errorf("go toolchain not found on PATH: required to resolve the latest version of the dependency set")
	}
	var ee *exec.ExitError
	if errors.As(err, &ee) && len(ee.Stderr) > 0 {
		return fmt.Errorf("go list -m -u: %s", strings.TrimSpace(string(ee.Stderr)))
	}
	return fmt.Errorf("go %s: %w", strings.Join(args[:4], " "), err)
}
