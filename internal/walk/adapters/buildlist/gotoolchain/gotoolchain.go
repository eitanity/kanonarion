// Package gotoolchain implements ports.BuildListResolver by delegating build-list
// computation to the Go toolchain. `go list -m -mod=readonly -json all` yields the
// selected module set and `go mod graph` yields the requirement edges. Both run in
// the project's working directory against the verified go.mod/go.sum, so the
// toolchain performs the exact MVS + lazy-loading arithmetic kanonarion would
// otherwise approximate. The toolchain decides only the SET; every listed module
// is still fetched and verified through kanonarion's own pipeline.
package gotoolchain

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/eitanity/kanonarion/internal/adapters/childproc"
	"github.com/eitanity/kanonarion/internal/adapters/goenv"
	"github.com/eitanity/kanonarion/internal/adapters/interrupt"
	walkports "github.com/eitanity/kanonarion/internal/walk/ports"
)

// Resolver runs the Go toolchain to compute a project's build list.
type Resolver struct {
	goBinary string // empty → resolved via PATH as "go"
	// target is the platform this resolver's children resolve for. The zero
	// value is a resolver nobody declared a target to, which still writes the
	// measured host into every child: see goenv.Target.Apply.
	target goenv.Target
	// tinygo is the declared TinyGo frame, layered after target; zero when
	// none was declared.
	tinygo goenv.TinyGo
	logger *slog.Logger
}

// New constructs a Resolver. goBinary may be empty (uses "go" from PATH).
func New(goBinary string, logger *slog.Logger) *Resolver {
	if logger == nil {
		logger = slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	return &Resolver{goBinary: goBinary, logger: logger}
}

// WithTarget returns a copy of the resolver whose children resolve for the
// declared target. It is a copy rather than a setter because one resolver serves
// one operation, and an operation whose target changed halfway would produce a
// module set no single platform ever had.
func (r *Resolver) WithTarget(t goenv.Target) *Resolver {
	out := *r
	out.target = t
	return &out
}

// WithTinyGo returns a copy of the resolver whose children resolve under the
// declared TinyGo frame: its environment on every child, its tags on the lists.
func (r *Resolver) WithTinyGo(f goenv.TinyGo) *Resolver {
	out := *r
	out.tinygo = f
	return &out
}

func (r *Resolver) goBin() string {
	if r.goBinary == "" {
		return "go"
	}
	return r.goBinary
}

// Resolve runs `go list -m -mod=readonly -json all` and `go mod graph` in
// projectDir and parses both into a BuildList. -mod=readonly guarantees go.mod is
// never mutated. The project environment (GOFLAGS/GOPROXY) is inherited from the
// caller's process. A non-nil error means the toolchain was unavailable or exited
// non-zero (missing binary, incomplete go.sum, restricted network); the caller is
// expected to fall back to the internal resolver and surface the uncertainty.
func (r *Resolver) Resolve(ctx context.Context, projectDir string) (walkports.BuildList, error) {
	listOut, err := r.run(ctx, projectDir, "list", "-m", "-mod=readonly", "-json", "all")
	if err != nil {
		return walkports.BuildList{}, err
	}
	graphOut, err := r.run(ctx, projectDir, "mod", "graph")
	if err != nil {
		return walkports.BuildList{}, err
	}

	modules, err := parseModules(listOut)
	if err != nil {
		return walkports.BuildList{}, err
	}
	edges, err := parseGraph(graphOut)
	if err != nil {
		return walkports.BuildList{}, err
	}

	// Capture the build environment (platform + toolchain version). It pins the
	// synthetic stdlib node and records the platform the module set is valid for.
	// It is a property of the build environment, not the module set, so a probe
	// failure degrades to empty values (no stdlib node, no platform) rather than
	// failing the walk — the module set is still authoritative without it.
	env := r.probeEnv(ctx, projectDir)
	goVersion, goos, goarch := env.goVersion, env.goos, env.goarch
	if interrupt.Stopped(ctx) {
		// A probe the cancellation cut short measured nothing; a build list
		// without its environment would read as one that has none.
		return walkports.BuildList{}, fmt.Errorf("probing the build environment: %w", ctx.Err())
	}

	bl := walkports.BuildList{
		Modules:       modules,
		Edges:         edges,
		WorkDir:       workDir(env.gowork),
		GoVersion:     goVersion,
		GOOS:          goos,
		GOARCH:        goarch,
		GOARM:         r.tinygo.GOARM(),
		TinyGoTarget:  r.tinygo.Target(),
		TinyGoVersion: r.tinygo.Version(),
		TinyGoTags:    r.tinygo.Tags(),
	}
	// Under TinyGo the standard library is part TinyGo's, part Go's, and which is
	// which decides how its advisories read. A listing that fails fails the build
	// list rather than yielding a walk that silently holds no split.
	if r.tinygo.Declared() {
		facts, goPkgs, aerr := r.attributeTinyGo(ctx, projectDir)
		if aerr != nil {
			return walkports.BuildList{}, aerr
		}
		bl.TinyGo, bl.GoPackages = facts, goPkgs
	}
	return bl, nil
}

// BuildEnvironment returns the toolchain version and target platform a Resolve
// of projectDir would record on the graph it produces. It is the same single
// `go env` probe Resolve uses, in the same directory, so a caller selecting a
// stored walk by build environment asks the question in exactly the terms the
// walk answered it in — including any go.mod toolchain directive, any
// GOTOOLCHAIN switch and any GOOS/GOARCH override in the environment.
//
// The toolchain is returned beside the platform rather than probed separately
// because both come out of one subprocess, and because a caller that pins one
// and not the other is answering about a build nobody performed.
//
// A probe failure returns empty strings. The caller decides what to do with
// that; this type will not invent a build environment it did not measure.
func (r *Resolver) BuildEnvironment(ctx context.Context, projectDir string) (goVersion, goos, goarch string) {
	env := r.probeEnv(ctx, projectDir)
	return env.goVersion, env.goos, env.goarch
}

// Workspace returns the directory of the go.work file in force for dir, or ""
// when dir resolves outside a workspace. A probe failure is an error, since a
// caller deciding how to resolve cannot read it as "no workspace".
func (r *Resolver) Workspace(ctx context.Context, dir string) (string, error) {
	out, err := r.run(ctx, dir, "env", "GOWORK")
	if err != nil {
		return "", err
	}
	return workDir(strings.TrimSpace(string(out))), nil
}

// workDir is the directory of a GOWORK value; empty and "off" name none.
func workDir(gowork string) string {
	if gowork == "" || gowork == "off" {
		return ""
	}
	return filepath.Dir(gowork)
}

// probedEnv is what one `go env` probe of a project directory reports.
type probedEnv struct {
	goVersion, goos, goarch, gowork string
}

// probeEnv returns the effective toolchain version, target platform and go.work
// file for projectDir via a single `go env GOVERSION GOOS GOARCH GOWORK`. `go
// env` prints one value per line in argument order, honouring any GOTOOLCHAIN
// switch and GOOS/GOARCH overrides the environment sets. A probe failure or
// short output returns empty strings so the caller omits the stdlib node and
// platform rather than treating it as fatal.
func (r *Resolver) probeEnv(ctx context.Context, projectDir string) probedEnv {
	out, err := r.run(ctx, projectDir, "env", "GOVERSION", "GOOS", "GOARCH", "GOWORK")
	if interrupt.Cancelled(ctx, err) {
		return probedEnv{}
	}
	if err != nil {
		r.logger.WarnContext(ctx, "walk.build_list.env_probe_failed",
			slog.String("project_dir", projectDir),
			slog.String("error", err.Error()),
		)
		return probedEnv{}
	}
	lines := strings.Split(strings.TrimRight(string(out), "\n"), "\n")
	get := func(i int) string {
		if i < len(lines) {
			return strings.TrimSpace(lines[i])
		}
		return ""
	}
	return probedEnv{goVersion: get(0), goos: get(1), goarch: get(2), gowork: get(3)}
}

// run executes the configured go binary with args in dir and returns stdout.
func (r *Resolver) run(ctx context.Context, dir string, args ...string) ([]byte, error) {
	if len(args) > 0 && args[0] == "list" {
		args = append(append([]string{"list"}, r.tinygo.ListArgs()...), args[1:]...)
	}
	cmd := childproc.CommandContext(ctx, r.goBin(), args...) // #nosec G204 -- binary path is either "go" (hardcoded) or caller-supplied and trusted
	cmd.Dir = dir
	// The platform is stated rather than inherited. Every child of a build-list
	// resolution — the module list, the requirement graph and the environment
	// probe — resolves for the same pair, and it is the pair the invocation
	// declared or, failing that, the host this process measured.
	cmd.Env = r.tinygo.Apply(r.target.Apply(os.Environ()))
	out, err := cmd.Output()
	if err != nil {
		if exitErr, ok := errors.AsType[*exec.ExitError](err); ok {
			return nil, fmt.Errorf("go %s: %w\n%s", strings.Join(args, " "), err, exitErr.Stderr)
		}
		return nil, fmt.Errorf("go %s: %w", strings.Join(args, " "), err)
	}
	return out, nil
}

// goListModule mirrors the fields kanonarion needs from `go list -m -json`.
type goListModule struct {
	Path     string
	Version  string
	Main     bool
	Indirect bool
	Dir      string
	Replace  *struct {
		Path    string
		Version string
	}
}

// parseModules decodes the concatenated JSON object stream emitted by
// `go list -m -json all` into BuildListModules.
func parseModules(data []byte) ([]walkports.BuildListModule, error) {
	dec := json.NewDecoder(bytes.NewReader(data))
	var mods []walkports.BuildListModule
	for {
		var m goListModule
		if err := dec.Decode(&m); errors.Is(err, io.EOF) {
			break
		} else if err != nil {
			return nil, fmt.Errorf("parsing go list -m output: %w", err)
		}
		mod := walkports.BuildListModule{
			Path:     m.Path,
			Version:  m.Version,
			Main:     m.Main,
			Indirect: m.Indirect,
			Dir:      m.Dir,
		}
		if m.Replace != nil {
			mod.Replace = &walkports.BuildListReplace{
				Path:    m.Replace.Path,
				Version: m.Replace.Version,
			}
		}
		mods = append(mods, mod)
	}
	return mods, nil
}

// parseGraph decodes the line-oriented output of `go mod graph` into edges. Each
// non-empty line is "from to" where each token is "path@version" (the main module
// appears without "@version"). Edges are returned in encounter order; the resolver
// normalises endpoints to selected versions and drops pseudo-nodes.
func parseGraph(data []byte) ([]walkports.BuildListEdge, error) {
	var edges []walkports.BuildListEdge
	for line := range strings.SplitSeq(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) != 2 {
			return nil, fmt.Errorf("parsing go mod graph: unexpected line %q", line)
		}
		edges = append(edges, walkports.BuildListEdge{From: fields[0], To: fields[1]})
	}
	return edges, nil
}

// Ensure Resolver implements ports.BuildListResolver at compile time.
var _ walkports.BuildListResolver = (*Resolver)(nil)
