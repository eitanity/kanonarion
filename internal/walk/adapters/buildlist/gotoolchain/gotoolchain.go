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
	"os/exec"
	"strings"

	walkports "github.com/eitanity/kanonarion/internal/walk/ports"
)

// Resolver runs the Go toolchain to compute a project's build list.
type Resolver struct {
	goBinary string // empty → resolved via PATH as "go"
	logger   *slog.Logger
}

// New constructs a Resolver. goBinary may be empty (uses "go" from PATH).
func New(goBinary string, logger *slog.Logger) *Resolver {
	if logger == nil {
		logger = slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	return &Resolver{goBinary: goBinary, logger: logger}
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
	goVersion, goos, goarch := r.buildEnv(ctx, projectDir)

	return walkports.BuildList{
		Modules:   modules,
		Edges:     edges,
		GoVersion: goVersion,
		GOOS:      goos,
		GOARCH:    goarch,
	}, nil
}

// buildEnv returns the effective toolchain version and target platform for
// projectDir via a single `go env GOVERSION GOOS GOARCH`. `go env` prints one
// value per line in argument order, honouring any GOTOOLCHAIN switch and
// GOOS/GOARCH overrides the environment sets. A probe failure or short output
// returns empty strings so the caller omits the stdlib node and platform rather
// than treating it as fatal.
func (r *Resolver) buildEnv(ctx context.Context, projectDir string) (goVersion, goos, goarch string) {
	out, err := r.run(ctx, projectDir, "env", "GOVERSION", "GOOS", "GOARCH")
	if err != nil {
		r.logger.WarnContext(ctx, "walk.build_list.env_probe_failed",
			slog.String("project_dir", projectDir),
			slog.String("error", err.Error()),
		)
		return "", "", ""
	}
	lines := strings.Split(strings.TrimRight(string(out), "\n"), "\n")
	get := func(i int) string {
		if i < len(lines) {
			return strings.TrimSpace(lines[i])
		}
		return ""
	}
	return get(0), get(1), get(2)
}

// run executes the configured go binary with args in dir and returns stdout.
func (r *Resolver) run(ctx context.Context, dir string, args ...string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, r.goBin(), args...) // #nosec G204 -- binary path is either "go" (hardcoded) or caller-supplied and trusted
	cmd.Dir = dir
	out, err := cmd.Output()
	if err != nil {
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
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
