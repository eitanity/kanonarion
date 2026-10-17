package tinycgo

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/eitanity/kanonarion/internal/adapters/childproc"
)

// ErrNoCompiler is the refusal for a cgo file that references a C name on a
// host with no C compiler to read its preamble.
var ErrNoCompiler = errors.New("no C compiler found on PATH (looked for clang, then clang-<N>)")

// FindCompiler is the C compiler the declarations are read with: clang on
// path, else the highest-numbered clang-N on it. Distributions install only the
// versioned name, so the second branch is the common one off CI.
func FindCompiler(path string) (string, error) {
	dirs := filepath.SplitList(path)
	for _, dir := range dirs {
		if p := filepath.Join(dir, "clang"); isExecutable(p) {
			return p, nil
		}
	}
	best, bestN := "", -1
	for _, dir := range dirs {
		entries, err := os.ReadDir(dir)
		if err != nil {
			continue
		}
		for _, e := range entries {
			n, ok := versionedClang(e.Name())
			if !ok || n <= bestN {
				continue
			}
			if p := filepath.Join(dir, e.Name()); isExecutable(p) {
				best, bestN = p, n
			}
		}
	}
	if best == "" {
		return "", ErrNoCompiler
	}
	return best, nil
}

// versionedClang reads N from "clang-N", N a plain decimal.
func versionedClang(name string) (int, bool) {
	rest, ok := strings.CutPrefix(name, "clang-")
	if !ok || rest == "" || strings.Trim(rest, "0123456789") != "" {
		return 0, false
	}
	n, err := strconv.Atoi(rest)
	return n, err == nil
}

func isExecutable(p string) bool {
	info, err := os.Stat(p)
	return err == nil && !info.IsDir() && info.Mode().Perm()&0o111 != 0
}

// compiler runs one clang binary with the target's flags.
type compiler struct {
	path  string
	env   []string
	flags []string
}

// run compiles src (a file path) with args after the target flags, returning
// stdout, or clang's first diagnostic line when it refuses.
func (c compiler) run(ctx context.Context, args ...string) ([]byte, error) {
	all := append(append([]string(nil), c.flags...), args...)
	cmd := childproc.CommandContext(ctx, c.path, all...) // #nosec G204 -- the discovered clang, flags from the target definition and a preamble file this process wrote
	cmd.Env = c.env
	cmd.WaitDelay = childproc.WaitDelay
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	if err := cmd.Run(); err != nil {
		if ctx.Err() != nil {
			return nil, fmt.Errorf("running %s: %w", c.path, ctx.Err())
		}
		if line := firstDiagnostic(stderr.String()); line != "" {
			return nil, errors.New(line)
		}
		return nil, fmt.Errorf("running %s: %w", c.path, err)
	}
	return stdout.Bytes(), nil
}

// version is the first line clang prints for --version.
func (c compiler) version(ctx context.Context) string {
	out, err := c.runBare(ctx, "--version")
	if err != nil {
		return "version unknown: " + err.Error()
	}
	first, _, _ := strings.Cut(strings.TrimSpace(string(out)), "\n")
	return first
}

func (c compiler) runBare(ctx context.Context, args ...string) ([]byte, error) {
	cmd := childproc.CommandContext(ctx, c.path, args...) // #nosec G204 -- the discovered clang with a literal flag
	cmd.Env = c.env
	cmd.WaitDelay = childproc.WaitDelay
	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("running %s: %w", c.path, err)
	}
	return out, nil
}

// firstDiagnostic is the first error line clang wrote, else its first line.
func firstDiagnostic(stderr string) string {
	lines := strings.Split(strings.TrimSpace(stderr), "\n")
	for _, l := range lines {
		if strings.Contains(l, "error:") {
			return strings.TrimSpace(l)
		}
	}
	return strings.TrimSpace(lines[0])
}

// envPath is the last PATH in env, the one a child would see.
func envPath(env []string) string {
	path := os.Getenv("PATH")
	for _, kv := range env {
		if v, ok := strings.CutPrefix(kv, "PATH="); ok {
			path = v
		}
	}
	return path
}
