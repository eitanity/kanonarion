package tinygo

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"strings"

	"code.eitanity.com/kanonarion/internal/adapters/childproc"
	"code.eitanity.com/kanonarion/internal/adapters/goenv"
)

// Toolchain is the Go toolchain a TinyGo frame for the tree at dir merges from:
// the one goenv.Toolchains settles on for it, the installed go when it satisfies
// the tree's go line and otherwise one already unpacked here, never a download.
// goBinary may be empty for "go" on PATH; an empty dir is a tree with no go.mod.
func Toolchain(ctx context.Context, goBinary, dir string) (goenv.OnDiskToolchain, error) {
	if goBinary == "" {
		goBinary = "go"
	}
	if dir == "" {
		tmp, err := os.MkdirTemp("", "kanonarion-toolchain-tree-*")
		if err != nil {
			return goenv.OnDiskToolchain{}, fmt.Errorf("creating a directory to ask the Go toolchain in: %w", err)
		}
		defer func() { _ = os.RemoveAll(tmp) }()
		dir = tmp
	}
	tcs := goenv.NewToolchains()
	defer func() { _ = tcs.Close() }()
	base := pinnedEnv()
	// `go list -m` refuses a go line the running toolchain does not satisfy; any
	// other failure is the tree's, and the child that meets it reports it.
	for {
		_, detail, err := runGo(ctx, goBinary, dir, tcs.Apply(base), "list", "-m")
		if err == nil {
			break
		}
		retry, refusal := tcs.Escalate(detail)
		if refusal != "" {
			return goenv.OnDiskToolchain{}, errors.New(refusal)
		}
		if !retry {
			break
		}
	}
	return nameToolchain(ctx, goBinary, dir, tcs.Apply(base))
}

// NamedToolchain is the toolchain name ("go1.27.3") a recorded walk resolved
// under: the installed go when it is that version, otherwise one already
// unpacked here, never a download. A host holding neither is refused by name.
func NamedToolchain(ctx context.Context, goBinary, name string) (goenv.OnDiskToolchain, error) {
	if goBinary == "" {
		goBinary = "go"
	}
	tmp, err := os.MkdirTemp("", "kanonarion-toolchain-tree-*")
	if err != nil {
		return goenv.OnDiskToolchain{}, fmt.Errorf("creating a directory to ask the Go toolchain in: %w", err)
	}
	defer func() { _ = os.RemoveAll(tmp) }()
	installed, err := nameToolchain(ctx, goBinary, tmp, pinnedEnv())
	if err != nil || installed.Name == name {
		return installed, err
	}
	if tc, ok := goenv.OnDiskToolchainNamed(name); ok {
		return tc, nil
	}
	return goenv.OnDiskToolchain{}, fmt.Errorf("the walk was resolved under %s, which is neither the installed Go (%s) nor unpacked "+
		"on this host in ~/sdk or the module cache, and kanonarion never downloads one: install it with "+
		"`go install golang.org/dl/%s@latest` and `%s download`, and re-run", name, installed.Name, name, name)
}

// pinnedEnv is this process's environment with go pinned and offline, so a
// question about a toolchain neither switches nor downloads one.
func pinnedEnv() []string { return append(os.Environ(), "GOTOOLCHAIN=local", "GOPROXY=off") }

// nameToolchain asks go in dir under env which toolchain it runs as.
func nameToolchain(ctx context.Context, goBinary, dir string, env []string) (goenv.OnDiskToolchain, error) {
	out, detail, err := runGo(ctx, goBinary, dir, env, "env", "GOVERSION", "GOROOT")
	if err != nil {
		return goenv.OnDiskToolchain{}, fmt.Errorf("naming the toolchain TinyGo merges from: %w: %s", err, strings.TrimSpace(detail))
	}
	name, root, _ := strings.Cut(strings.TrimSpace(string(out)), "\n")
	tc := goenv.OnDiskToolchain{Name: strings.TrimSpace(name), Root: strings.TrimSpace(root)}
	if tc.Name == "" || tc.Root == "" {
		return goenv.OnDiskToolchain{}, fmt.Errorf("go env GOVERSION GOROOT printed %q, which names no toolchain", strings.TrimSpace(string(out)))
	}
	return tc, nil
}

// runGo runs one go child in dir under env and returns its stdout and stderr.
func runGo(ctx context.Context, bin, dir string, env []string, args ...string) ([]byte, string, error) {
	cmd := childproc.CommandContext(ctx, bin, args...) // #nosec G204 -- bin is --go-binary or "go", args are literals
	cmd.Dir, cmd.Env = dir, env
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		return nil, stderr.String(), fmt.Errorf("go %s: %w", strings.Join(args, " "), err)
	}
	return out, "", nil
}
