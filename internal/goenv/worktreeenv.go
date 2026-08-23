package goenv

import (
	"os"
	"path/filepath"
	"strings"
)

// Worktree is the environment for a Go child analysing the working tree at dir:
// the loader, the import lister and the symbol probe all resolve the same way.
//
// A working tree's own go.work is its real build configuration rather than an
// artefact of packaging, so it is honoured.
//
// -mod=readonly on both branches, for two reasons that agree only by accident:
// workspace mode refuses -mod=mod, and this tree is the developer's rather than
// a copy we own — under -mod=mod a command asked to measure the tree writes the
// go.sum entries it finds missing instead of reporting them, from the module
// cache and without a download, so GOPROXY=off does not prevent it.
func Worktree(base []string, dir string) []string {
	env := make([]string, len(base), len(base)+5)
	copy(env, base)
	env = append(env, "GOPROXY=off", "GOSUMDB=off", "GOTOOLCHAIN=local")
	if !workspaceInScope(base, dir) {
		env = append(env, "GOWORK=off")
	}
	return append(env, "GOFLAGS=-mod=readonly")
}

// workspaceInScope answers the question the go command asks: GOWORK decides when
// it is set, and otherwise a go.work is looked for from dir upwards.
func workspaceInScope(base []string, dir string) bool {
	switch v, ok := lastValue(base, "GOWORK"); {
	case ok && v == "off":
		return false
	case ok && v != "":
		_, err := os.Stat(v)
		return err == nil
	}
	d, err := filepath.Abs(dir)
	if err != nil {
		return false
	}
	for {
		if _, err := os.Stat(filepath.Join(d, "go.work")); err == nil {
			return true
		}
		parent := filepath.Dir(d)
		if parent == d {
			return false
		}
		d = parent
	}
}

// lastValue returns the value a child process would see for key: the go command
// and exec.Cmd both resolve a repeated key to its last entry. This is a
// different question from Value, which resolves what THIS process sees.
func lastValue(env []string, key string) (string, bool) {
	value, found := "", false
	for _, kv := range env {
		if k, v, ok := strings.Cut(kv, "="); ok && k == key {
			value, found = v, true
		}
	}
	return value, found
}
