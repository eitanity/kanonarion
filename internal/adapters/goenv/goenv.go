// Package goenv resolves Go environment values the way the go command resolves
// them, and states the one question every network egress in this tool has to
// ask before it opens a socket: does this environment forbid the network?
//
// It exists because that question was previously answered five different ways —
// four of them by not asking at all, and the fifth by reading os.Getenv alone.
// os.Getenv is not how Go resolves GOPROXY: `go env -w GOPROXY=off` writes to
// Go's own env file and sets nothing in the process environment, so an operator
// who declared an air gap the way the go command documents it was invisible to
// a reader that only looked at the variable. One resolver, consulted by every
// egress, is the shape that makes the declaration mean the same thing wherever
// it is read.
//
// Resolution order is the go command's: the process environment first, and the
// env file only when the variable is unset or empty. The env file is
// $GOENV when set (GOENV=off disables it entirely), otherwise
// os.UserConfigDir()/go/env.
//
// It also holds the environment an analysis child is given and the table every
// such environment is checked against — the same scattering, one layer out.
package goenv

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

// ErrNetworkForbidden is the fact every egress refusal in this repository is
// built on: the environment declares no network module traffic.
//
// It carries no remedy of its own. A refusal is only actionable when it names
// the way to proceed *for the path that refused*, and those differ — the module
// proxy points at $GOMODCACHE and the store, the advisory snapshot points at
// the snapshot the store already holds, VCS cross-verification points at
// --skip-vcs-verify. So each adapter wraps this with its own sentence, and a
// caller that only needs to know "the operator forbade this" tests for it with
// errors.Is.
var ErrNetworkForbidden = errors.New("GOPROXY=off")

// Value returns the value of a Go environment variable, resolved as the go
// command resolves it.
//
// The process environment wins when it holds a non-empty value; otherwise the
// env file is consulted. An empty-but-set variable falls through to the file,
// which is what the go command does and is not the same as unset: it means
// "this shell says nothing", not "this shell says empty".
func Value(key string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fileValues()[key]
}

// Proxy returns the resolved GOPROXY value, empty when neither the environment
// nor the env file names one.
func Proxy() string { return Value("GOPROXY") }

// NetworkForbidden reports whether the resolved GOPROXY declares that this
// environment does no network module traffic.
//
// Only `off` forbids the network. `direct` does not: it selects VCS-origin
// fetching, which is a different route to the network rather than the absence
// of one, and an adapter that cannot serve it refuses for that reason instead.
func NetworkForbidden() bool { return FirstProxyEntry(Proxy()) == "off" }

// FirstProxyEntry returns the first usable entry of a GOPROXY-shaped list, or
// "" when the list names none.
//
// The grammar is Go's: entries separated by "," or "|", tried in order, empty
// entries skipped. Only the first entry is ever returned because it is the only
// one whose meaning is unconditional — everything after it is reached only when
// the entry before it failed, and an `off` reached first terminates the chain
// exactly as it does in the go command.
func FirstProxyEntry(list string) string {
	for entry := range strings.FieldsFuncSeq(list, func(r rune) bool { return r == ',' || r == '|' }) {
		if entry = strings.TrimSpace(entry); entry != "" {
			return entry
		}
	}
	return ""
}

// envFilePath returns the path of Go's env file, or "" when there is none to
// read (GOENV=off, or no user config directory).
func envFilePath() string {
	switch file := os.Getenv("GOENV"); file {
	case "":
	case "off":
		return ""
	default:
		return file
	}
	dir, err := os.UserConfigDir()
	if err != nil || dir == "" {
		return ""
	}
	return filepath.Join(dir, "go", "env")
}

var (
	fileMu     sync.Mutex
	cachedPath string
	cachedVals map[string]string
	cached     bool
)

// fileValues returns the parsed env file, reading it at most once per path.
//
// The cache is keyed on the resolved path rather than being a plain sync.Once
// so that a process which changes $GOENV — a test pointing at a fixture, an
// embedding that switches configuration — reads the file it now names rather
// than replaying the first one. Within one path the file is read once: this is
// consulted on every egress decision, and a per-decision stat/read would be a
// syscall added to paths that make no I/O at all.
func fileValues() map[string]string {
	path := envFilePath()
	fileMu.Lock()
	defer fileMu.Unlock()
	if cached && cachedPath == path {
		return cachedVals
	}
	cachedPath, cachedVals, cached = path, parseEnvFile(path), true
	return cachedVals
}

// parseEnvFile reads and parses Go's env file. An absent or unreadable file is
// an empty set, not an error: the file is optional, and a process that cannot
// read it is in exactly the position of one for which it does not exist.
func parseEnvFile(path string) map[string]string {
	values := map[string]string{}
	if path == "" {
		return values
	}
	data, err := os.ReadFile(path) // #nosec G304 -- path is $GOENV or the OS user-config directory, both operator-owned
	if err != nil {
		return values
	}
	for line := range strings.SplitSeq(strings.TrimPrefix(string(data), "\ufeff"), "\n") {
		line = strings.TrimSuffix(line, "\r")
		key, value, ok := strings.Cut(line, "=")
		if !ok || key == "" {
			continue
		}
		values[key] = value
	}
	return values
}
