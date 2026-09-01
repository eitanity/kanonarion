// Package localtest fabricates the one host condition the local analysis
// adapters cannot otherwise be tested against: an installed Go toolchain older
// than the tree being analysed, with a newer one already unpacked somewhere the
// analysis is allowed to reach.
//
// Both adapters in this context spawn Go children, and the guarantee they have
// to keep is about the environment those children are handed rather than about
// the answer that comes back. So the fake go records every environment it is
// given, and the assertions read those.
package localtest

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// Host is one fabricated analysis host: a dependency-free module tree, a fake go
// that refuses the way the real one does, and — when the caller asks for it — a
// toolchain unpacked where the analysis searches.
type Host struct {
	// Tree is a module the analysis can be pointed at.
	Tree string
	// GoBinary is the fake go, to be given to an adapter's constructor the way
	// --go-binary gives it a real one.
	GoBinary string

	envDir string
	relent string
	realGo string
	OnDisk bool
}

// NewHost stands up the condition. onDisk decides whether a toolchain new enough
// to serve the tree exists on this host: with one the analysis is expected to
// find it, without one it is expected to refuse and say who pinned the
// toolchain.
//
// The module cache is redirected and the toolchain is fabricated inside it, so
// what is on disk is entirely this test's statement. The build cache is left
// alone deliberately — the fake go delegates to the real one once the escalation
// has happened, and a redirected cache would make it rebuild the standard
// library to prove a point about an environment variable.
func NewHost(t *testing.T, onDisk bool) *Host {
	t.Helper()
	realGo, err := exec.LookPath("go")
	if err != nil {
		t.Skipf("no go command on PATH: %v", err)
	}

	modcache := t.TempDir()
	t.Setenv("GOMODCACHE", modcache)
	t.Setenv("GOENV", "off")
	if onDisk {
		root := filepath.Join(modcache, "golang.org",
			"toolchain@v0.0.1-go1.99.0."+runtime.GOOS+"-"+runtime.GOARCH)
		write(t, filepath.Join(root, "VERSION"), "go1.99.0\ntime 2026-08-11T00:40:52Z\n")
		writeExec(t, filepath.Join(root, "bin", "go"), "#!/bin/sh\nexit 0\n")
	}

	h := &Host{
		Tree:   t.TempDir(),
		envDir: t.TempDir(),
		relent: filepath.Join(t.TempDir(), "never-refuse"),
		realGo: realGo,
		OnDisk: onDisk,
	}
	write(t, filepath.Join(h.Tree, "go.mod"), "module example.com/probe\n\ngo 1.21\n")
	write(t, filepath.Join(h.Tree, "main.go"), "package main\n\nfunc main() {}\n")

	t.Setenv("KANONARION_CHILD_ENV_DIR", h.envDir)
	h.GoBinary = filepath.Join(t.TempDir(), "go")
	h.Shim(t, h.GoBinary,
		"if [ -f "+h.relent+" ] || [ \"$GOTOOLCHAIN\" = path ]; then\n"+
			"  exec env GOTOOLCHAIN=local "+realGo+" \"$@\"\n"+
			"fi\n"+
			"echo 'go: go.mod requires go >= 1.99.0 (running go 1.26.5; GOTOOLCHAIN=local)' >&2\n"+
			"exit 1\n")
	return h
}

// Shim writes an executable at path that records the environment it is handed
// and then runs body, which is shell source.
//
// It is exported because an analysis spawns Go children that are not the go
// command — a scan runs govulncheck, which loads packages itself and meets the
// same refusal — and the assertions below read what every child was given. One
// recording prologue rather than one per fabricated child is what keeps
// "GOTOOLCHAIN was never negotiated" a statement about the whole operation.
//
// The shim resolves go1.99.0 through its own PATH and records the answer, so a
// child claiming to have switched toolchains can be held to having one to switch
// to: the go command finds a toolchain on PATH by that exact file name.
func (h *Host) Shim(t *testing.T, path, body string) {
	t.Helper()
	writeExec(t, path, "#!/bin/sh\n"+
		"f=$(mktemp \"$KANONARION_CHILD_ENV_DIR/child.XXXXXX\")\n"+
		"env > \"$f\"\n"+
		"echo \"KANONARION_SHIM_RESOLVED=$(command -v go1.99.0 || true)\" >> \"$f\"\n"+
		body)
}

// NeverRefuse makes the fake go behave like a toolchain that satisfies the tree,
// so a test can assert that nothing escalates when nothing needs to.
func (h *Host) NeverRefuse(t *testing.T) {
	t.Helper()
	write(t, h.relent, "")
}

// Children is every environment the analysis handed a Go child, oldest first.
func (h *Host) Children(t *testing.T) []map[string]string {
	t.Helper()
	entries, err := os.ReadDir(h.envDir)
	if err != nil {
		t.Fatalf("reading recorded environments: %v", err)
	}
	out := make([]map[string]string, 0, len(entries))
	for _, e := range entries {
		raw, rerr := os.ReadFile(filepath.Join(h.envDir, e.Name())) // #nosec G304 -- written by this test into its own t.TempDir()
		if rerr != nil {
			t.Fatalf("reading %s: %v", e.Name(), rerr)
		}
		env := map[string]string{}
		for _, line := range strings.Split(string(raw), "\n") {
			if k, v, ok := strings.Cut(line, "="); ok {
				env[k] = v
			}
		}
		out = append(out, env)
	}
	if len(out) == 0 {
		t.Fatal("the analysis never ran a Go child, so nothing about its environment was measured")
	}
	return out
}

// AssertEscalated requires that the analysis tried the installed toolchain
// first, then ran under the one on this host — and that the offline posture the
// pin exists to serve survived the change.
func (h *Host) AssertEscalated(t *testing.T) {
	t.Helper()
	children := h.Children(t)
	pinned, switched := 0, 0
	for _, env := range children {
		switch env["GOTOOLCHAIN"] {
		case "local":
			pinned++
		case "path":
			switched++
			if env["KANONARION_SHIM_RESOLVED"] == "" {
				t.Errorf("a retried child could not find go1.99.0 on its own PATH=%q; the go command looks for "+
					"a toolchain by that name and nothing else", env["PATH"])
			}
		default:
			t.Errorf("a child was given GOTOOLCHAIN=%q; no analysis child may negotiate its own toolchain",
				env["GOTOOLCHAIN"])
		}
	}
	if pinned == 0 {
		t.Error("no child ran under the installed toolchain; the cheapest path must still be tried first")
	}
	if switched == 0 {
		t.Errorf("the analysis never ran under the toolchain on this host: %d child environment(s) recorded",
			len(children))
	}
	h.assertOffline(t, children)
}

// AssertNeverEscalated requires that every child ran under the installed
// toolchain: nothing asked for another one, or nothing on this host could serve.
func (h *Host) AssertNeverEscalated(t *testing.T) {
	t.Helper()
	children := h.Children(t)
	for _, env := range children {
		if env["GOTOOLCHAIN"] != "local" {
			t.Errorf("a child was given GOTOOLCHAIN=%q, want local", env["GOTOOLCHAIN"])
		}
	}
	h.assertOffline(t, children)
}

// assertOffline is the guarantee the whole mechanism lives inside: pinning the
// toolchain exists so no analysis child can reach the network, and an escalation
// that opened it would have traded one defect for a worse one.
func (h *Host) assertOffline(t *testing.T, children []map[string]string) {
	t.Helper()
	for _, env := range children {
		if env["GOPROXY"] != "off" || env["GOSUMDB"] != "off" {
			t.Errorf("a child was given GOPROXY=%q GOSUMDB=%q; the toolchain decision must not open the network",
				env["GOPROXY"], env["GOSUMDB"])
		}
	}
}

func write(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("writing %s: %v", path, err)
	}
}

func writeExec(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	if err := os.WriteFile(path, []byte(content), 0o700); err != nil { // #nosec G306 -- a binary these tests exec must be executable
		t.Fatalf("writing %s: %v", path, err)
	}
}
