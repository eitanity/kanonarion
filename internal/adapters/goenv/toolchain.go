package goenv

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
)

// OnDiskToolchain is a Go toolchain already unpacked on this host, named by its
// own VERSION file rather than by the directory holding it.
//
// The name is not cosmetic. It is what the go command looks for on PATH when it
// selects a toolchain, so a directory that has been renamed, or an SDK upgraded
// in place under an old name, must not be offered under the name it is filed
// as — that would hand the analysis a toolchain other than the one it asked for
// and the record would name a version that never ran.
type OnDiskToolchain struct {
	// Name is the toolchain in `go env GOVERSION` form: "go1.26.6".
	Name string
	// Root is its GOROOT. Root/bin/go is the command.
	Root string
}

// Toolchains is one operation's answer to the question "which Go must this
// operation's children run under".
//
// Every analysis child in this repository is pinned so it can never download a
// toolchain. That pin also refuses a toolchain sitting unpacked on the same
// disk, which leaves a module whose go directive exceeds the installed
// toolchain unanalysable however well equipped the host is. This type is the
// one place that decides what to do about it.
//
// It is failure-driven rather than predictive, because the go command is the
// only thing that knows what a load actually needed: the requirement can be
// raised by the module's own go line, by its toolchain line, or by a dependency
// several levels down the graph, and the go command's own sentence names the
// version in all three cases. Predicting it would mean reimplementing minimum
// version selection to guess an answer that arrives for free.
//
// It settles at most once per operation, and every later child of that
// operation runs under the result. An operation spawning six children must not
// pay six failed first attempts, and must not have two of its children
// disagreeing about which toolchain they measured.
//
// One value belongs to one operation and is not safe for concurrent use. That
// is how every caller uses it: the operation makes one, defers Close, and runs
// its children in sequence.
type Toolchains struct {
	shimDir  string
	selected string
	refusal  string
	settled  bool
}

// NewToolchains starts an operation running under the installed toolchain.
func NewToolchains() *Toolchains { return &Toolchains{} }

// Apply returns env as this operation's next child must see it.
//
// It takes the environment rather than holding one because every caller builds
// its child's environment from its own posture — the extracted-module load, the
// worktree load, the import lister, the symbol probe — and that posture is what
// must survive the escalation. Applying to each freshly built environment keeps
// the two decisions separate: the posture says what the child may do, and this
// says which Go does it.
func (t *Toolchains) Apply(env []string) []string {
	if t.shimDir == "" {
		return env
	}
	return WithOnDiskToolchain(env, t.shimDir)
}

// Escalate reads a child's failure and decides what the operation should do.
//
// retry is true when Env has changed and the same child is worth running again.
// refusal, when set, is the account the caller must report instead of the go
// command's own: this host cannot serve the version, and the go command's
// sentence cannot say who pinned the toolchain or how to obtain one.
//
// Exactly one of the two is ever set. A failure that is not the toolchain gap
// returns neither, and neither does a second call after an escalation was taken —
// the retry happens once and the operation then reports whatever it found.
//
// A REFUSAL, though, is repeated to every later child of the operation that meets
// the same wall. It is the operation's answer, not one child's: an operation
// spawns several children over ONE tree, so they all want the same Go, and the
// child that meets the gap second must not fall back to reporting the go
// command's own sentence — which names neither the pinner nor the remedy — just
// because another child asked first. Without this the account a reader is shown
// depends on which child happened to fail, and the scan surface shows it every
// time, since the child whose failure is recorded is never the first one run.
func (t *Toolchains) Escalate(detail string) (retry bool, refusal string) {
	if !IsToolchainTooOld(detail) {
		return false, ""
	}
	if t.settled {
		return false, t.refusal
	}
	required, running, ok := requiredGoVersion(detail)
	if !ok {
		return false, ""
	}
	t.settled = true
	found := OnDiskToolchainsAtLeast(required)
	if len(found) == 0 {
		t.refusal = unavailableDetail(required, running, detail)
		return false, t.refusal
	}
	dir, err := ToolchainShims(found)
	if err != nil {
		// The toolchain is here and the operation still cannot reach it. That is
		// this host's fault rather than the module's, exactly as the missing
		// toolchain is, and the report has to say which of the two it met.
		t.refusal = "kanonarion found " + found[0].Name + " on this host but could not stage it for the " +
			"analysis: " + err.Error() + ". The Go command reported: " + detail
		return false, t.refusal
	}
	t.shimDir, t.selected = dir, found[0].Name
	return true, ""
}

// Selected names the toolchain this operation escalated to, or "" when it is
// still running under the installed one. It is for the log line that says which
// toolchain measured what.
func (t *Toolchains) Selected() string { return t.selected }

// Close removes anything the escalation staged. It is safe to call when nothing
// was staged, which is the ordinary case.
func (t *Toolchains) Close() error {
	if t.shimDir == "" {
		return nil
	}
	dir := t.shimDir
	t.shimDir = ""
	if err := os.RemoveAll(dir); err != nil {
		return fmt.Errorf("removing toolchain directory %s: %w", dir, err)
	}
	return nil
}

// IsToolchainTooOld reports whether a Go child failed because the code it was
// pointed at asks for a newer Go than the one running: "<what> requires go >= X
// (running go Y)".
//
// Both halves are required so a module quoting the phrase in its own prose
// cannot match. No probe can see this class structurally — the go command runs,
// reads the directive and refuses — so the sentence is the only place the
// distinction exists.
func IsToolchainTooOld(detail string) bool {
	return strings.Contains(detail, " requires go >= ") && strings.Contains(detail, "(running go ")
}

// tooNewRequirement pulls the two versions out of that sentence. The trailing
// clause is optional and varies, so the running version is read up to whichever
// of ';' or ')' ends it.
var tooNewRequirement = regexp.MustCompile(`requires go >= ([0-9][^ ]*) \(running go ([^;)]+)[;)]`)

// requiredGoVersion reports the highest Go version a failure says is needed and
// the toolchain that was running, both as the go command spelled them.
//
// The highest rather than the first: one load can refuse for several modules at
// once, and a toolchain satisfying the largest requirement satisfies all of
// them.
func requiredGoVersion(detail string) (required, running string, ok bool) {
	for _, m := range tooNewRequirement.FindAllStringSubmatch(detail, -1) {
		if required == "" || HigherGoVersion(m[1], required) {
			required, running, ok = m[1], strings.TrimSpace(m[2]), true
		}
	}
	return required, running, ok
}

// unavailableDetail is the account of code this host cannot analyse: kanonarion
// pinned the toolchain, and nothing new enough is unpacked anywhere the
// operation can reach offline.
//
// It names kanonarion as the pinner because the go command's own sentence
// cannot: a reader who sees GOTOOLCHAIN in an error has no way to tell their own
// shell from this tool's posture, and goes looking in the wrong place. It names
// the version and the way to obtain it for the same reason — a refusal is only
// actionable when it says what would make it stop.
func unavailableDetail(required, running, reported string) string {
	name := ToolchainName(required)
	return "kanonarion pins the toolchain of every analysis child so it can never download one, and this code " +
		"needs go >= " + required + " while the analysis is running go" + running + ". No toolchain that new is " +
		"unpacked on this host, in either place one can be used from offline: ~/sdk or the module cache. " +
		"Install it with `go install golang.org/dl/" + name + "@latest` then `" + name + " download`, which " +
		"unpacks into ~/sdk, and re-run. The Go command reported: " + reported
}

// OnDiskToolchainsAtLeast returns every toolchain unpacked on this host whose
// version is at least min, which is a Go version without the "go" prefix as the
// go command writes it in "requires go >= 1.26.6".
//
// Two places are searched, in this order:
//
//  1. $HOME/sdk/go<version> — where `golang.org/dl/go<version> download` puts an
//     SDK someone installed on purpose.
//  2. $GOMODCACHE/golang.org/toolchain@v0.0.1-go<version>.<goos>-<goarch> — where
//     the go command's own toolchain switch unpacks one.
//
// Deliberate installation is searched first because the module cache is a cache:
// `go clean -modcache` empties it, and a toolchain there is a by-product of some
// earlier switch rather than a toolchain anyone chose to keep. When both hold the
// same version the choice does not matter, and when they differ the one a person
// installed is the one they meant.
//
// PATH is deliberately NOT searched here. The go command searches it itself
// whenever it is allowed to switch, so a `go1.26.6` shim already on the child's
// PATH is considered without this function knowing about it; what this adds is
// the two locations the go command reaches only by downloading.
//
// The whole search is filesystem-only: no subprocess, no network, and no
// resolution that could fail differently on a second run.
func OnDiskToolchainsAtLeast(min string) []OnDiskToolchain {
	want, ok := goVersionFields(min)
	if !ok {
		return nil
	}
	var out []OnDiskToolchain
	seen := map[string]bool{}
	for _, root := range candidateToolchainRoots() {
		tc, valid := readToolchain(root)
		if !valid || seen[tc.Name] {
			continue
		}
		if have, ok := goVersionFields(tc.Name); !ok || compareGoVersionFields(have, want) < 0 {
			continue
		}
		seen[tc.Name] = true
		out = append(out, tc)
	}
	return out
}

// candidateToolchainRoots lists the directories that might be a GOROOT, in the
// search order OnDiskToolchainsAtLeast documents. Nothing here is validated:
// readToolchain decides what a candidate actually is.
func candidateToolchainRoots() []string {
	var roots []string
	if home, err := os.UserHomeDir(); err == nil && home != "" {
		roots = append(roots, globDirs(filepath.Join(home, "sdk"), "go1.")...)
	}
	// The module cache spells the platform into the directory name, and a cache
	// can hold a toolchain for another one — a cross-compiled `go install` pulls
	// it in. Only this host's own can be executed here.
	suffix := "." + runtime.GOOS + "-" + runtime.GOARCH
	for _, dir := range globDirs(filepath.Join(modCacheDir(), "golang.org"), "toolchain@") {
		if strings.HasSuffix(dir, suffix) {
			roots = append(roots, dir)
		}
	}
	return roots
}

// globDirs returns the subdirectories of parent whose name starts with prefix,
// in the order the filesystem lists them, which os.ReadDir sorts by name.
func globDirs(parent, prefix string) []string {
	entries, err := os.ReadDir(parent)
	if err != nil {
		return nil
	}
	var out []string
	for _, e := range entries {
		if e.IsDir() && strings.HasPrefix(e.Name(), prefix) {
			out = append(out, filepath.Join(parent, e.Name()))
		}
	}
	return out
}

// modCacheDir resolves GOMODCACHE the way the go command does: the variable when
// it is set, otherwise GOPATH/pkg/mod, otherwise the default GOPATH under the
// user's home.
func modCacheDir() string {
	if v := Value("GOMODCACHE"); v != "" {
		return v
	}
	gopath := Value("GOPATH")
	if gopath == "" {
		home, err := os.UserHomeDir()
		if err != nil || home == "" {
			return ""
		}
		gopath = filepath.Join(home, "go")
	}
	// A list is legal in GOPATH and the module cache lives under its first entry.
	if i := strings.IndexByte(gopath, os.PathListSeparator); i >= 0 {
		gopath = gopath[:i]
	}
	return filepath.Join(gopath, "pkg", "mod")
}

// readToolchain reports what the directory at root actually is: a Go toolchain
// naming itself in its VERSION file and carrying an executable bin/go, or not a
// toolchain at all.
//
// The version comes from the VERSION file and never from the directory name, for
// the reason gotoolchain.FromGOROOT states about GOROOTs generally: a path says
// where a toolchain came from, and only the toolchain says which one it is.
func readToolchain(root string) (OnDiskToolchain, bool) {
	data, err := os.ReadFile(filepath.Join(root, "VERSION")) // #nosec G304 -- root is an entry of a directory this package enumerated
	if err != nil {
		return OnDiskToolchain{}, false
	}
	name, _, _ := strings.Cut(string(data), "\n")
	name = strings.TrimSpace(name)
	if !strings.HasPrefix(name, "go1.") {
		return OnDiskToolchain{}, false
	}
	info, err := os.Stat(filepath.Join(root, "bin", "go"))
	if err != nil || info.IsDir() || info.Mode().Perm()&0o111 == 0 {
		return OnDiskToolchain{}, false
	}
	return OnDiskToolchain{Name: name, Root: root}, true
}

// ToolchainShims stages tcs in a fresh directory, one entry per toolchain named
// the way the go command looks for it on PATH.
//
// A toolchain's own command is called `go`, and the go command searching PATH
// for a version reads the version off the FILE NAME — so an SDK is invisible to
// it until something links it under the versioned name. This is the same
// mechanism the --go-binary flag already uses to put a chosen toolchain in front
// of a child, one directory further out.
//
// The caller owns the directory and must remove it.
func ToolchainShims(tcs []OnDiskToolchain) (string, error) {
	dir, err := os.MkdirTemp("", "kanonarion-toolchain-*")
	if err != nil {
		return "", fmt.Errorf("creating toolchain directory: %w", err)
	}
	for _, tc := range tcs {
		if err := os.Symlink(filepath.Join(tc.Root, "bin", "go"), filepath.Join(dir, tc.Name)); err != nil {
			_ = os.RemoveAll(dir)
			return "", fmt.Errorf("linking %s: %w", tc.Name, err)
		}
	}
	return dir, nil
}

// WithOnDiskToolchain returns env with shimDir leading PATH and the toolchain
// selection moved from `local` to `path`.
//
// `path` is the only setting that lets the go command switch toolchains and
// cannot download one: it lists the candidates by reading PATH, and refuses by
// name when none of them matches. That is a stronger statement of the guarantee
// than `local` makes — `local` forbids the switch, `path` forbids the download —
// and it is enforced by the go command rather than by this side of the boundary.
// It is also the go command's own version arithmetic doing the selection, so a
// requirement raised by a dependency deep in the graph is resolved on the same
// terms as one on the main module's own go line.
//
// Both keys are appended rather than rewritten in place: a repeated key resolves
// to its last value for the go command and for exec, which is how every other
// value in these environments is set.
func WithOnDiskToolchain(env []string, shimDir string) []string {
	path, _ := lastValue(env, "PATH")
	if path != "" {
		shimDir += string(os.PathListSeparator) + path
	}
	return append(append(env[:len(env):len(env)], "PATH="+shimDir), "GOTOOLCHAIN=path")
}

// ToolchainName renders a Go version as the toolchain that provides it:
// "1.26.6" is go1.26.6, and a bare language version like "1.27" is served by its
// first release, go1.27.0. That second rule is the go command's own — no
// toolchain is published under a language version — and getting it wrong would
// print a remedy naming a download that does not exist.
func ToolchainName(version string) string {
	bare := strings.TrimPrefix(version, "go")
	f, ok := goVersionFields(bare)
	if ok && len(f) == 2 {
		return "go" + bare + ".0"
	}
	return "go" + bare
}

// HigherGoVersion reports whether x is a strictly higher Go version than y.
// Either spelling is accepted, and a version neither side can parse answers
// false: an ordering that cannot be established is not an ordering.
func HigherGoVersion(x, y string) bool {
	xf, xok := goVersionFields(x)
	yf, yok := goVersionFields(y)
	if !xok || !yok {
		return false
	}
	return compareGoVersionFields(xf, yf) > 0
}

// goVersionFields splits a Go version into its numeric fields. It accepts both
// the toolchain spelling ("go1.26.6") and the go-directive spelling ("1.26.6"),
// and rejects everything else — a prerelease such as "1.27rc1" included.
//
// Rejecting prereleases is the conservative half of the decision it feeds: an
// unparsable candidate is never offered to an analysis, and an unparsable
// requirement is never claimed to be satisfied.
func goVersionFields(v string) ([]int, bool) {
	v = strings.TrimPrefix(v, "go")
	if v == "" {
		return nil, false
	}
	parts := strings.Split(v, ".")
	if len(parts) < 2 || len(parts) > 3 {
		return nil, false
	}
	out := make([]int, 0, len(parts))
	for _, p := range parts {
		n, err := strconv.Atoi(p)
		if err != nil || n < 0 {
			return nil, false
		}
		out = append(out, n)
	}
	return out, true
}

// compareGoVersionFields orders two field lists, treating a missing field as
// zero so 1.27 and 1.27.0 compare equal — which is what a "go 1.27" directive
// means and what the go command's first release of a language version provides.
func compareGoVersionFields(x, y []int) int {
	for i := range max(len(x), len(y)) {
		a, b := 0, 0
		if i < len(x) {
			a = x[i]
		}
		if i < len(y) {
			b = y[i]
		}
		if a != b {
			if a < b {
				return -1
			}
			return 1
		}
	}
	return 0
}
