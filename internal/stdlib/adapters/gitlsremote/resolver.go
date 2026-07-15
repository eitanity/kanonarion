// Package gitlsremote implements ports.CommitResolver by running
// `git ls-remote` against the Go source repository to resolve a release tag to
// its commit — the VCS-anchor half of the standard-library chain of custody.
//
// Runtime dependency: git must be present in PATH. A missing git binary or an
// unreachable remote surfaces as an error, which the acquirer records as an
// unresolved commit rather than a failure.
package gitlsremote

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"os/exec"
	"strings"
	"time"

	"github.com/eitanity/kanonarion/internal/stdlib/ports"
)

// defaultTimeout bounds the ls-remote call so an unreachable or drip-feeding
// remote cannot wedge acquisition.
const defaultTimeout = 30 * time.Second

// ErrGitNotInstalled is returned when the git binary cannot be found in PATH.
var ErrGitNotInstalled = errors.New("git not found in PATH")

// Resolver resolves tags to commits via git ls-remote.
type Resolver struct {
	timeout time.Duration
	// allowedProtocols restricts git's transport to https so a hostile repo URL
	// cannot select an RCE/SSRF-capable transport helper.
	allowedProtocols string
}

// New constructs a Resolver restricted to the https transport.
func New() *Resolver {
	return &Resolver{timeout: defaultTimeout, allowedProtocols: "https"}
}

// ResolveCommit returns the commit SHA that tag resolves to in repoURL. It
// prefers the peeled ref (refs/tags/<tag>^{}) so an annotated tag resolves to
// the commit it points at rather than the tag object; a lightweight tag has no
// peeled ref and its direct SHA is used.
func (r *Resolver) ResolveCommit(ctx context.Context, repoURL, tag string) (string, error) {
	if _, err := exec.LookPath("git"); err != nil {
		return "", ErrGitNotInstalled
	}

	ctx, cancel := context.WithTimeout(ctx, r.timeout)
	defer cancel()

	ref := "refs/tags/" + tag
	// #nosec G204 -- binary is hard-coded "git"; repoURL is the fixed Go source
	// repository and the transport is restricted to https via GIT_ALLOW_PROTOCOL.
	cmd := exec.CommandContext(ctx, "git", "ls-remote", "--tags", repoURL, ref, ref+"^{}")
	cmd.Env = append(cmd.Environ(), "GIT_ALLOW_PROTOCOL="+r.allowedProtocols, "GIT_TERMINAL_PROMPT=0")

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return "", fmt.Errorf("git ls-remote %s %s: %w: %s", repoURL, ref, err, strings.TrimSpace(stderr.String()))
	}

	commit, err := parseLsRemote(stdout.Bytes(), ref)
	if err != nil {
		return "", fmt.Errorf("resolving %s in %s: %w", tag, repoURL, err)
	}
	return commit, nil
}

// parseLsRemote extracts the commit for ref from ls-remote output, preferring
// the peeled "<ref>^{}" line when present.
func parseLsRemote(out []byte, ref string) (string, error) {
	var direct string
	sc := bufio.NewScanner(bytes.NewReader(out))
	for sc.Scan() {
		fields := strings.Fields(sc.Text())
		if len(fields) != 2 {
			continue
		}
		sha, name := fields[0], fields[1]
		switch name {
		case ref + "^{}":
			return sha, nil // peeled ref → the commit an annotated tag points at
		case ref:
			direct = sha
		}
	}
	if direct != "" {
		return direct, nil
	}
	return "", errors.New("tag not found in ls-remote output")
}

var _ ports.CommitResolver = (*Resolver)(nil)
