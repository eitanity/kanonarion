// Package gitexec implements ports.VCSClient by shelling out to the git binary.
//
// Runtime dependency: git must be present in PATH.
package gitexec

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/eitanity/kanonarion/internal/fetch/ports"
)

const (
	// defaultFallbackFetchDepth bounds the object count of the full-fetch
	// fallback in CheckoutToDir. When the single-commit shallow fetch is
	// refused by the server, the fallback fetches every branch head truncated
	// at this depth instead of the unbounded full history — a hostile or
	// enormous repository can therefore no longer exhaust disk via the
	// fallback. If the wanted commit is deeper than this in every branch, the
	// checkout fails closed (the caller records UnverifiedNoVCS) rather than
	// fetching without bound.
	defaultFallbackFetchDepth = 1024

	// defaultFetchTimeout is the wall-clock bound applied to each individual
	// git fetch attempt in CheckoutToDir, so a stalling or drip-feeding remote
	// cannot wedge cross-verification indefinitely.
	defaultFetchTimeout = 2 * time.Minute

	// cmdWaitDelay bounds how long Run waits for I/O pipes after the context
	// cancels the git process. git spawns helpers (git-remote-https) that
	// inherit the output pipes and survive the parent's kill; without this
	// grace period cmd.Run blocks until the helper exits on its own, which
	// against a stalling remote defeats the fetch timeout entirely.
	cmdWaitDelay = 3 * time.Second
)

// ErrGitNotInstalled is returned when the git binary cannot be found in PATH.
// It wraps ports.ErrVCSToolMissing so the application layer can recognise the
// "tool absent" case with errors.Is without importing this adapter, while the
// message stays actionable: it names the --skip-vcs-verify escape hatch so a
// missing tool reads as actionable rather than as a verification failure.
var ErrGitNotInstalled = fmt.Errorf(
	"%w: git not found in PATH — install git or pass --skip-vcs-verify "+
		"(checksum verification still runs)", ports.ErrVCSToolMissing)

// Client shells out to git for VCS operations.
type Client struct {
	// allowedProtocols is the GIT_ALLOW_PROTOCOL value applied to every git
	// invocation. It defaults to "https" so transport helpers that enable RCE or
	// SSRF (ext::, file://, ssh://, git://) are blocked even if a URL slips past
	// the application-layer Origin validation.
	allowedProtocols string
	// fallbackFetchDepth bounds the full-fetch fallback in CheckoutToDir.
	fallbackFetchDepth int
	// fetchTimeout bounds each individual git fetch attempt in CheckoutToDir.
	fetchTimeout time.Duration
}

// New constructs a gitexec Client restricted to the https transport.
func New() *Client {
	return &Client{
		allowedProtocols:   "https",
		fallbackFetchDepth: defaultFallbackFetchDepth,
		fetchTimeout:       defaultFetchTimeout,
	}
}

// checkGitAvailable preflights the git binary so a missing tool surfaces as the
// actionable ErrGitNotInstalled rather than the raw os/exec "executable file not
// found" string buried in a wrapped error.
func checkGitAvailable() error {
	if _, err := exec.LookPath("git"); err != nil {
		return ErrGitNotInstalled
	}
	return nil
}

// ResolveTag returns the full commit SHA a tag or ref points to in the
// remote repository, using git ls-remote.
func (c *Client) ResolveTag(ctx context.Context, url, ref string) (string, error) {
	if err := checkGitAvailable(); err != nil {
		return "", err
	}
	// git ls-remote <url> <ref> prints "<commit>\t<ref>"
	out, err := c.runGit(ctx, "ls-remote", "--exit-code", "--end-of-options", url, ref)
	if err != nil {
		return "", fmt.Errorf("ls-remote %s %s: %w", url, ref, err)
	}
	return parseLsRemoteOutput(out, url, ref)
}

// parseLsRemoteOutput extracts the commit hash that ref points to from raw
// git ls-remote output ("<commit>\t<ref>" lines). It is a pure parser over
// remote-controlled bytes (the DFD untrusted-input surface for the VCS
// cross-verify egress) and is exercised by FuzzResolveTagParse.
func parseLsRemoteOutput(out []byte, url, ref string) (string, error) {
	for line := range strings.SplitSeq(strings.TrimSpace(string(out)), "\n") {
		fields := strings.Fields(line)
		if len(fields) >= 2 && fields[1] == ref {
			commit := fields[0]
			if len(commit) != 40 {
				return "", fmt.Errorf("unexpected commit hash length %d for %q", len(commit), commit)
			}
			return commit, nil
		}
	}
	return "", fmt.Errorf("ref %q not found at %s", ref, url)
}

// CheckoutToDir clones the repository at url and checks out commit into dir.
// dir must exist. This does a shallow clone to the specific commit.
func (c *Client) CheckoutToDir(ctx context.Context, url, commit, dir string) error {
	if err := checkGitAvailable(); err != nil {
		return err
	}
	// Init a bare local repo and fetch just the commit. --end-of-options before
	// the remote and commit positionals stops a flag-like value (e.g. a
	// "--upload-pack=..." commit) from being parsed as an option; a trailing
	// "--" does not, since git parses the positional before reaching it.
	if _, err := c.runGitDir(ctx, dir, "init"); err != nil {
		return fmt.Errorf("git init: %w", err)
	}
	if _, err := c.runGitDir(ctx, dir, "remote", "add", "--end-of-options", "origin", url); err != nil {
		return fmt.Errorf("git remote add: %w", err)
	}
	// Fetch only the specific commit, bounded in wall-clock time.
	if err := c.runFetch(ctx, dir, "fetch", "--depth=1", "--end-of-options", "origin", commit); err != nil {
		// Fall back when single-commit fetch is not supported — but never to an
		// unbounded full fetch: a malicious proxy could point cross-verify at an
		// enormous repository and exhaust disk/time. The fallback is capped at
		// fallbackFetchDepth commits per branch and the same fetch timeout.
		depth := fmt.Sprintf("--depth=%d", c.fallbackFetchDepth)
		if err2 := c.runFetch(ctx, dir, "fetch", depth, "--end-of-options", "origin"); err2 != nil {
			return fmt.Errorf("git fetch: %w (after: %w)", err2, err)
		}
		// The bounded fallback may legitimately not contain the wanted commit
		// (deeper than the depth cap in every branch). Fail closed with an
		// explicit error instead of letting checkout produce a confusing one.
		if _, err2 := c.runGitDir(ctx, dir, "cat-file", "-e", commit+"^{commit}"); err2 != nil {
			return fmt.Errorf(
				"commit %s not found within bounded fallback fetch (depth %d); refusing unbounded fetch: %w",
				commit, c.fallbackFetchDepth, err2)
		}
	}
	// checkout does not honour --end-of-options in older git; the commit is
	// hex-validated before it reaches here, and the trailing "--" keeps it from
	// being read as a pathspec.
	if _, err := c.runGitDir(ctx, dir, "checkout", commit, "--"); err != nil {
		return fmt.Errorf("git checkout %s: %w", commit, err)
	}
	return nil
}

// gitEnv returns an environment for git subprocesses that restricts the
// transport allowlist (blocking ext::/file:///ssh:// RCE and SSRF vectors),
// disables interactive credential prompts (preventing hangs in non-TTY
// contexts), and injects a GitHub token when GITHUB_TOKEN is set.
func (c *Client) gitEnv() []string {
	env := append(os.Environ(),
		// Only the configured transports may be used. GIT_PROTOCOL_FROM_USER=0
		// marks these URLs as not user-supplied so git enforces the allowlist
		// even for transports it would otherwise trust from an interactive user.
		"GIT_ALLOW_PROTOCOL="+c.allowedProtocols,
		"GIT_PROTOCOL_FROM_USER=0",
		"GIT_TERMINAL_PROMPT=0",
		"GIT_ASKPASS=/bin/false",
	)
	if token := os.Getenv("GITHUB_TOKEN"); token != "" {
		env = append(env,
			"GIT_CONFIG_COUNT=1",
			"GIT_CONFIG_KEY_0=http.https://github.com/.extraheader",
			"GIT_CONFIG_VALUE_0=Authorization: token "+token,
		)
	}
	return env
}

func (c *Client) runGit(ctx context.Context, args ...string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, "git", args...) // #nosec G204 -- binary is hard-coded; args come from internal call sites
	cmd.Env = c.gitEnv()
	cmd.WaitDelay = cmdWaitDelay
	var out, errBuf bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &errBuf
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("%w: %s", err, errBuf.String())
	}
	return out.Bytes(), nil
}

// runFetch runs a git fetch invocation in dir under the client's fetch
// timeout, so a stalling or drip-feeding remote cannot hold cross-verification
// open indefinitely. A timeout is reported as such rather than as the raw
// "signal: killed" git failure.
func (c *Client) runFetch(ctx context.Context, dir string, args ...string) error {
	fetchCtx, cancel := context.WithTimeout(ctx, c.fetchTimeout)
	defer cancel()
	if _, err := c.runGitDir(fetchCtx, dir, args...); err != nil {
		if errors.Is(fetchCtx.Err(), context.DeadlineExceeded) && ctx.Err() == nil {
			return fmt.Errorf("git %s exceeded the %s fetch bound: %w",
				strings.Join(args, " "), c.fetchTimeout, err)
		}
		return err
	}
	return nil
}

func (c *Client) runGitDir(ctx context.Context, dir string, args ...string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, "git", args...) // #nosec G204 -- binary is hard-coded; args come from internal call sites
	cmd.Dir = dir
	cmd.Env = c.gitEnv()
	cmd.WaitDelay = cmdWaitDelay
	var out, errBuf bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &errBuf
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("%w: %s", err, errBuf.String())
	}
	return out.Bytes(), nil
}
