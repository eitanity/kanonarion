// Package gitexec implements ports.VCSClient by shelling out to the git binary.
//
// Runtime dependency: git must be present in PATH, version 2.32 or newer.
// 2.32 is the release that introduced GIT_CONFIG_GLOBAL/GIT_CONFIG_SYSTEM,
// which this adapter relies on to neutralise git's configuration surface (see
// gitEnv). On an older git the GIT_CONFIG_NOSYSTEM=1 and HOME overrides still
// close the system and per-user files, but the neutralisation is no longer
// belt-and-braces.
//
// Every git subprocess started here runs against attacker-controlled
// repository content (the module source being cross-verified), so the child
// environment is built from an explicit allowlist rather than inherited, and
// git's config discovery is switched off in full. Config is not merely a
// preferences mechanism for git: core.hooksPath, filter.<name>.smudge and
// core.fsmonitor are all arbitrary-command sinks reachable from a plain
// checkout, and url.<base>.insteadOf rewrites a fetch URL *after* the
// application layer has validated it against the VCS host allowlist.
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
	// extraConfig holds additional "-c key=value" argument pairs appended to
	// configArgs. It is empty in production; tests use it to drive git into a
	// mode they need (protocol.version=0), which they can no longer do through
	// the environment now that config discovery is neutralised.
	extraConfig []string
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
	// Init a local repo with a working tree and fetch just the commit. The tree
	// is required: the caller hashes the checked-out directory as a module zip
	// and reads go.mod files out of it to locate a major-version subdirectory,
	// neither of which a bare repo can serve. Execution sinks that a checkout
	// would otherwise reach — post-checkout hooks, smudge filters selected by
	// the repository's own .gitattributes — are closed by gitEnv/configArgs
	// rather than by withholding the tree. --end-of-options before
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

// inheritedEnvKeys is the allowlist of parent-process environment variables
// passed through to git subprocesses. The child environment is built from this
// list rather than from os.Environ() so that an inherited GIT_CONFIG_GLOBAL,
// GIT_CONFIG_SYSTEM, GIT_CONFIG_COUNT, XDG_CONFIG_HOME or HOME cannot reach
// git at all — appending overrides on top of os.Environ() would leave the
// hostile value present in the block and rely on last-wins resolution, which is
// a libc detail rather than a guarantee.
//
// PATH is needed to find git itself and its helpers (git-remote-https); TMPDIR
// so git's own scratch files land where the operator expects; the proxy and CA
// variables so cross-verification still works on a network that requires them.
// None of them can name a config file or a command for git to run.
var inheritedEnvKeys = []string{
	"PATH",
	"TMPDIR",
	"HTTP_PROXY", "HTTPS_PROXY", "NO_PROXY", "ALL_PROXY",
	"http_proxy", "https_proxy", "no_proxy", "all_proxy",
	"SSL_CERT_FILE", "SSL_CERT_DIR",
	"GIT_SSL_CAINFO", "GIT_SSL_CAPATH",
	"SystemRoot", // Windows: winsock fails to initialise without it
}

// gitEnv returns an environment for git subprocesses that neutralises git's
// configuration surface, restricts the transport allowlist (blocking
// ext::/file:///ssh:// RCE and SSRF vectors), disables interactive credential
// prompts (preventing hangs in non-TTY contexts), and injects a GitHub token
// when GITHUB_TOKEN is set.
//
// home must be a private, empty directory owned by this process — never the
// checkout directory, which holds attacker-controlled content and would supply
// a ~/.gitconfig of the attacker's choosing.
//
// With GIT_CONFIG_GLOBAL, GIT_CONFIG_SYSTEM and HOME all neutralised, the
// GITHUB_TOKEN entries below are the only configuration in effect for the
// child, which is the intent.
func (c *Client) gitEnv(home string) []string {
	env := make([]string, 0, len(inheritedEnvKeys)+12)
	for _, key := range inheritedEnvKeys {
		if val, ok := os.LookupEnv(key); ok {
			env = append(env, key+"="+val)
		}
	}
	env = append(env,
		// Only the configured transports may be used. GIT_PROTOCOL_FROM_USER=0
		// marks these URLs as not user-supplied so git enforces the allowlist
		// even for transports it would otherwise trust from an interactive user.
		"GIT_ALLOW_PROTOCOL="+c.allowedProtocols,
		"GIT_PROTOCOL_FROM_USER=0",
		"GIT_TERMINAL_PROMPT=0",
		"GIT_ASKPASS=/bin/false",
		// Config discovery off at every path: the system file (twice, so an
		// older git without GIT_CONFIG_SYSTEM is still covered), the per-user
		// file, and — via HOME — ~/.gitconfig and ~/.config/git/config.
		// XDG_CONFIG_HOME is simply not inherited.
		"GIT_CONFIG_SYSTEM=/dev/null",
		"GIT_CONFIG_NOSYSTEM=1",
		"GIT_CONFIG_GLOBAL=/dev/null",
		"HOME="+home,
		// /etc/gitattributes would otherwise still be read, and attributes are
		// what select a smudge filter for a path.
		"GIT_ATTR_NOSYSTEM=1",
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

// configArgs returns the -c overrides prepended to every git invocation. They
// duplicate what the neutralised environment already achieves, deliberately: a
// future refactor that reintroduces an ambient config path would otherwise
// silently reopen the hooks/fsmonitor/ext-transport sinks. Command-line -c
// beats every config file, so these hold whatever the environment does.
func (c *Client) configArgs() []string {
	args := []string{
		"-c", "core.hooksPath=/dev/null",
		"-c", "core.fsmonitor=",
		"-c", "protocol.ext.allow=never",
	}
	return append(args, c.extraConfig...)
}

// runGit runs git with the process working directory. dir == "" means "wherever
// the parent happens to be"; runGitDir is the variant that pins it.
func (c *Client) runGit(ctx context.Context, args ...string) ([]byte, error) {
	return c.run(ctx, "", args...)
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
	return c.run(ctx, dir, args...)
}

// run is the single point at which a git subprocess is started, so the config
// neutralisation cannot be bypassed by adding a call site. Each invocation gets
// a fresh private HOME: git must not be able to discover a per-user config, and
// the checkout directory is unusable for that purpose because its contents come
// from the repository being verified.
func (c *Client) run(ctx context.Context, dir string, args ...string) ([]byte, error) {
	home, err := os.MkdirTemp("", "kanonarion-githome-*")
	if err != nil {
		return nil, fmt.Errorf("creating isolated git HOME: %w", err)
	}
	defer func() {
		// Best-effort: a leaked empty temp dir is not worth failing a
		// verification over, and there is no logger at this layer.
		_ = os.RemoveAll(home)
	}()

	argv := append(c.configArgs(), args...)
	cmd := exec.CommandContext(ctx, "git", argv...) // #nosec G204 -- binary is hard-coded; args come from internal call sites
	cmd.Dir = dir
	cmd.Env = c.gitEnv(home)
	cmd.WaitDelay = cmdWaitDelay
	var out, errBuf bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &errBuf
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("%w: %s", err, errBuf.String())
	}
	return out.Bytes(), nil
}
