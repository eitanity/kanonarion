// Package gitenv builds the constrained environment and command-line overrides
// shared by every adapter in this repository that shells out to git.
//
// It exists so the two git call sites cannot drift apart. Git's configuration
// is not a preferences mechanism when the repository content is chosen by
// someone else: core.hooksPath fires a post-checkout hook, filter.<name>.smudge
// is selected by the repository's own .gitattributes and need only be defined
// somewhere to be run, core.fsmonitor runs on index operations, and
// url.<base>.insteadOf rewrites a URL after the application layer has validated
// it against a host allowlist. None of those involve a transport, so the
// transport allowlist does not bound any of them.
//
// The defence has three parts, and all three are needed:
//
//  1. The environment is built from an explicit allowlist rather than
//     inherited, so a hostile GIT_CONFIG_GLOBAL/GIT_CONFIG_SYSTEM/
//     GIT_CONFIG_COUNT is absent rather than overridden by last-wins, which is
//     a libc detail rather than a guarantee.
//  2. HOME points at a private empty directory, so no per-user config or
//     attributes file can be discovered.
//  3. Git runs somewhere no repository can be found, because repository-local
//     .git/config is the one config file GIT_CONFIG_GLOBAL and
//     GIT_CONFIG_SYSTEM do not govern.
//
// Requires git 2.32 or newer, the release that introduced GIT_CONFIG_GLOBAL and
// GIT_CONFIG_SYSTEM. On an older git, GIT_CONFIG_NOSYSTEM and the HOME override
// still close the system and per-user files.
package gitenv

import (
	"fmt"
	"os"
	"path/filepath"
)

// inheritedEnvKeys is the allowlist of parent-process environment variables
// passed through to git subprocesses.
//
// PATH is needed to find git itself and its transport helpers
// (git-remote-https); TMPDIR so git's scratch files land where the operator
// expects; the proxy and CA variables so git still works on a network that
// requires them. None of them can name a config file or a command for git to
// run.
//
// Note what this excludes: an operator who configures a TLS-intercepting proxy
// or an internal mirror through *git config* rather than through these
// variables will find that git subprocesses started here do not see it. That
// is the intended trade — a mirror substituted via url.<base>.insteadOf would
// silently redirect a verification whose record still reads Verified.
var inheritedEnvKeys = []string{
	"PATH",
	"TMPDIR",
	"HTTP_PROXY", "HTTPS_PROXY", "NO_PROXY", "ALL_PROXY",
	"http_proxy", "https_proxy", "no_proxy", "all_proxy",
	"SSL_CERT_FILE", "SSL_CERT_DIR",
	"GIT_SSL_CAINFO", "GIT_SSL_CAPATH",
	"SystemRoot", // Windows: winsock fails to initialise without it
}

// ScratchHome creates a private empty directory to serve as a git subprocess's
// HOME, and returns it with a cleanup function that removes it. Callers must
// call cleanup.
//
// The directory must never be one holding repository content: a checkout of an
// untrusted repository used as HOME would supply a ~/.gitconfig of the
// publisher's choosing, which is the situation this package exists to prevent.
func ScratchHome() (dir string, cleanup func(), err error) {
	dir, err = os.MkdirTemp("", "kanonarion-githome-*")
	if err != nil {
		return "", nil, fmt.Errorf("creating isolated git HOME: %w", err)
	}
	return dir, func() {
		// Best-effort: a leaked empty temp dir is not worth failing an
		// operation over.
		_ = os.RemoveAll(dir)
	}, nil
}

// Base returns the constrained environment for a git subprocess.
//
// home must be a private empty directory, normally from ScratchHome. workDir is
// the directory the subprocess will run in; it is used to bound repository
// discovery, and the caller must actually set it as the command's directory —
// leaving a command's Dir empty runs it in the parent's working directory,
// which is routinely inside a git repository.
//
// allowedProtocols is the GIT_ALLOW_PROTOCOL value; "https" for every current
// caller.
func Base(home, workDir, allowedProtocols string) []string {
	env := make([]string, 0, len(inheritedEnvKeys)+11)
	for _, key := range inheritedEnvKeys {
		if val, ok := os.LookupEnv(key); ok {
			env = append(env, key+"="+val)
		}
	}
	return append(env,
		// Only the configured transports may be used. GIT_PROTOCOL_FROM_USER=0
		// marks these URLs as not user-supplied so git enforces the allowlist
		// even for transports it would otherwise trust from an interactive user.
		"GIT_ALLOW_PROTOCOL="+allowedProtocols,
		"GIT_PROTOCOL_FROM_USER=0",
		// No interactive prompt: in a non-TTY context it would hang rather than
		// fail.
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
		// Stop repository discovery from walking above workDir's parent, for
		// the case where workDir is itself nested inside a repository. The
		// parent — not workDir — is the ceiling, so a working directory that is
		// deliberately a repository still finds its own .git.
		"GIT_CEILING_DIRECTORIES="+filepath.Dir(workDir),
		"GIT_DISCOVERY_ACROSS_FILESYSTEM=0",
	)
}

// ConfigArgs returns the -c overrides to prepend to every git invocation. They
// duplicate what Base already achieves, deliberately: a future refactor that
// reintroduces an ambient config path would otherwise silently reopen the
// hooks/fsmonitor/ext-transport sinks. Command-line -c beats every config file,
// including a repository-local one, so these hold whatever the environment does.
func ConfigArgs() []string {
	return []string{
		"-c", "core.hooksPath=/dev/null",
		"-c", "core.fsmonitor=",
		"-c", "protocol.ext.allow=never",
	}
}
