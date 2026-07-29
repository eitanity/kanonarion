package gitexec

import "time"

// NewWithProtocols is a test-only constructor that widens the git transport
// allowlist. Production code must use New (https only); tests use this to drive
// the checkout/resolve paths over the file:// transport without loosening the
// default https-only policy. It exists only in test builds.
func NewWithProtocols(protocols string) *Client {
	c := New()
	c.allowedProtocols = protocols
	return c
}

// SetFetchBounds is a test-only override of the fallback-fetch depth cap and
// the per-attempt fetch timeout, so tests can drive the fail-closed paths with
// tiny bounds instead of waiting out the production defaults.
func (c *Client) SetFetchBounds(fallbackDepth int, timeout time.Duration) {
	c.fallbackFetchDepth = fallbackDepth
	c.fetchTimeout = timeout
}

// SetExtraConfig is a test-only override appending "-c key=value" pairs to
// every git invocation. Tests need it because gitEnv no longer passes
// GIT_CONFIG_* through from the parent process, so the environment is not a
// route for shaping git's behaviour in a test any more. Pass keys and values
// already joined, e.g. "protocol.version=0".
func (c *Client) SetExtraConfig(settings ...string) {
	c.extraConfig = nil
	for _, s := range settings {
		c.extraConfig = append(c.extraConfig, "-c", s)
	}
}

// GitEnv re-exports the child environment builder so tests can assert on the
// exact variable block handed to git — that no inherited GIT_CONFIG_* survives,
// and that HOME is the isolated directory rather than the operator's. workDir
// is the directory the invocation would run in.
func (c *Client) GitEnv(home, workDir string) []string { return c.gitEnv(home, workDir) }

// ConfigArgs re-exports the per-invocation -c overrides for the same reason.
func (c *Client) ConfigArgs() []string { return c.configArgs() }

// ParseLsRemoteOutput re-exports the pure ls-remote parser for the fuzz target
// and parser unit tests.
var ParseLsRemoteOutput = parseLsRemoteOutput
