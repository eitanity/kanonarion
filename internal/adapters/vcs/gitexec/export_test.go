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

// ParseLsRemoteOutput re-exports the pure ls-remote parser for the fuzz target
// and parser unit tests.
var ParseLsRemoteOutput = parseLsRemoteOutput
