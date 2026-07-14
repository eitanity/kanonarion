// Package godev implements the go.dev/dl-backed ports: the release manifest
// client and the source-tarball downloader.
package godev

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/eitanity/kanonarion/internal/stdlib/domain"
	"github.com/eitanity/kanonarion/internal/stdlib/ports"
)

const (
	// defaultTimeout bounds a single HTTP request. The source tarball is tens of
	// MiB, so this is generous rather than tight.
	defaultTimeout = 5 * time.Minute
	// maxManifestBytes caps the release-manifest response read into memory.
	maxManifestBytes = 16 << 20 // 16 MiB
	// maxTarballBytes caps the source-tarball response. The go source tarball is
	// ~30 MiB; the cap guards against an unbounded or hostile response.
	maxTarballBytes = 256 << 20 // 256 MiB
	// userAgent identifies kanonarion in go.dev/dl request logs.
	userAgent = "kanonarion-stdlib-acquirer"
)

// Client is an HTTP client for Go's download service.
type Client struct {
	http        *http.Client
	manifestURL string
}

// New returns a Client with a bounded HTTP timeout.
func New() *Client {
	return NewWithManifestURL(domain.ReleaseManifestURL)
}

// NewWithManifestURL returns a Client that reads the release manifest from a
// caller-supplied URL. It exists so tests can point the client at a local
// server; production code uses New.
func NewWithManifestURL(manifestURL string) *Client {
	return &Client{
		http:        &http.Client{Timeout: defaultTimeout},
		manifestURL: manifestURL,
	}
}

// FetchReleases reads and decodes the published release manifest.
func (c *Client) FetchReleases(ctx context.Context) ([]domain.Release, error) {
	body, err := c.get(ctx, c.manifestURL, maxManifestBytes)
	if err != nil {
		return nil, fmt.Errorf("fetching release manifest: %w", err)
	}
	var releases []domain.Release
	if err := json.Unmarshal(body, &releases); err != nil {
		return nil, fmt.Errorf("decoding release manifest: %w", err)
	}
	return releases, nil
}

// Download fetches the full source tarball at url into memory.
func (c *Client) Download(ctx context.Context, url string) ([]byte, error) {
	body, err := c.get(ctx, url, maxTarballBytes)
	if err != nil {
		return nil, fmt.Errorf("downloading %s: %w", url, err)
	}
	return body, nil
}

// get performs a bounded GET and returns the response body, failing on any
// non-2xx status so a proxy error page is never mistaken for a manifest or a
// tarball.
func (c *Client) get(ctx context.Context, url string, maxBytes int64) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("building request: %w", err)
	}
	req.Header.Set("User-Agent", userAgent)

	resp, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status %s", resp.Status)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxBytes))
	if err != nil {
		return nil, fmt.Errorf("reading response body: %w", err)
	}
	return body, nil
}

var (
	_ ports.ManifestClient = (*Client)(nil)
	_ ports.TarballClient  = (*Client)(nil)
)
