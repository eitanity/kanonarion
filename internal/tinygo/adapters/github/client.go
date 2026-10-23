// Package github reads TinyGo's releases from GitHub: the asset listing with
// its published digests, and the release archive, measured as it streams in.
package github

import (
	"archive/tar"
	"archive/zip"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path"
	"strings"
	"time"

	"github.com/eitanity/kanonarion/internal/adapters/goenv"
	"github.com/eitanity/kanonarion/internal/tinygo/domain"
	"github.com/eitanity/kanonarion/internal/tinygo/ports"
)

// ErrNetworkForbidden reports that the environment declares no network, so
// the request was refused before any I/O.
var ErrNetworkForbidden = fmt.Errorf("%w: the environment declares no TinyGo release download from GitHub", goenv.ErrNetworkForbidden)

const (
	// The archive is about 185 MB on linux/amd64; the bound is generous so the
	// cap only ever stops a hostile or broken response.
	defaultTimeout         = 15 * time.Minute
	maxListingBytes        = 8 << 20
	maxArchiveBytes  int64 = 2 << 30
	maxArchiveFile   int64 = 256 << 20
	srcPrefix              = "tinygo/src/"
	userAgent              = "kanonarion-tinygo-release"
	githubAPIVersion       = "2022-11-28"
)

// Client reads TinyGo's GitHub releases.
type Client struct {
	http    *http.Client
	baseURL string
}

// New returns a client for the public GitHub API.
func New() *Client { return NewWithBaseURL(domain.RepositoryReleasesAPI) }

// NewWithBaseURL reads the release listing from baseURL+tag; tests point it at
// a local server.
func NewWithBaseURL(baseURL string) *Client {
	return &Client{http: &http.Client{Timeout: defaultTimeout}, baseURL: baseURL}
}

// Assets lists the assets of the release tagged tag.
func (c *Client) Assets(ctx context.Context, tag string) ([]ports.Asset, bool, error) {
	resp, err := c.get(ctx, c.baseURL+tag, "application/vnd.github+json")
	if err != nil {
		return nil, false, err
	}
	defer func() { _ = resp.Body.Close() }() //nolint:errcheck // a read-only body
	if resp.StatusCode == http.StatusNotFound {
		return nil, false, nil
	}
	if resp.StatusCode != http.StatusOK {
		return nil, false, fmt.Errorf("GitHub answered %s for the release %s", resp.Status, tag)
	}
	var listing struct {
		Assets []struct {
			Name               string `json:"name"`
			BrowserDownloadURL string `json:"browser_download_url"`
			Digest             string `json:"digest"`
		} `json:"assets"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxListingBytes)).Decode(&listing); err != nil {
		return nil, false, fmt.Errorf("decoding the release %s: %w", tag, err)
	}
	out := make([]ports.Asset, 0, len(listing.Assets))
	for _, a := range listing.Assets {
		out = append(out, ports.Asset{Name: a.Name, URL: a.BrowserDownloadURL, Digest: a.Digest})
	}
	return out, true, nil
}

// Read downloads the archive at url and measures it as it streams: the SHA-256
// of every byte, and of every regular file under tinygo/src. A .zip has no
// streaming form, so it passes through a temporary file that is removed after.
func (c *Client) Read(ctx context.Context, url, name string) (ports.Archive, error) {
	resp, err := c.get(ctx, url, "application/octet-stream")
	if err != nil {
		return ports.Archive{}, err
	}
	defer func() { _ = resp.Body.Close() }() //nolint:errcheck // a read-only body
	if resp.StatusCode != http.StatusOK {
		return ports.Archive{}, fmt.Errorf("GitHub answered %s for %s", resp.Status, name)
	}
	body := &boundedReader{r: resp.Body, left: maxArchiveBytes}
	sum := sha256.New()
	tee := io.TeeReader(body, sum)
	var manifest []domain.ManifestEntry
	if strings.HasSuffix(name, ".zip") {
		manifest, err = readZip(tee)
	} else {
		manifest, err = readTarGz(tee)
	}
	if err != nil {
		return ports.Archive{}, fmt.Errorf("reading %s: %w", name, err)
	}
	// What the archive format did not consume still belongs to the digest.
	if _, err := io.Copy(io.Discard, tee); err != nil {
		return ports.Archive{}, fmt.Errorf("reading %s: %w", name, err)
	}
	return ports.Archive{SHA256: hex.EncodeToString(sum.Sum(nil)), Manifest: manifest}, nil
}

func (c *Client) get(ctx context.Context, url, accept string) (*http.Response, error) {
	if goenv.NetworkForbidden() {
		return nil, fmt.Errorf("%w: %s not fetched", ErrNetworkForbidden, url)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("building the request for %s: %w", url, err)
	}
	req.Header.Set("User-Agent", userAgent)
	req.Header.Set("Accept", accept)
	req.Header.Set("X-GitHub-Api-Version", githubAPIVersion)
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("requesting %s: %w", url, err)
	}
	return resp, nil
}

func readTarGz(r io.Reader) ([]domain.ManifestEntry, error) {
	gz, err := gzip.NewReader(r)
	if err != nil {
		return nil, fmt.Errorf("opening gzip: %w", err)
	}
	tr := tar.NewReader(gz)
	var out []domain.ManifestEntry
	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("reading tar: %w", err)
		}
		rel, ok := srcPath(hdr.Name)
		if !ok || hdr.Typeflag != tar.TypeReg {
			continue
		}
		digest, err := hashOf(tr)
		if err != nil {
			return nil, fmt.Errorf("reading %s: %w", hdr.Name, err)
		}
		out = append(out, domain.ManifestEntry{Path: rel, SHA256: digest})
	}
	if err := gz.Close(); err != nil {
		return nil, fmt.Errorf("closing gzip: %w", err)
	}
	return out, nil
}

func readZip(r io.Reader) (_ []domain.ManifestEntry, retErr error) {
	tmp, err := os.CreateTemp("", "kanonarion-tinygo-*.zip")
	if err != nil {
		return nil, fmt.Errorf("creating a temporary file: %w", err)
	}
	defer func() {
		retErr = errors.Join(retErr, tmp.Close(), os.Remove(tmp.Name()))
	}()
	size, err := io.Copy(tmp, r)
	if err != nil {
		return nil, fmt.Errorf("saving the archive: %w", err)
	}
	zr, err := zip.NewReader(tmp, size)
	if err != nil {
		return nil, fmt.Errorf("opening zip: %w", err)
	}
	var out []domain.ManifestEntry
	for _, f := range zr.File {
		rel, ok := srcPath(f.Name)
		if !ok || !f.Mode().IsRegular() {
			continue
		}
		digest, err := hashZipEntry(f)
		if err != nil {
			return nil, err
		}
		out = append(out, domain.ManifestEntry{Path: rel, SHA256: digest})
	}
	return out, nil
}

func hashZipEntry(f *zip.File) (_ string, retErr error) {
	rc, err := f.Open()
	if err != nil {
		return "", fmt.Errorf("opening %s: %w", f.Name, err)
	}
	defer func() { retErr = errors.Join(retErr, rc.Close()) }()
	digest, err := hashOf(rc)
	if err != nil {
		return "", fmt.Errorf("reading %s: %w", f.Name, err)
	}
	return digest, nil
}

// srcPath is an archive entry's path under tinygo/src, refusing any name that
// would leave it.
func srcPath(name string) (string, bool) {
	rel, ok := strings.CutPrefix(name, srcPrefix)
	if !ok || rel == "" || path.Clean(rel) != rel || strings.HasPrefix(rel, "../") {
		return "", false
	}
	return rel, true
}

func hashOf(r io.Reader) (string, error) {
	h := sha256.New()
	n, err := io.Copy(h, io.LimitReader(r, maxArchiveFile+1))
	if err != nil {
		return "", fmt.Errorf("hashing: %w", err)
	}
	if n > maxArchiveFile {
		return "", fmt.Errorf("a file larger than %d bytes", maxArchiveFile)
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// boundedReader fails once more than left bytes were read, rather than
// silently truncating what is then hashed.
type boundedReader struct {
	r    io.Reader
	left int64
}

func (b *boundedReader) Read(p []byte) (int, error) {
	n, err := b.r.Read(p)
	b.left -= int64(n)
	if b.left < 0 {
		return n, fmt.Errorf("the archive is larger than %d bytes", maxArchiveBytes)
	}
	return n, err //nolint:wrapcheck // io.EOF must reach the caller unwrapped
}

var (
	_ ports.ReleaseIndex  = (*Client)(nil)
	_ ports.ArchiveReader = (*Client)(nil)
)
