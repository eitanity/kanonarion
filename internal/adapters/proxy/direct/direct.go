// Package direct implements ports.ModuleProxy against a Go module proxy
// (default: proxy.golang.org). It honours $GOPROXY, $GONOSUMCHECK, and
// $GONOSUMDB environment variables via the standard go/env resolution.
package direct

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"sort"
	"strings"
	"time"

	domain2 "github.com/eitanity/kanonarion/internal/fetch/domain"
	"github.com/eitanity/kanonarion/internal/fetch/ports"
	"golang.org/x/mod/module"
	"golang.org/x/mod/semver"
	"golang.org/x/mod/sumdb/dirhash"
)

// errNotFound is returned by get when the server responds with 404.
var errNotFound = errors.New("not found")

const (
	defaultProxy = "https://proxy.golang.org"
	// maxZipBytes matches Go's own limit for module zips (500 MB).
	maxZipBytes = 500 << 20
)

var MaxZipBytes int64 = maxZipBytes

// Proxy is the direct proxy adapter.
type Proxy struct {
	baseURL    string
	httpClient *http.Client
	insecure   bool
}

// New constructs a Proxy adapter. If baseURL is empty it uses $GOPROXY (first
// entry) or proxy.golang.org. Returns an error when baseURL uses plain HTTP
// and insecure is false.
func New(baseURL string, insecure bool) (*Proxy, error) {
	if baseURL == "" {
		baseURL = resolveProxy()
	}
	baseURL = strings.TrimRight(baseURL, "/")
	if !insecure && strings.HasPrefix(strings.ToLower(baseURL), "http://") {
		return nil, fmt.Errorf("proxy URL %q uses plain HTTP; pass --insecure to allow (forces unverified status)", baseURL)
	}
	return &Proxy{
		baseURL:  baseURL,
		insecure: insecure,
		httpClient: &http.Client{
			Timeout: 60 * time.Second,
		},
	}, nil
}

func resolveProxy() string {
	goproxy := os.Getenv("GOPROXY")
	if goproxy == "" {
		return defaultProxy
	}
	parts := strings.SplitN(goproxy, ",", 2)
	first := strings.TrimSpace(parts[0])
	if first == "direct" || first == "off" {
		return defaultProxy
	}
	return first
}

// Info fetches the.info endpoint for the module version.
func (p *Proxy) Info(ctx context.Context, coord domain2.ModuleCoordinate) (_ ports.ModuleInfo, retErr error) {
	escapedPath, err := module.EscapePath(coord.Path)
	if err != nil {
		return ports.ModuleInfo{}, fmt.Errorf("escaping module path %q: %w", coord.Path, err)
	}
	escapedVersion, err := module.EscapeVersion(coord.Version)
	if err != nil {
		return ports.ModuleInfo{}, fmt.Errorf("escaping version %q: %w", coord.Version, err)
	}

	url := fmt.Sprintf("%s/%s/@v/%s.info", p.baseURL, escapedPath, escapedVersion)
	body, err := p.get(ctx, url)
	if err != nil {
		return ports.ModuleInfo{}, fmt.Errorf("fetching info: %w", err)
	}
	defer func() {
		if cerr := body.Close(); cerr != nil && retErr == nil {
			retErr = fmt.Errorf("closing info response body: %w", cerr)
		}
	}()

	var raw struct {
		Version string    `json:"Version"`
		Time    time.Time `json:"Time"`
		Origin  *struct {
			VCS  string `json:"VCS"`
			URL  string `json:"URL"`
			Ref  string `json:"Ref"`
			Hash string `json:"Hash"`
		} `json:"Origin"`
	}
	if err := json.NewDecoder(body).Decode(&raw); err != nil {
		return ports.ModuleInfo{}, fmt.Errorf("decoding info JSON: %w", err)
	}

	info := ports.ModuleInfo{
		Version: raw.Version,
		Time:    raw.Time,
	}
	if raw.Origin != nil {
		info.Origin = &ports.ModuleOrigin{
			VCS:  raw.Origin.VCS,
			URL:  raw.Origin.URL,
			Ref:  raw.Origin.Ref,
			Hash: raw.Origin.Hash,
		}
	}
	return info, nil
}

// ListVersions fetches the /@v/list endpoint and returns all known versions,
// sorted newest-first. Returns a nil slice (no error) if the module is unknown.
func (p *Proxy) ListVersions(ctx context.Context, path string) (_ []string, retErr error) {
	escapedPath, err := module.EscapePath(path)
	if err != nil {
		return nil, fmt.Errorf("escaping module path %q: %w", path, err)
	}
	url := fmt.Sprintf("%s/%s/@v/list", p.baseURL, escapedPath)
	body, err := p.get(ctx, url)
	if errors.Is(err, errNotFound) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("listing versions for %s: %w", path, err)
	}
	defer func() {
		if cerr := body.Close(); cerr != nil && retErr == nil {
			retErr = fmt.Errorf("closing version list body: %w", cerr)
		}
	}()
	data, err := io.ReadAll(body)
	if err != nil {
		return nil, fmt.Errorf("reading version list: %w", err)
	}
	var versions []string
	for _, line := range strings.Split(strings.TrimSpace(string(data)), "\n") {
		if v := strings.TrimSpace(line); v != "" {
			versions = append(versions, v)
		}
	}
	sort.Slice(versions, func(i, j int) bool {
		return semver.Compare(versions[i], versions[j]) > 0
	})
	return versions, nil
}

// LatestVersionInfo holds the resolved version and release timestamp from /@latest.
type LatestVersionInfo struct {
	Version string
	Time    time.Time
}

// Latest fetches the /@latest endpoint and returns the resolved coordinate.
// The proxy resolves "latest" as the highest tagged release, or the highest
// pre-release if no release exists.
func (p *Proxy) Latest(ctx context.Context, path string) (_ domain2.ModuleCoordinate, retErr error) {
	info, err := p.LatestInfo(ctx, path)
	if err != nil {
		return domain2.ModuleCoordinate{}, err
	}
	coord, err := domain2.NewModuleCoordinate(path, info.Version)
	if err != nil {
		return domain2.ModuleCoordinate{}, fmt.Errorf("proxy returned invalid version %q for %s: %w", info.Version, path, err)
	}
	return coord, nil
}

// LatestInfo fetches the /@latest endpoint and returns both the resolved version
// and its release timestamp.
func (p *Proxy) LatestInfo(ctx context.Context, path string) (_ LatestVersionInfo, retErr error) {
	escapedPath, err := module.EscapePath(path)
	if err != nil {
		return LatestVersionInfo{}, fmt.Errorf("escaping module path %q: %w", path, err)
	}
	url := fmt.Sprintf("%s/%s/@latest", p.baseURL, escapedPath)
	body, err := p.get(ctx, url)
	if err != nil {
		return LatestVersionInfo{}, fmt.Errorf("resolving %s@latest: %w", path, err)
	}
	defer func() {
		if cerr := body.Close(); cerr != nil && retErr == nil {
			retErr = fmt.Errorf("closing latest response body: %w", cerr)
		}
	}()
	var raw struct {
		Version string    `json:"Version"`
		Time    time.Time `json:"Time"`
	}
	if err := json.NewDecoder(body).Decode(&raw); err != nil {
		return LatestVersionInfo{}, fmt.Errorf("decoding latest response for %s: %w", path, err)
	}
	if raw.Version == "" {
		return LatestVersionInfo{}, fmt.Errorf("proxy returned empty version for %s@latest", path)
	}
	return LatestVersionInfo{Version: raw.Version, Time: raw.Time}, nil
}

// Download fetches the module zip and go.mod. ZipHash and GoModHash are always
// computed from the received bytes — the proxy's own.ziphash claim is not
// trusted. Returns an error if the download exceeds maxZipBytes.
func (p *Proxy) Download(ctx context.Context, coord domain2.ModuleCoordinate) (ports.ModuleDownload, error) {
	escapedPath, err := module.EscapePath(coord.Path)
	if err != nil {
		return ports.ModuleDownload{}, fmt.Errorf("escaping module path: %w", err)
	}
	escapedVersion, err := module.EscapeVersion(coord.Version)
	if err != nil {
		return ports.ModuleDownload{}, fmt.Errorf("escaping version: %w", err)
	}

	// Fetch standalone go.mod first (smaller; fail fast on bad coordinates).
	modURL := fmt.Sprintf("%s/%s/@v/%s.mod", p.baseURL, escapedPath, escapedVersion)
	modBody, err := p.get(ctx, modURL)
	if err != nil {
		return ports.ModuleDownload{}, fmt.Errorf("fetching go.mod: %w", err)
	}
	goModBytes, readErr := io.ReadAll(modBody)
	if cerr := modBody.Close(); cerr != nil {
		return ports.ModuleDownload{}, fmt.Errorf("closing go.mod response: %w", cerr)
	}
	if readErr != nil {
		return ports.ModuleDownload{}, fmt.Errorf("reading go.mod: %w", readErr)
	}

	// Compute go.mod hash from the actual bytes using the canonical algorithm.
	goModHashStr, err := dirhash.Hash1([]string{"go.mod"}, func(string) (io.ReadCloser, error) {
		return io.NopCloser(bytes.NewReader(goModBytes)), nil
	})
	if err != nil {
		return ports.ModuleDownload{}, fmt.Errorf("computing go.mod hash: %w", err)
	}
	goModHash, err := domain2.ParseModuleHash(goModHashStr)
	if err != nil {
		return ports.ModuleDownload{}, fmt.Errorf("parsing go.mod hash: %w", err)
	}

	// Fetch zip; enforce size limit to guard against resource exhaustion (T12).
	zipURL := fmt.Sprintf("%s/%s/@v/%s.zip", p.baseURL, escapedPath, escapedVersion)
	zipBody, err := p.get(ctx, zipURL)
	if err != nil {
		return ports.ModuleDownload{}, fmt.Errorf("fetching zip: %w", err)
	}
	limited := io.LimitReader(zipBody, MaxZipBytes+1)
	zipBytes, readErr := io.ReadAll(limited)
	if cerr := zipBody.Close(); cerr != nil {
		return ports.ModuleDownload{}, fmt.Errorf("closing zip response: %w", cerr)
	}
	if readErr != nil {
		return ports.ModuleDownload{}, fmt.Errorf("reading zip: %w", readErr)
	}
	if int64(len(zipBytes)) > MaxZipBytes {
		return ports.ModuleDownload{}, fmt.Errorf("module zip exceeds %d MB limit", MaxZipBytes>>20)
	}

	// Compute zip hash from the actual bytes — never from the proxy's.ziphash.
	zipHashStr, err := hashZipBytes(zipBytes)
	if err != nil {
		return ports.ModuleDownload{}, fmt.Errorf("computing zip hash: %w", err)
	}
	zipHash, err := domain2.ParseModuleHash(zipHashStr)
	if err != nil {
		return ports.ModuleDownload{}, fmt.Errorf("parsing zip hash: %w", err)
	}

	return ports.ModuleDownload{
		Zip:               io.NopCloser(bytes.NewReader(zipBytes)),
		GoMod:             io.NopCloser(bytes.NewReader(goModBytes)),
		ZipHash:           zipHash,
		GoModHash:         goModHash,
		InsecureTransport: p.insecure,
	}, nil
}

// hashZipBytes computes the h1 hash of a module zip's contents using the
// canonical dirhash algorithm. The result matches go.sum and sumdb entries.
func hashZipBytes(data []byte) (string, error) {
	zr, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		return "", fmt.Errorf("opening zip: %w", err)
	}
	files := make([]string, len(zr.File))
	byName := make(map[string]*zip.File, len(zr.File))
	for i, f := range zr.File {
		files[i] = f.Name
		byName[f.Name] = f
	}
	hash, err := dirhash.Hash1(files, func(name string) (io.ReadCloser, error) {
		f := byName[name]
		if f == nil {
			return nil, fmt.Errorf("file %q not in zip", name)
		}
		return f.Open()
	})
	if err != nil {
		return "", fmt.Errorf("hashing zip contents: %w", err)
	}
	return hash, nil
}

func (p *Proxy) get(ctx context.Context, url string) (io.ReadCloser, error) {
	if !p.insecure && strings.HasPrefix(strings.ToLower(url), "http://") {
		return nil, fmt.Errorf("refusing plain HTTP connection to %s", url)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("creating request for %s: %w", url, err)
	}
	resp, err := p.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("executing request for %s: %w", url, err)
	}
	if resp.StatusCode == http.StatusNotFound {
		if cerr := resp.Body.Close(); cerr != nil {
			return nil, fmt.Errorf("%w: %s (closing body: %w)", errNotFound, url, cerr)
		}
		return nil, fmt.Errorf("%w: %s", errNotFound, url)
	}
	if resp.StatusCode != http.StatusOK {
		if cerr := resp.Body.Close(); cerr != nil {
			return nil, fmt.Errorf("HTTP %d from %s (closing body: %w)", resp.StatusCode, url, cerr)
		}
		return nil, fmt.Errorf("HTTP %d from %s", resp.StatusCode, url)
	}
	return resp.Body, nil
}

// Exported for testing.
type ProxyTest struct{}

func (ProxyTest) ResolveProxy() string {
	return resolveProxy()
}

func NewProxyForTest() ProxyTest {
	return ProxyTest{}
}
