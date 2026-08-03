// Package direct implements ports.ModuleProxy against a Go module proxy
// (default: proxy.golang.org).
//
// It reads $GOPROXY under Go's own grammar, including the two values whose
// meaning is that no proxy is to be used: `off` (this environment does no
// module fetching) and `direct` (fetch from the VCS origin instead). Both
// refuse — see ErrProxyOff and ErrProxyDirectUnsupported — because rewriting
// either to the default proxy would cross the boundary the operator drew, and
// would do it silently. $GONOSUMCHECK and $GONOSUMDB govern the checksum
// database, not this adapter; they are read by the sumdb adapter.
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

	"github.com/eitanity/kanonarion/internal/coordinate"

	domain2 "github.com/eitanity/kanonarion/internal/fetch/domain"
	"github.com/eitanity/kanonarion/internal/fetch/ports"
	"golang.org/x/mod/module"
	"golang.org/x/mod/semver"
	"golang.org/x/mod/sumdb/dirhash"
)

// ErrNotFound is returned (wrapped) by get when the server responds with 404.
//
// It is exported because 404 is a definitive answer, not a failure, and callers
// have to be able to tell them apart. The major-version probe is the case that
// forced it: an absent /vN path is exactly what bounds the probe and is a
// cacheable negative, whereas a timeout or a 5xx on the same request is neither.
var ErrNotFound = errors.New("not found")

// ErrProxyOff reports that the environment declares no module fetching
// (GOPROXY=off) and the operation was refused before any network request.
//
// It is a refusal, never a fall-back. GOPROXY=off is an operator's statement
// that this process is on the wrong side of an air gap; treating it as
// "unset" and reaching for the default proxy breaches the contract AND
// records network-acquired evidence in a store that is meant to hold only
// what the enclave itself can see.
var ErrProxyOff = errors.New("GOPROXY=off: the environment declares no module fetching")

// ErrProxyDirectUnsupported reports that GOPROXY selects direct VCS-origin
// fetching, which this adapter does not implement.
//
// It is separate from ErrProxyOff because the two say different things: `off`
// forbids the network, `direct` asks for a fetch route this adapter has not
// got. Both refuse; neither may quietly become the default proxy, which is
// what an operator who wrote `direct` was specifically avoiding.
var ErrProxyDirectUnsupported = errors.New("GOPROXY=direct: direct VCS-origin module fetching is not supported by this adapter")

// offlineRemedies names the ways to proceed without the network. It is
// appended to every no-network refusal so the message that stops the run also
// says what to run instead.
const offlineRemedies = "run offline instead: --from-modcache reads the bytes already in $GOMODCACHE, " +
	"and `kanonarion use --recursive` reconstitutes a module from the store"

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
// entry) or proxy.golang.org; a non-empty baseURL (the --goproxy override) is
// read with the same grammar, so `off` and `direct` mean the same thing from
// the flag as from the environment.
//
// Returns an error when the resolved value forbids proxy fetching (ErrProxyOff,
// ErrProxyDirectUnsupported) or when baseURL uses plain HTTP and insecure is
// false. Construction is the gate on purpose: a caller that builds this adapter
// in order to make a request on the next line is refused before a socket is
// opened rather than after a request has already gone out. A caller that wires
// the adapter into a container it may never fetch through takes Refusing
// instead, so reading a warm store offline still works.
func New(baseURL string, insecure bool) (*Proxy, error) {
	baseURL, err := resolveProxyValue(baseURL)
	if err != nil {
		return nil, err
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

// resolveProxy reads $GOPROXY under Go's own grammar and reports the proxy
// base URL to use, or the refusal that value demands.
func resolveProxy() (string, error) {
	return resolveProxyValue("")
}

// resolveProxyValue resolves an explicit GOPROXY-shaped value, falling back to
// $GOPROXY when value is empty and to proxy.golang.org when that is empty too.
//
// The list grammar is Go's: entries separated by "," or "|", tried in order.
// This adapter speaks to exactly one proxy, so only the first usable entry is
// ever consulted — which is also why an `off` or `direct` after a URL is not
// an error here: Go would try that URL first as well, and never reach the rest
// unless the first entry failed, which this adapter does not survive anyway.
// An `off` reached as the first entry terminates the chain, exactly as it does
// in the go command: nothing after it is tried, and nothing is fetched.
func resolveProxyValue(value string) (string, error) {
	if strings.TrimSpace(value) == "" {
		value = os.Getenv("GOPROXY")
	}
	for entry := range strings.FieldsFuncSeq(value, func(r rune) bool { return r == ',' || r == '|' }) {
		entry = strings.TrimSpace(entry)
		switch entry {
		case "":
			continue
		case "off":
			return "", fmt.Errorf("%w; %s", ErrProxyOff, offlineRemedies)
		case "direct":
			return "", fmt.Errorf("%w; set GOPROXY to a module proxy URL, or %s", ErrProxyDirectUnsupported, offlineRemedies)
		}
		return entry, nil
	}
	return defaultProxy, nil
}

// Info fetches the.info endpoint for the module version.
func (p *Proxy) Info(ctx context.Context, coord coordinate.ModuleCoordinate) (_ ports.ModuleInfo, retErr error) {
	escapedPath, err := module.EscapePath(coord.Path())
	if err != nil {
		return ports.ModuleInfo{}, fmt.Errorf("escaping module path %q: %w", coord.Path(), err)
	}
	escapedVersion, err := module.EscapeVersion(coord.Version())
	if err != nil {
		return ports.ModuleInfo{}, fmt.Errorf("escaping version %q: %w", coord.Version(), err)
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
	if errors.Is(err, ErrNotFound) {
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
	for line := range strings.SplitSeq(strings.TrimSpace(string(data)), "\n") {
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
func (p *Proxy) Latest(ctx context.Context, path string) (_ coordinate.ModuleCoordinate, retErr error) {
	info, err := p.LatestInfo(ctx, path)
	if err != nil {
		return coordinate.ModuleCoordinate{}, err
	}
	coord, err := coordinate.NewModuleCoordinate(path, info.Version)
	if err != nil {
		return coordinate.ModuleCoordinate{}, fmt.Errorf("proxy returned invalid version %q for %s: %w", info.Version, path, err)
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
func (p *Proxy) Download(ctx context.Context, coord coordinate.ModuleCoordinate) (ports.ModuleDownload, error) {
	escapedPath, err := module.EscapePath(coord.Path())
	if err != nil {
		return ports.ModuleDownload{}, fmt.Errorf("escaping module path: %w", err)
	}
	escapedVersion, err := module.EscapeVersion(coord.Version())
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
	goModHash, err := hashGoModBytes(goModBytes)
	if err != nil {
		return ports.ModuleDownload{}, err
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
		// Raw digests over the same zip bytes used for the h1 hash, for the SBOM.
		Digests: domain2.ComputeArtifactDigests(zipBytes),
	}, nil
}

// DownloadGoMod fetches only the standalone go.mod for a module version. It
// hits the proxy's /@v/<version>.mod endpoint and never the .zip endpoint, so
// it does none of the zip download or hashing work Download performs. GoModHash
// is computed from the received bytes — the proxy's own claim is not trusted.
func (p *Proxy) DownloadGoMod(ctx context.Context, coord coordinate.ModuleCoordinate) (ports.GoModDownload, error) {
	escapedPath, err := module.EscapePath(coord.Path())
	if err != nil {
		return ports.GoModDownload{}, fmt.Errorf("escaping module path: %w", err)
	}
	escapedVersion, err := module.EscapeVersion(coord.Version())
	if err != nil {
		return ports.GoModDownload{}, fmt.Errorf("escaping version: %w", err)
	}

	modURL := fmt.Sprintf("%s/%s/@v/%s.mod", p.baseURL, escapedPath, escapedVersion)
	modBody, err := p.get(ctx, modURL)
	if err != nil {
		return ports.GoModDownload{}, fmt.Errorf("fetching go.mod: %w", err)
	}
	goModBytes, readErr := io.ReadAll(modBody)
	if cerr := modBody.Close(); cerr != nil {
		return ports.GoModDownload{}, fmt.Errorf("closing go.mod response: %w", cerr)
	}
	if readErr != nil {
		return ports.GoModDownload{}, fmt.Errorf("reading go.mod: %w", readErr)
	}

	goModHash, err := hashGoModBytes(goModBytes)
	if err != nil {
		return ports.GoModDownload{}, err
	}

	return ports.GoModDownload{
		GoMod:             io.NopCloser(bytes.NewReader(goModBytes)),
		GoModHash:         goModHash,
		InsecureTransport: p.insecure,
	}, nil
}

// hashGoModBytes computes the h1 hash of a standalone go.mod using the canonical
// dirhash algorithm. The result matches the "<version>/go.mod" line go.sum and
// the checksum database record.
func hashGoModBytes(data []byte) (domain2.ModuleHash, error) {
	hashStr, err := dirhash.Hash1([]string{"go.mod"}, func(string) (io.ReadCloser, error) {
		return io.NopCloser(bytes.NewReader(data)), nil
	})
	if err != nil {
		return domain2.ModuleHash{}, fmt.Errorf("computing go.mod hash: %w", err)
	}
	hash, err := domain2.ParseModuleHash(hashStr)
	if err != nil {
		return domain2.ModuleHash{}, fmt.Errorf("parsing go.mod hash: %w", err)
	}
	return hash, nil
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
			return nil, fmt.Errorf("%w: %s (closing body: %w)", ErrNotFound, url, cerr)
		}
		return nil, fmt.Errorf("%w: %s", ErrNotFound, url)
	}
	if resp.StatusCode != http.StatusOK {
		// Typed so callers can tell a retryable proxy condition (429, 5xx) from a
		// definitive answer without parsing the message.
		statusErr := &domain2.ProxyStatusError{StatusCode: resp.StatusCode, URL: url}
		if cerr := resp.Body.Close(); cerr != nil {
			return nil, fmt.Errorf("%w (closing body: %w)", statusErr, cerr)
		}
		return nil, statusErr
	}
	return resp.Body, nil
}

// Exported for testing.
type ProxyTest struct{}

func (ProxyTest) ResolveProxy() (string, error) {
	return resolveProxy()
}

func NewProxyForTest() ProxyTest {
	return ProxyTest{}
}
