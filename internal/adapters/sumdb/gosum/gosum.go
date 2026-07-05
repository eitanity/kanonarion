// Package gosum implements ports.SumDBClient using golang.org/x/mod/sumdb.
// It queries the Go checksum database (sum.golang.org by default) and performs
// full Merkle-tree verification of returned hash entries.
package gosum

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	domain2 "github.com/eitanity/kanonarion/internal/fetch/domain"
	"github.com/eitanity/kanonarion/internal/fetch/ports"
	"golang.org/x/mod/sumdb"
)

const (
	defaultServer = "sum.golang.org"
	// Public key for sum.golang.org, per https://sum.golang.org/lookup/.
	defaultKey = "sum.golang.org+033de0ae+Ac4zctda0e5eza+HJyk9SxEdh+s3Ux18htTTAD8OuAn8"
)

// Client implements ports.SumDBClient.
type Client struct {
	sc       *sumdb.Client
	server   string
	disabled bool
}

// New constructs a Client. cacheDir is the directory used to persist Merkle
// tree tiles and lookup results across invocations. If empty, $GOMODCACHE or
// $GOPATH is used; without any cache the Merkle tree is re-fetched each time.
//
// The client honours GOSUMDB, GOPRIVATE, and GONOSUMCHECK environment variables.
func New(cacheDir string) *Client {
	gosumdb := os.Getenv("GOSUMDB")
	if gosumdb == "off" {
		return &Client{disabled: true}
	}

	server, key := defaultServer, defaultKey
	if gosumdb != "" && gosumdb != defaultServer {
		parts := strings.SplitN(gosumdb, " ", 2)
		server = parts[0]
		if len(parts) == 2 {
			key = parts[1]
		}
	}

	if cacheDir == "" {
		cacheDir = resolveCacheDir(server)
	}

	o := &ops{
		server:   server,
		key:      key,
		cacheDir: cacheDir,
		httpCli: &http.Client{
			Timeout: 30 * time.Second,
		},
	}
	sc := sumdb.NewClient(o)
	return &Client{sc: sc, server: server}
}

// Lookup queries the checksum database for the given module version.
// All failures (disabled, not found, network error, security error) are
// returned as Available=false so the caller can decide the verification policy.
func (c *Client) Lookup(_ context.Context, coord domain2.ModuleCoordinate) ports.SumDBResult {
	if c.disabled {
		return ports.SumDBResult{Available: false, Reason: "GOSUMDB=off"}
	}
	if matchesNoSum(coord.Path) {
		return ports.SumDBResult{Available: false, Reason: "module matches GONOSUMCHECK/GOPRIVATE pattern"}
	}

	lines, err := c.sc.Lookup(coord.Path, coord.Version)
	if err != nil {
		return ports.SumDBResult{Available: false, Reason: fmt.Sprintf("sumdb lookup: %v", err)}
	}

	var zipHash, goModHash domain2.ModuleHash
	for _, line := range lines {
		parts := strings.Fields(line)
		if len(parts) != 3 {
			continue
		}
		hashStr := parts[2]
		if strings.HasSuffix(parts[1], "/go.mod") {
			h, err := domain2.ParseModuleHash(hashStr)
			if err == nil {
				goModHash = h
			}
		} else {
			h, err := domain2.ParseModuleHash(hashStr)
			if err == nil {
				zipHash = h
			}
		}
	}

	if zipHash.IsZero() {
		return ports.SumDBResult{Available: false, Reason: "sumdb returned no zip hash for module"}
	}
	return ports.SumDBResult{
		Available: true,
		ZipHash:   zipHash,
		GoModHash: goModHash,
	}
}

// ops implements sumdb.ClientOps using the local filesystem for caching and
// plain HTTPS for remote fetches.
type ops struct {
	server   string
	key      string
	cacheDir string
	httpCli  *http.Client
	mu       sync.Mutex
	secErr   error
}

func (o *ops) ReadRemote(path string) (_ []byte, retErr error) {
	scheme := "https://"
	if strings.HasPrefix(o.server, "127.0.0.1") || strings.HasPrefix(o.server, "localhost") {
		scheme = "http://"
	}
	url := scheme + o.server + path
	resp, err := o.httpCli.Get(url)
	if err != nil {
		return nil, fmt.Errorf("fetching %s: %w", url, err)
	}
	defer func() {
		if cerr := resp.Body.Close(); cerr != nil && retErr == nil {
			retErr = fmt.Errorf("closing sumdb response for %s: %w", path, cerr)
		}
	}()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("sumdb HTTP %d for %s", resp.StatusCode, url)
	}
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("reading sumdb response for %s: %w", path, err)
	}
	return data, nil
}

func (o *ops) ReadConfig(file string) ([]byte, error) {
	if file == "key" {
		return []byte(o.key), nil
	}
	p := o.configPath(file)
	data, err := os.ReadFile(p) // #nosec G304 -- path derived from operator-controlled cache dir
	if os.IsNotExist(err) {
		return nil, nil // signals "start with empty tree" per ClientOps contract
	}
	if err != nil {
		return nil, fmt.Errorf("reading sumdb config %s: %w", file, err)
	}
	return data, nil
}

func (o *ops) WriteConfig(file string, old, new []byte) error {
	if file == "key" {
		return nil
	}
	p := o.configPath(file)
	if err := os.MkdirAll(filepath.Dir(p), 0o750); err != nil {
		return fmt.Errorf("creating sumdb config dir: %w", err)
	}
	if old == nil {
		f, err := os.OpenFile(p, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600) // #nosec G304 -- path derived from operator-controlled cache dir
		if os.IsExist(err) {
			return nil
		}
		if err != nil {
			return fmt.Errorf("creating sumdb config %s: %w", file, err)
		}
		_, werr := f.Write(new)
		cerr := f.Close()
		if werr != nil {
			return fmt.Errorf("writing sumdb config %s: %w", file, werr)
		}
		if cerr != nil {
			return fmt.Errorf("closing sumdb config %s: %w", file, cerr)
		}
		return nil
	}
	curr, err := os.ReadFile(p) // #nosec G304 -- path derived from operator-controlled cache dir
	if err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("reading sumdb config %s: %w", file, err)
	}
	if !bytes.Equal(curr, old) {
		return fmt.Errorf("sumdb config %s changed unexpectedly", file)
	}
	if err := os.WriteFile(p, new, 0o600); err != nil { // #nosec G304 -- path derived from operator-controlled cache dir
		return fmt.Errorf("writing sumdb config %s: %w", file, err)
	}
	return nil
}

func (o *ops) ReadCache(file string) ([]byte, error) {
	p := filepath.Join(o.cacheDir, filepath.FromSlash(file))
	data, err := os.ReadFile(p) // #nosec G304 -- path derived from operator-controlled cache dir
	if err != nil {
		return nil, fmt.Errorf("reading sumdb cache %s: %w", file, err)
	}
	return data, nil
}

func (o *ops) WriteCache(file string, data []byte) {
	p := filepath.Join(o.cacheDir, filepath.FromSlash(file))
	if err := os.MkdirAll(filepath.Dir(p), 0o750); err != nil {
		return // non-fatal: next ReadCache miss causes re-fetch
	}
	if err := os.WriteFile(p, data, 0o600); err != nil { // #nosec G304 -- path derived from operator-controlled cache dir
		return // non-fatal: next ReadCache miss causes re-fetch
	}
}

func (o *ops) Log(line string) {}

func (o *ops) SecurityError(msg string) {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.secErr = fmt.Errorf("sumdb security error: %s", msg)
}

func (o *ops) configPath(file string) string {
	// "lookup/module@version" → cacheDir/lookup/module@version
	rel := filepath.FromSlash(file)
	return filepath.Join(o.cacheDir, rel)
}

// resolveCacheDir returns a suitable directory for persisting sumdb state,
// mirroring the layout the Go tool uses: $GOMODCACHE/download/sumdb/<server>/.
func resolveCacheDir(server string) string {
	if modcache := os.Getenv("GOMODCACHE"); modcache != "" {
		return filepath.Join(modcache, "download", "sumdb", server)
	}
	if gopath := os.Getenv("GOPATH"); gopath != "" {
		return filepath.Join(gopath, "pkg", "mod", "cache", "download", "sumdb", server)
	}
	// Fall back to UserCacheDir so Merkle tiles persist across invocations
	// even when GOMODCACHE/GOPATH are unset. On platforms where UserCacheDir
	// fails we accept the no-cache degradation rather than invent an
	// unpredictable path.
	if cacheDir, err := os.UserCacheDir(); err == nil && cacheDir != "" {
		return filepath.Join(cacheDir, "kanonarion", "sumdb", server)
	}
	return ""
}

// matchesNoSum reports whether the module path is excluded from sumdb
// checking by GONOSUMCHECK or GOPRIVATE.
func matchesNoSum(modulePath string) bool {
	for _, pattern := range noSumPatterns() {
		pattern = strings.TrimSpace(pattern)
		if pattern == "" {
			continue
		}
		if matchesPathPattern(pattern, modulePath) {
			return true
		}
	}
	return false
}

func noSumPatterns() []string {
	var patterns []string
	if v := os.Getenv("GOPRIVATE"); v != "" {
		patterns = append(patterns, strings.Split(v, ",")...)
	}
	if v := os.Getenv("GONOSUMCHECK"); v != "" {
		patterns = append(patterns, strings.Split(v, ",")...)
	}
	if v := os.Getenv("GONOSUMDB"); v != "" {
		patterns = append(patterns, strings.Split(v, ",")...)
	}
	return patterns
}

// matchesPathPattern reports whether path equals pattern, has pattern as a
// prefix (followed by /), or matches the glob pattern.
func matchesPathPattern(pattern, path string) bool {
	if pattern == path {
		return true
	}
	if strings.HasPrefix(path, pattern+"/") {
		return true
	}
	// Support simple wildcard prefix matching: *.corp.com matches sub.corp.com
	if strings.HasPrefix(pattern, "*.") {
		suffix := pattern[1:] // ".corp.com"
		if strings.HasSuffix(path, suffix) || path == pattern[2:] {
			return true
		}
	}
	return false
}
