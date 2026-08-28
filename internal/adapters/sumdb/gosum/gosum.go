// Package gosum implements ports.SumDBClient using golang.org/x/mod/sumdb.
// It queries the Go checksum database (sum.golang.org by default) and performs
// full Merkle-tree verification of returned hash entries.
//
// Every environment variable it honours is resolved the way the go command
// resolves them — the variable, then Go's own env file — so `go env -w
// GOSUMDB=off` means here what it means to `go build`.
//
// It answers to GOPROXY as well as to GOSUMDB, because the go command proxies
// checksum-database traffic through $GOPROXY: an environment that declares
// GOPROXY=off has declared that this traffic does not happen either, and a
// client that dialled sum.golang.org anyway would be reaching the network on a
// run whose whole premise is that it does not.
package gosum

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/eitanity/kanonarion/internal/adapters/goenv"
	"github.com/eitanity/kanonarion/internal/coordinate"

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
	// mu guards sc and ops, which are rebuilt after a failed lookup — see
	// client/discard.
	mu  sync.Mutex
	sc  *sumdb.Client
	ops *ops
	// newOps builds a fresh ops for a rebuilt sumdb.Client.
	newOps func() *ops

	server string
	// disabledReason, when non-empty, is the policy answer every Lookup returns
	// without building a client or opening a socket. It carries the reason
	// rather than a bare bool so the caller's verification detail names which
	// declaration switched the checksum database off, which is the difference
	// between "the operator chose this" and "something went wrong".
	disabledReason string
}

// New constructs a Client. cacheDir is the directory used to persist Merkle
// tree tiles and lookup results across invocations. If empty, $GOMODCACHE or
// $GOPATH is used; without any cache the Merkle tree is re-fetched each time.
//
// The client honours GOSUMDB, GOPROXY, GOPRIVATE, GONOSUMCHECK and GONOSUMDB,
// each resolved as the go command resolves it.
//
// Three of those switch the database off outright, and all three are decided
// here rather than at the socket: construction is where the caller learns it
// has a client that will never dial, and a Lookup that never builds a
// sumdb.Client never builds its transport either.
func New(cacheDir string) *Client {
	gosumdb := goenv.Value("GOSUMDB")
	switch {
	case gosumdb == "off":
		return &Client{disabledReason: "GOSUMDB=off"}
	case goenv.NetworkForbidden():
		// The go command reaches the checksum database through $GOPROXY, so
		// GOPROXY=off withdraws this traffic exactly as it withdraws a module
		// fetch. Reported as a policy answer, not a failure: retrying cannot
		// change an operator's declaration.
		return &Client{disabledReason: "GOPROXY=off: the environment declares no checksum-database traffic"}
	case noSumCheckDisablesAll():
		return &Client{disabledReason: "GONOSUMCHECK=" + goenv.Value("GONOSUMCHECK")}
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

	newOps := func() *ops {
		return &ops{
			server:   server,
			key:      key,
			cacheDir: cacheDir,
			httpCli: &http.Client{
				Timeout: 30 * time.Second,
			},
		}
	}
	return &Client{newOps: newOps, server: server}
}

// client returns the inner sumdb client, building one on first use or after a
// discard, together with the ops that observed its transport errors.
func (c *Client) client() (*sumdb.Client, *ops) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.sc == nil {
		c.ops = c.newOps()
		c.sc = sumdb.NewClient(c.ops)
	}
	return c.sc, c.ops
}

// discard drops sc so the next Lookup builds a fresh sumdb client.
//
// This is what makes retrying a failed lookup mean anything. sumdb.Client
// memoises every lookup in a per-client cache keyed by module@version — and the
// memoised value includes the error, as does its tile cache. Asking the same
// sumdb.Client again after a 503 therefore replays the recorded failure without
// touching the network, which would turn a retry decorator into a silent no-op.
// A rebuilt client re-fetches; the Merkle tiles it re-reads come back off the
// on-disk cache, so the cost is a map, not a re-download of the tree.
//
// sc is compared identity-wise so a concurrent lookup that already rebuilt the
// client is not discarded a second time.
func (c *Client) discard(sc *sumdb.Client) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.sc == sc {
		c.sc = nil
		c.ops = nil
	}
}

// Lookup queries the checksum database for the given module version.
// All failures (disabled, not found, network error, security error) are
// returned as Available=false so the caller can decide the verification policy,
// discriminated by SumDBResult.Unavailability: a deliberate policy answer versus
// a lookup that failed and may succeed on a later attempt.
func (c *Client) Lookup(_ context.Context, coord coordinate.ModuleCoordinate) ports.SumDBResult {
	if c.disabledReason != "" {
		return ports.SumDBResult{
			Available:      false,
			Reason:         c.disabledReason,
			Unavailability: ports.SumDBUnavailabilityPolicy,
		}
	}
	if matchesNoSum(coord.Path()) {
		return ports.SumDBResult{
			Available:      false,
			Reason:         "module matches GONOSUMCHECK/GOPRIVATE pattern",
			Unavailability: ports.SumDBUnavailabilityPolicy,
		}
	}

	sc, o := c.client()
	lines, err := sc.Lookup(coord.Path(), coord.Version())
	if err != nil {
		// The failed lookup is memoised inside sc (errors included), so drop the
		// client: a retry must reach the network, not replay this error.
		c.discard(sc)
		return ports.SumDBResult{
			Available:      false,
			Reason:         fmt.Sprintf("sumdb lookup: %v", err),
			Unavailability: ports.SumDBUnavailabilityFailure,
			Err:            classifiableLookupError(err, o),
		}
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
		// The database answered; it simply carries no zip hash line for this
		// version. That is a settled answer about the module, not a failed
		// measurement, so it is policy-unavailable and retrying cannot change it.
		return ports.SumDBResult{
			Available:      false,
			Reason:         "sumdb returned no zip hash for module",
			Unavailability: ports.SumDBUnavailabilityPolicy,
		}
	}
	return ports.SumDBResult{
		Available: true,
		ZipHash:   zipHash,
		GoModHash: goModHash,
	}
}

// classifiableLookupError returns the error a retry decorator should classify
// for a failed lookup.
//
// sumdb.Client.Lookup annotates its error with fmt.Errorf("%s@%s: %v", …) —
// %v, not %w — so by the time a lookup failure reaches this adapter the error
// chain has been flattened to a string and neither errors.As nor errors.Is can
// see the transport error underneath. Classifying on the flattened message would
// mean pattern-matching text that x/mod is free to reword.
//
// Instead the transport error is captured where it is still typed, by ops, and
// read back here. Two rules govern the read:
//
//   - A security error always wins. ClientOps documents that the client returns
//     ErrSecurity from any operation that called SecurityError, so a recorded
//     secErr is the authoritative signal even though the returned error's chain
//     was flattened. A misbehaving-server verdict is a tamper signal about the
//     database, and retrying it is exactly the wrong response.
//   - Otherwise the last unrecovered transient transport failure, if any, is the
//     error to classify. ops clears it on a later successful fetch, so a 503 on a
//     partial tile that the full-tile fetch then satisfied does not make an
//     unrelated verification failure look transient.
func classifiableLookupError(err error, o *ops) error {
	if o == nil {
		return err
	}
	if secErr := o.securityError(); secErr != nil {
		return err
	}
	if transient := o.lastTransportError(); transient != nil {
		return transient
	}
	return err
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
	// lastErr is the most recent unrecovered ReadRemote failure, retained with
	// its type intact so a caller can classify it after sumdb.Client has
	// flattened the error chain it returns. A successful fetch clears it.
	//
	// One ops is shared by every concurrent lookup through the same client, so a
	// failure observed by one lookup can be read by another that failed at the
	// same moment. The consequence is bounded — at worst one extra retry of a
	// permanent error on a run where the network was genuinely misbehaving — and
	// it is preferred to per-lookup plumbing that sumdb.ClientOps gives no hook for.
	lastErr error
}

func (o *ops) ReadRemote(path string) (_ []byte, retErr error) {
	scheme := "https://"
	if strings.HasPrefix(o.server, "127.0.0.1") || strings.HasPrefix(o.server, "localhost") {
		scheme = "http://"
	}
	url := scheme + o.server + path
	resp, err := o.httpCli.Get(url)
	if err != nil {
		return nil, o.recordRemoteErr(fmt.Errorf("fetching %s: %w", url, err))
	}
	defer func() {
		if cerr := resp.Body.Close(); cerr != nil && retErr == nil {
			retErr = fmt.Errorf("closing sumdb response for %s: %w", path, cerr)
		}
	}()
	if resp.StatusCode != http.StatusOK {
		// Carried as a typed *ProxyStatusError, not only as message text, so the
		// status is classifiable data: a 429 or 5xx from the checksum database is a
		// transient condition, a 4xx its real answer. Returned bare rather than
		// wrapped in a "sumdb HTTP %d for %s" prefix, because its own Error()
		// already renders the status and the URL — wrapping printed both twice in
		// the verification detail that lands on the record.
		return nil, o.recordRemoteErr(&domain2.ProxyStatusError{StatusCode: resp.StatusCode, URL: url})
	}
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, o.recordRemoteErr(fmt.Errorf("reading sumdb response for %s: %w", path, err))
	}
	o.clearRemoteErr()
	return data, nil
}

// recordRemoteErr retains err for later classification and returns it unchanged.
func (o *ops) recordRemoteErr(err error) error {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.lastErr = err
	return err
}

// clearRemoteErr forgets any retained failure: a fetch has since succeeded, so
// the earlier failure was recovered and must not colour a later verdict.
func (o *ops) clearRemoteErr() {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.lastErr = nil
}

// lastTransportError returns the retained unrecovered ReadRemote failure, if any.
func (o *ops) lastTransportError() error {
	o.mu.Lock()
	defer o.mu.Unlock()
	return o.lastErr
}

// securityError returns the error recorded by SecurityError, if the client
// reported a misbehaving server.
func (o *ops) securityError() error {
	o.mu.Lock()
	defer o.mu.Unlock()
	return o.secErr
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
// Both variables are resolved the go command's way, so a cache relocated with
// `go env -w GOMODCACHE=...` is the one this writes to rather than a second
// copy beside it.
func resolveCacheDir(server string) string {
	if modcache := goenv.Value("GOMODCACHE"); modcache != "" {
		return filepath.Join(modcache, "download", "sumdb", server)
	}
	if gopath := goenv.Value("GOPATH"); gopath != "" {
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
	if v := goenv.Value("GOPRIVATE"); v != "" {
		patterns = append(patterns, strings.Split(v, ",")...)
	}
	// GONOSUMCHECK in its boolean form is not a pattern list and must not be
	// read as one: as a pattern, "1" matches the module path "1" and nothing
	// else, so an operator who switched the checksum database off got it left
	// on for every module they own.
	if v := goenv.Value("GONOSUMCHECK"); v != "" && !isBooleanTrue(v) {
		patterns = append(patterns, strings.Split(v, ",")...)
	}
	if v := goenv.Value("GONOSUMDB"); v != "" {
		patterns = append(patterns, strings.Split(v, ",")...)
	}
	return patterns
}

// noSumCheckDisablesAll reports whether GONOSUMCHECK carries its legacy boolean
// meaning — switch the checksum database off for everything — rather than a
// pattern list.
func noSumCheckDisablesAll() bool { return isBooleanTrue(goenv.Value("GONOSUMCHECK")) }

// isBooleanTrue reports whether v is one of the spellings of "yes" that Go's
// own boolean environment variables accept. A value that is not one of them is
// a pattern list, which is the variable's other historical meaning.
func isBooleanTrue(v string) bool {
	return slices.Contains([]string{"1", "t", "true", "y", "yes", "on"}, strings.ToLower(strings.TrimSpace(v)))
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
