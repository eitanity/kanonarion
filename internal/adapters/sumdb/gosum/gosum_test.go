package gosum

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"code.eitanity.com/kanonarion/internal/coordinate/coordinatetest"
	"golang.org/x/mod/sumdb/note"
)

// mustNew is New for an environment the test expects to parse.
func mustNew(t *testing.T, cacheDir string) *Client {
	t.Helper()
	c, err := New(cacheDir)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return c
}

// TestNew_ParsesGOSUMDBAsTheGoCommandDoes: each value gives the database the go
// command would dial — verifier name, key and address — or the go command's
// refusal, which no client is built for.
func TestNew_ParsesGOSUMDBAsTheGoCommandDoes(t *testing.T) {
	loopKey := testVerifierKey(t, "localhost:8443")
	pathKey := testVerifierKey(t, "example.com/sumdb")
	slashKey := testVerifierKey(t, "example.com/")
	tests := []gosumdbCase{
		{value: "", name: defaultServer, key: defaultKey, address: "https://sum.golang.org"},
		{value: defaultKey, name: defaultServer, key: defaultKey, address: "https://sum.golang.org"},
		{value: defaultKey + " https://sum.golang.org", name: defaultServer, key: defaultKey, address: "https://sum.golang.org"},
		{value: "sum.golang.org https://sum.golang.org", name: defaultServer, key: defaultKey, address: "https://sum.golang.org"},
		{value: "sum.golang.google.cn", name: defaultServer, key: defaultKey, address: "https://sum.golang.google.cn"},
		{value: "sum.golang.org http://127.0.0.1:1", name: defaultServer, key: defaultKey, address: "http://127.0.0.1:1"},
		{value: "\tsum.golang.org  https://sum.golang.org ", name: defaultServer, key: defaultKey, address: "https://sum.golang.org"},
		{value: loopKey, name: "localhost:8443", key: loopKey, address: "http://localhost:8443"},
		{value: pathKey, name: "example.com/sumdb", key: pathKey, address: "https://example.com/sumdb"},
		{value: "off", disabled: "GOSUMDB=off"},
		{value: "a b c", refusal: "too many fields"},
		{value: "a", refusal: "malformed verifier id"},
		{value: "example.com+bad", refusal: "malformed verifier id"},
		{value: "sum.golang.google.cn https://sum.golang.google.cn", refusal: "malformed verifier id"},
		{value: "  ", refusal: "no database named"},
		{value: "sum.golang.org ://bad", refusal: "bad URL"},
		{value: slashKey, refusal: "must be host[/path]"},
	}
	for _, tt := range tests {
		t.Run(tt.value, func(t *testing.T) {
			clearSumEnv(t)
			t.Setenv("GOSUMDB", tt.value)
			tt.check(t)
		})
	}
}

// gosumdbCase is one GOSUMDB value and the database, policy answer or refusal
// it gives.
type gosumdbCase struct {
	value, name, key, address, disabled, refusal string
}

func (tt gosumdbCase) check(t *testing.T) {
	t.Helper()
	c, err := New(t.TempDir())
	if tt.refusal != "" {
		tt.checkRefusal(t, c, err)
		return
	}
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if cerr := CheckConfig(); cerr != nil {
		t.Errorf("CheckConfig = %v, want nil", cerr)
	}
	if tt.disabled != "" {
		if c.disabledReason != tt.disabled || c.newOps != nil {
			t.Errorf("disabledReason = %q, ops wired = %v; want %q and no ops", c.disabledReason, c.newOps != nil, tt.disabled)
		}
		return
	}
	o := c.newOps()
	if c.server != tt.name || o.server != tt.name || o.key != tt.key || o.base != tt.address {
		t.Errorf("name %q/%q, key %q, address %q; want %q, %q, %q", c.server, o.server, o.key, o.base, tt.name, tt.key, tt.address)
	}
}

func (tt gosumdbCase) checkRefusal(t *testing.T, c *Client, err error) {
	t.Helper()
	if !errors.Is(err, ErrInvalidGOSUMDB) || !strings.Contains(err.Error(), tt.refusal) ||
		!strings.Contains(err.Error(), fmt.Sprintf("%q", tt.value)) {
		t.Fatalf("New = %v, %v; want a refusal naming GOSUMDB, %q and %q", c, err, tt.value, tt.refusal)
	}
	if cerr := CheckConfig(); cerr == nil || cerr.Error() != err.Error() {
		t.Errorf("CheckConfig = %v, want %v", cerr, err)
	}
}

// testVerifierKey is a fresh note verifier key for a database called name.
func testVerifierKey(t *testing.T, name string) string {
	t.Helper()
	_, vkey, err := note.GenerateKey(rand.Reader, name)
	if err != nil {
		t.Fatalf("GenerateKey(%q): %v", name, err)
	}
	return vkey
}

// TestOps_ReadRemoteJoinsTheBaseURL: an explicit GOSUMDB URL is a base the
// database's paths are read under, path and all.
func TestOps_ReadRemoteJoinsTheBaseURL(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/mirror/sumdb/lookup/m@v1" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		_, _ = w.Write([]byte("ok")) //nolint:errcheck // a failed write is seen by the client under test
	}))
	defer ts.Close()
	for _, base := range []string{ts.URL + "/mirror/sumdb", ts.URL + "/mirror/sumdb/"} {
		o := &ops{server: "example.com", base: base, httpCli: ts.Client()}
		if data, err := o.ReadRemote("/lookup/m@v1"); err != nil || string(data) != "ok" {
			t.Errorf("base %q: ReadRemote = %q, %v; want ok", base, data, err)
		}
	}
}

func TestMatchesNoSum(t *testing.T) {
	tests := []struct {
		name       string
		private    string
		nosum      string
		modulePath string
		want       bool
	}{
		{"no patterns", "", "", "github.com/foo/bar", false},
		{"GOPRIVATE match exact", "github.com/foo", "", "github.com/foo", true},
		{"GOPRIVATE match prefix", "github.com/foo", "", "github.com/foo/bar", true},
		{"GOPRIVATE mismatch", "github.com/foo", "", "github.com/bar", false},
		{"GONOSUMCHECK match", "", "github.com/foo", "github.com/foo/bar", true},
		{"Wildcard pattern match", "*.corp.com", "", "sub.corp.com", true},
		{"Wildcard pattern mismatch", "*.corp.com", "", "other.com", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Setenv("GOPRIVATE", tt.private)
			t.Setenv("GONOSUMCHECK", tt.nosum)
			t.Setenv("GONOSUMDB", "")
			if got := matchesNoSum(tt.modulePath); got != tt.want {
				t.Errorf("matchesNoSum(%q) = %v, want %v", tt.modulePath, got, tt.want)
			}
		})
	}
}

func TestOps(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "gosum-test-*")
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		_ = os.RemoveAll(tmpDir)
	}()

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/test-path" {
			_, _ = w.Write([]byte("test data")) //nolint:errcheck // a failed write is seen by the client under test
		} else {
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer ts.Close()

	o := &ops{
		server:   ts.Listener.Addr().String(),
		key:      "test-key",
		cacheDir: tmpDir,
		httpCli:  ts.Client(),
	}

	// Test ReadRemote
	data, err := o.ReadRemote("/test-path")
	if err != nil {
		t.Errorf("ReadRemote failed: %v", err)
	}
	if string(data) != "test data" {
		t.Errorf("expected 'test data', got %q", string(data))
	}

	_, err = o.ReadRemote("/not-found")
	if err == nil {
		t.Error("ReadRemote should fail for 404")
	}

	checkOpsConfigRoundTrip(t, o)

	// Test WriteCache update
	o.WriteCache("cache-file", []byte("new cache data"))
	data, err = o.ReadCache("cache-file")
	if err != nil {
		t.Errorf("ReadCache after update failed: %v", err)
	}
	if string(data) != "new cache data" {
		t.Errorf("expected 'new cache data', got %q", string(data))
	}

	// Test Log and SecurityError
	o.Log("some log")
	o.SecurityError("some error")
	if o.secErr == nil || !strings.Contains(o.secErr.Error(), "some error") {
		t.Errorf("SecurityError not recorded correctly: %v", o.secErr)
	}

	checkOpsConfigEdgeCases(t, o)

	// Test ReadRemote edge cases
	_, err = o.ReadRemote("/not-found")
	if err == nil || !strings.Contains(err.Error(), "404") {
		t.Errorf("ReadRemote expected 404 error, got %v", err)
	}
}

// checkOpsConfigRoundTrip writes, reads back and updates a config entry.
func checkOpsConfigRoundTrip(t *testing.T, o *ops) {
	t.Helper()
	// Test ReadConfig/WriteConfig
	err := o.WriteConfig("test-config", nil, []byte("config data"))
	if err != nil {
		t.Errorf("WriteConfig failed: %v", err)
	}

	data, err := o.ReadConfig("test-config")
	if err != nil {
		t.Errorf("ReadConfig failed: %v", err)
	}
	if string(data) != "config data" {
		t.Errorf("expected 'config data', got %q", string(data))
	}

	// Test WriteConfig update
	err = o.WriteConfig("test-config", []byte("config data"), []byte("new config data"))
	if err != nil {
		t.Errorf("WriteConfig update failed: %v", err)
	}
}

// checkOpsConfigEdgeCases covers the reserved "key" entry, a missing entry,
// and a WriteConfig whose old value does not match.
func checkOpsConfigEdgeCases(t *testing.T, o *ops) {
	t.Helper()
	// Test ReadConfig edge cases
	data, err := o.ReadConfig("key")
	if err != nil || string(data) != "test-key" {
		t.Errorf("ReadConfig('key') failed: data=%q, err=%v", string(data), err)
	}
	data, err = o.ReadConfig("non-existent")
	if err != nil || data != nil {
		t.Errorf("ReadConfig non-existent should return nil,nil; got data=%q, err=%v", string(data), err)
	}

	// Test WriteConfig edge cases
	err = o.WriteConfig("key", nil, []byte("ignored"))
	if err != nil {
		t.Errorf("WriteConfig('key') should be a no-op, got err=%v", err)
	}

	err = o.WriteConfig("test-config", []byte("wrong old"), []byte("new"))
	if err == nil {
		t.Error("WriteConfig with wrong 'old' data should fail")
	}
}

func TestLookup(t *testing.T) {
	// We skip the actual sumdb.Client.Lookup call because it requires a full Merkle tree
	// and signed notes which are hard to mock without a lot of boilerplate.
	// Instead we test the wrapping logic and some error paths.

	client := &Client{disabledReason: "GOSUMDB=off"}
	res := client.Lookup(context.Background(), coordinatetest.MustNew("any", "v1.0.0"))
	if res.Available {
		t.Error("Lookup should not be available when disabled")
	}

	client = &Client{}
	t.Setenv("GONOSUMCHECK", "private.com")
	res = client.Lookup(context.Background(), coordinatetest.MustNew("private.com/foo", "v1.0.0"))
	if res.Available {
		t.Error("Lookup should be unavailable for GONOSUMCHECK")
	}

}

func TestResolveCacheDir_NoEnv(t *testing.T) {
	t.Setenv("GOMODCACHE", "")
	t.Setenv("GOPATH", "")
	dir := resolveCacheDir("server")
	// Fall back to UserCacheDir so Merkle tiles persist across invocations
	// even when GOMODCACHE/GOPATH are unset. On platforms where UserCacheDir
	// succeeds the path must live under kanonarion/sumdb; if it fails we
	// accept the empty no-cache result.
	if dir == "" {
		return
	}
	if !strings.Contains(dir, filepath.Join("kanonarion", "sumdb", "server")) {
		t.Errorf("expected UserCacheDir fallback under kanonarion/sumdb/server, got %s", dir)
	}
}

func TestLookupDisabled(t *testing.T) {
	client := &Client{disabledReason: "GOSUMDB=off"}
	res := client.Lookup(context.Background(), coordinatetest.MustNew("any", "v1.0.0"))
	if res.Available {
		t.Error("Lookup should not be available when disabled")
	}
}

func TestResolveCacheDir(t *testing.T) {
	t.Setenv("GOMODCACHE", "/tmp/modcache")
	dir := resolveCacheDir("server")
	if !strings.HasPrefix(dir, "/tmp/modcache") {
		t.Errorf("expected dir to start with /tmp/modcache, got %s", dir)
	}

	t.Setenv("GOMODCACHE", "")
	t.Setenv("GOPATH", "/tmp/gopath")
	dir = resolveCacheDir("server")
	if !strings.HasPrefix(dir, "/tmp/gopath") {
		t.Errorf("expected dir to start with /tmp/gopath, got %s", dir)
	}
}
