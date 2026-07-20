package gosum

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/eitanity/kanonarion/internal/coordinate"
)

func TestNew(t *testing.T) {
	// Test default initialization
	t.Setenv("GOSUMDB", "")
	client := New("")
	if client.disabled {
		t.Error("client should not be disabled by default")
	}
	if client.server != defaultServer {
		t.Errorf("expected server %s, got %s", defaultServer, client.server)
	}

	// Test GOSUMDB=off
	t.Setenv("GOSUMDB", "off")
	clientOff := New("")
	if !clientOff.disabled {
		t.Error("client should be disabled when GOSUMDB=off")
	}

	// Test custom GOSUMDB
	customServer := "custom.sumdb.org"
	customKey := "custom.sumdb.org+key"
	t.Setenv("GOSUMDB", customServer+" "+customKey)
	clientCustom := New("")
	if clientCustom.server != customServer {
		t.Errorf("expected server %s, got %s", customServer, clientCustom.server)
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
			_, _ = w.Write([]byte("test data"))
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

	// Test ReadConfig/WriteConfig
	err = o.WriteConfig("test-config", nil, []byte("config data"))
	if err != nil {
		t.Errorf("WriteConfig failed: %v", err)
	}

	data, err = o.ReadConfig("test-config")
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

	// Test ReadConfig edge cases
	data, err = o.ReadConfig("key")
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

	// Test ReadRemote edge cases
	_, err = o.ReadRemote("/not-found")
	if err == nil || !strings.Contains(err.Error(), "404") {
		t.Errorf("ReadRemote expected 404 error, got %v", err)
	}
}

func TestLookup(t *testing.T) {
	// We skip the actual sumdb.Client.Lookup call because it requires a full Merkle tree
	// and signed notes which are hard to mock without a lot of boilerplate.
	// Instead we test the wrapping logic and some error paths.

	client := &Client{disabled: true}
	res := client.Lookup(context.Background(), coordinate.ModuleCoordinate{Path: "any", Version: "v1.0.0"})
	if res.Available {
		t.Error("Lookup should not be available when disabled")
	}

	client = &Client{disabled: false}
	t.Setenv("GONOSUMCHECK", "private.com")
	res = client.Lookup(context.Background(), coordinate.ModuleCoordinate{Path: "private.com/foo", Version: "v1.0.0"})
	if res.Available {
		t.Error("Lookup should be unavailable for GONOSUMCHECK")
	}

	// Test malformed server/key
	client = New("badserver")
	if client == nil {
		t.Fatal("New should return client even for bad server")
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
	client := &Client{disabled: true}
	res := client.Lookup(context.Background(), coordinate.ModuleCoordinate{Path: "any", Version: "v1.0.0"})
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
