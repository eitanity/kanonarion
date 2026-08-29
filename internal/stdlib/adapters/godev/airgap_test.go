package godev_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"

	"github.com/eitanity/kanonarion/internal/adapters/goenv"
	"github.com/eitanity/kanonarion/internal/stdlib/adapters/godev"
)

// countingServer answers the release manifest and counts every request, so
// "refused before I/O" is measured against a server that was ready to answer
// rather than inferred from the box being offline.
func countingServer(t *testing.T) (*httptest.Server, *atomic.Int64) {
	t.Helper()
	var hits atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		_, _ = w.Write([]byte(`[{"version":"go1.26.4","files":[]}]`))
	}))
	t.Cleanup(srv.Close)
	return srv, &hits
}

// TestGoDev_ControlFetches is the non-zero control.
func TestGoDev_ControlFetches(t *testing.T) {
	t.Setenv("GOENV", filepath.Join(t.TempDir(), "absent"))
	t.Setenv("GOPROXY", "https://proxy.example.com")
	srv, hits := countingServer(t)

	if _, err := godev.NewWithManifestURL(srv.URL).FetchReleases(context.Background()); err != nil {
		t.Fatalf("FetchReleases with the network permitted: %v", err)
	}
	if got := hits.Load(); got != 1 {
		t.Errorf("request count = %d, want 1", got)
	}
}

// TestGoDev_RefusedUnderAirGap: the standard library's go.dev/dl acquisition
// refuses before a socket, and says what answers instead.
func TestGoDev_RefusedUnderAirGap(t *testing.T) {
	path := filepath.Join(t.TempDir(), "env")
	if err := os.WriteFile(path, []byte("GOPROXY=off\n"), 0o600); err != nil {
		t.Fatalf("writing env file: %v", err)
	}
	t.Setenv("GOENV", path)
	t.Setenv("GOPROXY", "")
	srv, hits := countingServer(t)
	c := godev.NewWithManifestURL(srv.URL)

	if _, err := c.FetchReleases(context.Background()); !errors.Is(err, godev.ErrNetworkForbidden) {
		t.Errorf("FetchReleases error = %v, want ErrNetworkForbidden", err)
	}
	if _, err := c.Download(context.Background(), srv.URL+"/go1.26.4.src.tar.gz"); !errors.Is(err, goenv.ErrNetworkForbidden) {
		t.Errorf("Download error = %v, want the shared no-network fact", err)
	}
	if got := hits.Load(); got != 0 {
		t.Errorf("request count = %d, want 0: the refusal must land before any I/O", got)
	}
}
