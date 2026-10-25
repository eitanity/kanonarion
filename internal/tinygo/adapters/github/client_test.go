package github_test

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/eitanity/kanonarion/internal/adapters/goenv"
	"github.com/eitanity/kanonarion/internal/tinygo/adapters/github"
	"github.com/eitanity/kanonarion/internal/tinygo/domain"
)

func sum(b []byte) string {
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:])
}

// archiveFiles is what a release archive holds: two files under src, one
// outside it, a directory and a link, which the manifest leaves out.
var archiveFiles = map[string]string{
	"tinygo/src/device/rp/rp2040.go": "package rp\n",
	"tinygo/src/machine/machine.go":  "package machine\n",
	"tinygo/bin/tinygo":              "ELF",
}

func wantManifest() []domain.ManifestEntry {
	return []domain.ManifestEntry{
		{Path: "device/rp/rp2040.go", SHA256: sum([]byte("package rp\n"))},
		{Path: "machine/machine.go", SHA256: sum([]byte("package machine\n"))},
	}
}

func tarGz(t *testing.T) []byte {
	t.Helper()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	for _, h := range []*tar.Header{
		{Name: "tinygo/src/", Typeflag: tar.TypeDir, Mode: 0o755},
		{Name: "tinygo/src/link.go", Typeflag: tar.TypeSymlink, Linkname: "machine/machine.go"},
		{Name: "tinygo/src/../escape.go", Typeflag: tar.TypeReg, Mode: 0o644},
	} {
		if err := tw.WriteHeader(h); err != nil {
			t.Fatal(err)
		}
	}
	for _, name := range []string{"tinygo/bin/tinygo", "tinygo/src/device/rp/rp2040.go", "tinygo/src/machine/machine.go"} {
		body := archiveFiles[name]
		if err := tw.WriteHeader(&tar.Header{Name: name, Typeflag: tar.TypeReg, Mode: 0o644, Size: int64(len(body))}); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write([]byte(body)); err != nil {
			t.Fatal(err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func zipped(t *testing.T) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	if _, err := zw.Create("tinygo/src/"); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"tinygo/bin/tinygo", "tinygo/src/device/rp/rp2040.go", "tinygo/src/machine/machine.go"} {
		w, err := zw.Create(name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := w.Write([]byte(archiveFiles[name])); err != nil {
			t.Fatal(err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func serve(t *testing.T, h http.HandlerFunc) (*httptest.Server, *atomic.Int64) {
	t.Helper()
	t.Setenv("GOENV", filepath.Join(t.TempDir(), "absent"))
	t.Setenv("GOPROXY", "https://proxy.example.com")
	var hits atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		h(w, r)
	}))
	t.Cleanup(srv.Close)
	return srv, &hits
}

func TestAssets(t *testing.T) {
	srv, _ := serve(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v0.42.0":
			_, _ = w.Write([]byte(`{"assets":[{"name":"tinygo0.42.0.linux-amd64.tar.gz","browser_download_url":"https://x/tgz","digest":"sha256:ab"}]}`)) //nolint:errcheck // seen by the client
		case "/v9.9.9":
			http.NotFound(w, r)
		case "/broken":
			_, _ = w.Write([]byte(`{`)) //nolint:errcheck // seen by the client
		default:
			http.Error(w, "limited", http.StatusForbidden)
		}
	})
	c := github.NewWithBaseURL(srv.URL + "/")
	assets, found, err := c.Assets(context.Background(), "v0.42.0")
	if err != nil || !found || len(assets) != 1 || assets[0].URL != "https://x/tgz" || assets[0].Digest != "sha256:ab" {
		t.Errorf("Assets = %+v, %v, %v", assets, found, err)
	}
	assetsRefusals(t, c)
}

func assetsRefusals(t *testing.T, c *github.Client) {
	t.Helper()
	if _, found, err := c.Assets(context.Background(), "v9.9.9"); found || err != nil {
		t.Errorf("an absent release = %v, %v; want not found and no error", found, err)
	}
	if _, _, err := c.Assets(context.Background(), "broken"); err == nil || !strings.Contains(err.Error(), "decoding") {
		t.Errorf("a broken listing err = %v", err)
	}
	if _, _, err := c.Assets(context.Background(), "v0.0.1"); err == nil || !strings.Contains(err.Error(), "403") {
		t.Errorf("a refused listing err = %v", err)
	}
	if _, _, err := github.NewWithBaseURL("http://127.0.0.1:0/").Assets(context.Background(), "v0.42.0"); err == nil {
		t.Error("an unreachable API answered")
	}
	if _, _, err := github.NewWithBaseURL("://bad").Assets(context.Background(), "v0.42.0"); err == nil {
		t.Error("an unparseable URL was requested")
	}
}

func TestRead_MeasuresTheArchiveAndItsSourceTree(t *testing.T) {
	tgz, zp := tarGz(t), zipped(t)
	// Trailing bytes after the gzip stream are no file, but they are the
	// asset's bytes, and the digest is of the asset.
	tgzTrailing := append(append([]byte{}, tgz...), make([]byte, 1<<17)...)
	srv, _ := serve(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/a.tar.gz":
			_, _ = w.Write(tgzTrailing) //nolint:errcheck // seen by the client
		case "/a.zip":
			_, _ = w.Write(zp) //nolint:errcheck // seen by the client
		case "/notgz.tar.gz", "/notzip.zip":
			_, _ = w.Write([]byte("not an archive")) //nolint:errcheck // seen by the client
		default:
			http.NotFound(w, r)
		}
	})
	c := github.New()
	for name, tc := range map[string]struct{ url, asset, digest string }{
		"tar.gz": {srv.URL + "/a.tar.gz", "tinygo0.42.0.linux-amd64.tar.gz", sum(tgzTrailing)},
		"zip":    {srv.URL + "/a.zip", "tinygo0.42.0.windows-amd64.zip", sum(zp)},
	} {
		t.Run(name, func(t *testing.T) {
			got, err := c.Read(context.Background(), tc.url, tc.asset)
			if err != nil {
				t.Fatalf("Read: %v", err)
			}
			if got.SHA256 != tc.digest {
				t.Errorf("digest %s, want %s: the whole asset", got.SHA256, tc.digest)
			}
			if !reflect.DeepEqual(got.Manifest, wantManifest()) {
				t.Errorf("manifest = %+v, want %+v", got.Manifest, wantManifest())
			}
		})
	}
	for _, bad := range []string{"/notgz.tar.gz", "/notzip.zip", "/missing.tar.gz"} {
		if _, err := c.Read(context.Background(), srv.URL+bad, strings.TrimPrefix(bad, "/")); err == nil {
			t.Errorf("Read(%s) succeeded", bad)
		}
	}
}

func TestRead_ACorruptTarIsRefused(t *testing.T) {
	tgz := tarGz(t)
	srv, _ := serve(t, func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(tgz[:len(tgz)/2]) //nolint:errcheck // seen by the client
	})
	if _, err := github.New().Read(context.Background(), srv.URL, "a.tar.gz"); err == nil {
		t.Error("a truncated archive was measured")
	}
}

// TestClient_RefusedUnderAirGap: nothing leaves the machine when the
// environment declares no network, measured against a server ready to answer.
func TestClient_RefusedUnderAirGap(t *testing.T) {
	srv, hits := serve(t, func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte(`{}`)) }) //nolint:errcheck // seen by the client
	if _, _, err := github.NewWithBaseURL(srv.URL+"/").Assets(context.Background(), "v0.42.0"); err != nil {
		t.Fatalf("control: %v", err)
	}
	if hits.Load() != 1 {
		t.Fatalf("control made %d requests, want 1", hits.Load())
	}
	path := filepath.Join(t.TempDir(), "env")
	if err := os.WriteFile(path, []byte("GOPROXY=off\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("GOENV", path)
	t.Setenv("GOPROXY", "")
	c := github.NewWithBaseURL(srv.URL + "/")
	if _, _, err := c.Assets(context.Background(), "v0.42.0"); !errors.Is(err, goenv.ErrNetworkForbidden) {
		t.Errorf("Assets err = %v, want the no-network refusal", err)
	}
	if _, err := c.Read(context.Background(), srv.URL+"/a.tar.gz", "a.tar.gz"); !errors.Is(err, github.ErrNetworkForbidden) {
		t.Errorf("Read err = %v, want the no-network refusal", err)
	}
	if hits.Load() != 1 {
		t.Errorf("%d requests, want none after the control", hits.Load()-1)
	}
}
