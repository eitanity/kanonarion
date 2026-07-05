package direct_test

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	proxyadapter "github.com/eitanity/kanonarion/internal/adapters/proxy/direct"
	"github.com/eitanity/kanonarion/internal/fetch/domain"
)

func fakeInfoJSON(version string, origin *struct {
	VCS, URL, Ref, Hash string
}) []byte {
	type infoOrigin struct {
		VCS  string `json:"VCS,omitempty"`
		URL  string `json:"URL,omitempty"`
		Ref  string `json:"Ref,omitempty"`
		Hash string `json:"Hash,omitempty"`
	}
	type info struct {
		Version string      `json:"Version"`
		Time    time.Time   `json:"Time"`
		Origin  *infoOrigin `json:"Origin,omitempty"`
	}
	v := info{Version: version, Time: time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)}
	if origin != nil {
		v.Origin = &infoOrigin{VCS: origin.VCS, URL: origin.URL, Ref: origin.Ref, Hash: origin.Hash}
	}
	b, _ := json.Marshal(v)
	return b
}

// createMinimalZip builds a valid module zip with a single go.mod entry.
func createMinimalZip(t *testing.T, modPath, version string) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	entry := fmt.Sprintf("%s@%s/go.mod", modPath, version)
	f, err := zw.Create(entry)
	if err != nil {
		t.Fatalf("zip create: %v", err)
	}
	if _, err := fmt.Fprintf(f, "module %s\n\ngo 1.21\n", modPath); err != nil {
		t.Fatalf("zip write: %v", err)
	}
	if err := zw.Close(); err != nil {
		t.Fatalf("zip close: %v", err)
	}
	return buf.Bytes()
}

func setupFakeProxy(t *testing.T, modPath, version, goModContent string, origin *struct {
	VCS, URL, Ref, Hash string
}) *httptest.Server {
	t.Helper()
	zipData := createMinimalZip(t, modPath, version)
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		switch {
		case matchSuffix(r.URL.Path, ".info"):
			w.Header().Set("Content-Type", "application/json")
			if _, err := w.Write(fakeInfoJSON(version, origin)); err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
			}
		case matchSuffix(r.URL.Path, ".ziphash"):
			// proxy's claimed hash (not trusted; we compute our own)
			if _, err := fmt.Fprint(w, "h1:placeholder==\n"); err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
			}
		case matchSuffix(r.URL.Path, ".mod"):
			if _, err := fmt.Fprint(w, goModContent); err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
			}
		case matchSuffix(r.URL.Path, ".zip"):
			w.Header().Set("Content-Type", "application/zip")
			if _, err := w.Write(zipData); err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
			}
		default:
			http.NotFound(w, r)
		}
	})
	return httptest.NewServer(mux)
}

func matchSuffix(path, suffix string) bool {
	return len(path) > len(suffix) && path[len(path)-len(suffix):] == suffix
}

func TestProxy_Info(t *testing.T) {
	srv := setupFakeProxy(t, "github.com/gorilla/mux", "v1.8.1",
		"module github.com/gorilla/mux\n\ngo 1.13\n",
		&struct{ VCS, URL, Ref, Hash string }{
			VCS: "git", URL: "https://github.com/gorilla/mux", Ref: "refs/tags/v1.8.1", Hash: "aabbcc",
		})
	defer srv.Close()

	p, err := proxyadapter.New(srv.URL, true) // insecure: httptest uses http://
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	coord := domain.ModuleCoordinate{Path: "github.com/gorilla/mux", Version: "v1.8.1"}

	info, err := p.Info(context.Background(), coord)
	if err != nil {
		t.Fatalf("Info: %v", err)
	}
	if info.Version != "v1.8.1" {
		t.Errorf("Version = %q", info.Version)
	}
	if info.Origin == nil {
		t.Fatal("Origin is nil")
	}
	if info.Origin.URL != "https://github.com/gorilla/mux" {
		t.Errorf("Origin.URL = %q", info.Origin.URL)
	}
}

func TestProxy_Download(t *testing.T) {
	modPath, version := "github.com/gorilla/mux", "v1.8.1"
	goModContent := fmt.Sprintf("module %s\n\ngo 1.13\n", modPath)
	srv := setupFakeProxy(t, modPath, version, goModContent, nil)
	defer srv.Close()

	p, err := proxyadapter.New(srv.URL, true)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	coord := domain.ModuleCoordinate{Path: modPath, Version: version}

	dl, err := p.Download(context.Background(), coord)
	if err != nil {
		t.Fatalf("Download: %v", err)
	}
	defer func() {
		if err := dl.Zip.Close(); err != nil {
			t.Errorf("Zip.Close: %v", err)
		}
	}()
	defer func() {
		if err := dl.GoMod.Close(); err != nil {
			t.Errorf("GoMod.Close: %v", err)
		}
	}()

	// Hash must be computed from bytes; algorithm is always "h1".
	if dl.ZipHash.Algorithm != "h1" || dl.ZipHash.Value == "" {
		t.Errorf("ZipHash = %v, want non-empty h1 hash", dl.ZipHash)
	}
	if dl.GoModHash.Algorithm != "h1" || dl.GoModHash.Value == "" {
		t.Errorf("GoModHash = %v, want non-empty h1 hash", dl.GoModHash)
	}
}

func TestProxy_InsecureRefused(t *testing.T) {
	// direct.New returns error if URL is http and insecure=false.
	// We need to bypass New's check to test get's check if possible,
	// or just be happy that New also checks it.
	_, err := proxyadapter.New("http://example.com", false)
	if err == nil || !strings.Contains(err.Error(), "uses plain HTTP") {
		t.Errorf("expected error from New for plain HTTP, got: %v", err)
	}
}

func TestProxy_NotFound(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.NotFound(w, r)
	}))
	defer srv.Close()

	p, err := proxyadapter.New(srv.URL, true)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	coord := domain.ModuleCoordinate{Path: "example.com/foo", Version: "v1.0.0"}
	_, err = p.Info(context.Background(), coord)
	if err == nil || !strings.Contains(err.Error(), "not found") {
		t.Errorf("expected not found error, got: %v", err)
	}
}

func TestProxy_ErrorResponse(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	p, err := proxyadapter.New(srv.URL, true)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	coord := domain.ModuleCoordinate{Path: "example.com/foo", Version: "v1.0.0"}
	_, err = p.Info(context.Background(), coord)
	if err == nil || !strings.Contains(err.Error(), "HTTP 500") {
		t.Errorf("expected 500 error, got: %v", err)
	}
}

func TestResolveProxy(t *testing.T) {
	tests := []struct {
		goproxy string
		want    string
	}{
		{"", "https://proxy.golang.org"},
		{"https://custom.proxy", "https://custom.proxy"},
		{"https://custom.proxy,direct", "https://custom.proxy"},
		{"direct", "https://proxy.golang.org"},
		{"off", "https://proxy.golang.org"},
	}

	for _, tt := range tests {
		t.Run(tt.goproxy, func(t *testing.T) {
			t.Setenv("GOPROXY", tt.goproxy)
			got := proxyadapter.NewProxyForTest().ResolveProxy()
			if got != tt.want {
				t.Errorf("resolveProxy() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestProxy_DownloadLimit(t *testing.T) {
	oldMax := proxyadapter.MaxZipBytes
	proxyadapter.MaxZipBytes = 1024
	defer func() { proxyadapter.MaxZipBytes = oldMax }()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, ".mod") {
			_, _ = fmt.Fprint(w, "module test\n")
			return
		}
		// Return more than MaxZipBytes
		data := make([]byte, 2048)
		_, _ = w.Write(data)
	}))
	defer srv.Close()

	p, err := proxyadapter.New(srv.URL, true)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	coord := domain.ModuleCoordinate{Path: "example.com/too-big", Version: "v1.0.0"}
	_, err = p.Download(context.Background(), coord)
	if err == nil || !strings.Contains(err.Error(), "exceeds 0 MB limit") {
		t.Errorf("expected limit error, got: %v", err)
	}
}
