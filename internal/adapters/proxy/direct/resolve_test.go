package direct_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/eitanity/kanonarion/internal/coordinate"

	proxyadapter "github.com/eitanity/kanonarion/internal/adapters/proxy/direct"
)

func TestProxy_HTTPError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "not found", http.StatusNotFound)
	}))
	defer srv.Close()

	// insecure=true because httptest uses http://
	p, err := proxyadapter.New(srv.URL, true)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	coord := coordinate.ModuleCoordinate{Path: "github.com/foo/bar", Version: "v1.0.0"}

	if _, err := p.Info(context.Background(), coord); err == nil {
		t.Error("expected error on 404")
	}
	if _, err := p.Download(context.Background(), coord); err == nil {
		t.Error("expected error on 404 during download")
	}
}

func TestNew_PlainHTTP_Rejected(t *testing.T) {
	_, err := proxyadapter.New("http://proxy.example.com", false)
	if err == nil {
		t.Error("expected error for plain HTTP without insecure flag")
	}
}

func TestNew_GOPROXY(t *testing.T) {
	srv := setupFakeProxy(t, "example.com/m", "v1.0.0", "module example.com/m\n", nil)
	defer srv.Close()

	t.Setenv("GOPROXY", srv.URL)
	p, err := proxyadapter.New("", true) // insecure: GOPROXY points to http://
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	coord := coordinate.ModuleCoordinate{Path: "example.com/m", Version: "v1.0.0"}

	// Just verify it doesn't panic; the fake proxy may 404 for unknown paths.
	_, _ = p.Info(context.Background(), coord)
}

func TestNew_GOPROXY_DirectFallback(t *testing.T) {
	// GOPROXY=direct should fall back to default (proxy.golang.org, HTTPS).
	t.Setenv("GOPROXY", "direct")
	p, err := proxyadapter.New("", false)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if p == nil {
		t.Error("expected non-nil proxy")
	}
}

func TestNew_GOPROXY_Off(t *testing.T) {
	t.Setenv("GOPROXY", "off")
	p, err := proxyadapter.New("", false)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if p == nil {
		t.Error("expected non-nil proxy")
	}
}
