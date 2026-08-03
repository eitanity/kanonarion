package direct_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	proxyadapter "github.com/eitanity/kanonarion/internal/adapters/proxy/direct"
	"github.com/eitanity/kanonarion/internal/coordinate/coordinatetest"
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
	coord := coordinatetest.MustNew("github.com/foo/bar", "v1.0.0")

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
	coord := coordinatetest.MustNew("example.com/m", "v1.0.0")

	// Just verify it doesn't panic; the fake proxy may 404 for unknown paths.
	_, _ = p.Info(context.Background(), coord)
}

// TestNew_GOPROXY_DirectRefuses: `direct` asks for VCS-origin fetching, which
// this adapter does not implement. It refuses and says so; it must not become
// the default proxy, which is the one place the operator did not point it.
func TestNew_GOPROXY_DirectRefuses(t *testing.T) {
	t.Setenv("GOPROXY", "direct")
	p, err := proxyadapter.New("", false)
	if !errors.Is(err, proxyadapter.ErrProxyDirectUnsupported) {
		t.Fatalf("New: want ErrProxyDirectUnsupported, got %v", err)
	}
	if p != nil {
		t.Error("expected no proxy adapter alongside the refusal")
	}
}

// TestNew_GOPROXY_OffRefuses: GOPROXY=off is the environment declaring no
// module fetching. Construction fails, so no fetch-capable command gets as far
// as a socket, and the message names the offline ways to proceed.
func TestNew_GOPROXY_OffRefuses(t *testing.T) {
	t.Setenv("GOPROXY", "off")
	p, err := proxyadapter.New("", false)
	if !errors.Is(err, proxyadapter.ErrProxyOff) {
		t.Fatalf("New: want ErrProxyOff, got %v", err)
	}
	if p != nil {
		t.Error("expected no proxy adapter alongside the refusal")
	}
	for _, remedy := range []string{"--from-modcache", "use --recursive"} {
		if !strings.Contains(err.Error(), remedy) {
			t.Errorf("refusal does not name the remedy %q: %v", remedy, err)
		}
	}
}

// TestNew_GOPROXYFlagValue_OffRefuses: the --goproxy override is read with the
// same grammar as the environment variable, so `off` from the flag refuses
// too. A flag that quietly accepted "off" as a hostname would reopen the same
// hole from the other side.
func TestNew_GOPROXYFlagValue_OffRefuses(t *testing.T) {
	t.Setenv("GOPROXY", "https://proxy.example.com")
	if _, err := proxyadapter.New("off", false); !errors.Is(err, proxyadapter.ErrProxyOff) {
		t.Fatalf("New(\"off\"): want ErrProxyOff, got %v", err)
	}
	if _, err := proxyadapter.New("direct", false); !errors.Is(err, proxyadapter.ErrProxyDirectUnsupported) {
		t.Fatalf("New(\"direct\"): want ErrProxyDirectUnsupported, got %v", err)
	}
}
