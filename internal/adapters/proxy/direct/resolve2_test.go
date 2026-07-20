package direct_test

import (
	"context"
	"testing"

	"github.com/eitanity/kanonarion/internal/coordinate"

	proxyadapter "github.com/eitanity/kanonarion/internal/adapters/proxy/direct"
)

func TestNew_GOPROXY_CommaSeparated(t *testing.T) {
	srv := setupFakeProxy(t, "example.com/m", "v1.0.0", "module example.com/m\n", nil)
	defer srv.Close()

	// GOPROXY with multiple entries — should use the first (HTTP, so insecure=true).
	t.Setenv("GOPROXY", srv.URL+",https://proxy.golang.org,direct")
	p, err := proxyadapter.New("", true)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	coord := coordinate.ModuleCoordinate{Path: "example.com/m", Version: "v1.0.0"}
	_, _ = p.Info(context.Background(), coord)
}

func TestProxy_InvalidURL(t *testing.T) {
	// Nothing listening at this address; connection refused.
	p, err := proxyadapter.New("http://127.0.0.1:1", true) // insecure=true for http scheme
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	coord := coordinate.ModuleCoordinate{Path: "example.com/m", Version: "v1.0.0"}
	if _, err := p.Info(context.Background(), coord); err == nil {
		t.Error("expected connection refused error")
	}
}
