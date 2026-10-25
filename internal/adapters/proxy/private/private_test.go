package private_test

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/eitanity/kanonarion/internal/adapters/proxy/private"
	"github.com/eitanity/kanonarion/internal/coordinate"
	"github.com/eitanity/kanonarion/internal/coordinate/coordinatetest"
	"github.com/eitanity/kanonarion/internal/fetch/ports"
)

// recordingProxy names itself in every answer and records what it was asked.
type recordingProxy struct {
	name  string
	asked []string
}

func (p *recordingProxy) Info(_ context.Context, c coordinate.ModuleCoordinate) (ports.ModuleInfo, error) {
	p.asked = append(p.asked, "info "+c.String())
	return ports.ModuleInfo{Version: p.name}, nil
}

func (p *recordingProxy) Download(_ context.Context, c coordinate.ModuleCoordinate) (ports.ModuleDownload, error) {
	p.asked = append(p.asked, "download "+c.String())
	return ports.ModuleDownload{}, nil
}

func (p *recordingProxy) DownloadGoMod(_ context.Context, c coordinate.ModuleCoordinate) (ports.GoModDownload, error) {
	p.asked = append(p.asked, "gomod "+c.String())
	return ports.GoModDownload{}, nil
}

func corpOnly(path string) (string, bool) {
	return "GOPRIVATE", strings.HasPrefix(path, "corp.example.com")
}

// TestRouter_NoPrivatePathReachesThePublicProxy: every method sends a private
// module to the cache and every other module to the proxy, and the cache is
// built once, on first need.
func TestRouter_NoPrivatePathReachesThePublicProxy(t *testing.T) {
	public, cache := &recordingProxy{name: "public"}, &recordingProxy{name: "cache"}
	built := 0
	r := private.New(public, corpOnly, func(context.Context) (ports.ModuleProxy, error) {
		built++
		return cache, nil
	})
	ctx := context.Background()
	pub := coordinatetest.MustNew("example.org/pub", "v1.0.0")
	if _, err := r.Info(ctx, pub); err != nil {
		t.Fatal(err)
	}
	if built != 0 {
		t.Fatalf("the cache was built for a public module")
	}
	priv := coordinatetest.MustNew("corp.example.com/a", "v1.0.0")
	for _, c := range []coordinate.ModuleCoordinate{pub, priv} {
		if _, err := r.Info(ctx, c); err != nil {
			t.Fatal(err)
		}
		if _, err := r.Download(ctx, c); err != nil {
			t.Fatal(err)
		}
		if _, err := r.DownloadGoMod(ctx, c); err != nil {
			t.Fatal(err)
		}
	}
	for _, a := range public.asked {
		if strings.Contains(a, "corp.example.com") {
			t.Errorf("the public proxy was asked %q", a)
		}
	}
	if len(public.asked) != 4 || len(cache.asked) != 3 {
		t.Errorf("public asked %v, cache asked %v", public.asked, cache.asked)
	}
	if built != 1 {
		t.Errorf("cache built %d times, want once", built)
	}
}

// TestRouter_CacheFailureIsNamedAndNeverFallsBackToTheProxy.
func TestRouter_CacheFailureIsNamedAndNeverFallsBackToTheProxy(t *testing.T) {
	public := &recordingProxy{name: "public"}
	boom := errors.New("no module cache")
	r := private.New(public, corpOnly, func(context.Context) (ports.ModuleProxy, error) { return nil, boom })
	priv := coordinatetest.MustNew("corp.example.com/a", "v1.0.0")
	ctx := context.Background()
	for name, call := range map[string]func() error{
		"Info":          func() error { _, err := r.Info(ctx, priv); return err },
		"Download":      func() error { _, err := r.Download(ctx, priv); return err },
		"DownloadGoMod": func() error { _, err := r.DownloadGoMod(ctx, priv); return err },
	} {
		err := call()
		if !errors.Is(err, boom) || !strings.Contains(err.Error(), "matches GOPRIVATE") {
			t.Errorf("%s: err = %v, want the cache failure naming GOPRIVATE", name, err)
		}
	}
	if len(public.asked) != 0 {
		t.Errorf("the public proxy was asked %v after the cache failed", public.asked)
	}
}
