package cli

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/eitanity/kanonarion/internal/coordinate"
)

// -- proxy seam fakes --

type fakeLatest struct {
	coord coordinate.ModuleCoordinate
	err   error
}

func (f fakeLatest) Latest(_ context.Context, _ string) (coordinate.ModuleCoordinate, error) {
	return f.coord, f.err
}

type fakeVersions struct {
	versions []string
	err      error
}

func (f fakeVersions) ListVersions(_ context.Context, _ string) ([]string, error) {
	return f.versions, f.err
}

// -- resolveLatest --

func TestResolveLatest_Success(t *testing.T) {
	want := coordinate.ModuleCoordinate{Path: "example.com/m", Version: "v1.2.3"}
	var stderr bytes.Buffer

	got, err := resolveLatest(context.Background(), "example.com/m", fakeLatest{coord: want}, &stderr)
	if err != nil {
		t.Fatalf("resolveLatest: %v", err)
	}
	if got != want {
		t.Errorf("want %+v, got %+v", want, got)
	}
	// The resolution must be reported to stderr so the user sees the pin.
	if !strings.Contains(stderr.String(), "resolved example.com/m@latest → v1.2.3") {
		t.Errorf("stderr missing resolution notice: %q", stderr.String())
	}
}

func TestResolveLatest_ProxyError(t *testing.T) {
	sentinel := errors.New("proxy down")
	var stderr bytes.Buffer

	_, err := resolveLatest(context.Background(), "example.com/m", fakeLatest{err: sentinel}, &stderr)
	if err == nil {
		t.Fatal("expected error when the proxy fails")
	}
	if !errors.Is(err, sentinel) {
		t.Errorf("error should wrap the proxy error, got: %v", err)
	}
	if stderr.Len() != 0 {
		t.Errorf("no resolution should be printed on failure, got: %q", stderr.String())
	}
}

// -- runListVersions --

func TestRunListVersions_Empty(t *testing.T) {
	var stdout bytes.Buffer
	if err := runListVersions(context.Background(), "example.com/m", false, fakeVersions{}, &stdout); err != nil {
		t.Fatalf("runListVersions: %v", err)
	}
	if !strings.Contains(stdout.String(), "no versions found for example.com/m") {
		t.Errorf("empty branch missing notice: %q", stdout.String())
	}
}

func TestRunListVersions_PlainList(t *testing.T) {
	var stdout bytes.Buffer
	vs := fakeVersions{versions: []string{"v1.1.0", "v1.0.0"}}
	if err := runListVersions(context.Background(), "example.com/m", false, vs, &stdout); err != nil {
		t.Fatalf("runListVersions: %v", err)
	}
	got := stdout.String()
	if strings.HasPrefix(strings.TrimSpace(got), "[") {
		t.Errorf("plain mode should not emit JSON: %q", got)
	}
	for _, v := range vs.versions {
		if !strings.Contains(got, v) {
			t.Errorf("output missing version %q: %q", v, got)
		}
	}
}

func TestRunListVersions_JSON(t *testing.T) {
	var stdout bytes.Buffer
	vs := fakeVersions{versions: []string{"v1.1.0", "v1.0.0"}}
	if err := runListVersions(context.Background(), "example.com/m", true, vs, &stdout); err != nil {
		t.Fatalf("runListVersions: %v", err)
	}
	got := strings.TrimSpace(stdout.String())
	if !strings.HasPrefix(got, "[") || !strings.HasSuffix(got, "]") {
		t.Errorf("JSON mode should emit an array: %q", got)
	}
	for _, v := range vs.versions {
		if !strings.Contains(got, v) {
			t.Errorf("JSON output missing version %q: %q", v, got)
		}
	}
}

func TestRunListVersions_ProxyError(t *testing.T) {
	sentinel := errors.New("proxy down")
	var stdout bytes.Buffer
	err := runListVersions(context.Background(), "example.com/m", false, fakeVersions{err: sentinel}, &stdout)
	if err == nil {
		t.Fatal("expected error when the proxy fails")
	}
	if !errors.Is(err, sentinel) {
		t.Errorf("error should wrap the proxy error, got: %v", err)
	}
}

// -- resolveCoordForInspect (non-network branches) --

func TestResolveCoordForInspect_PinnedVersion(t *testing.T) {
	var stderr bytes.Buffer
	got, err := resolveCoordForInspect(context.Background(), "example.com/m@v1.0.0", "", "", &stderr)
	if err != nil {
		t.Fatalf("resolveCoordForInspect: %v", err)
	}
	want := coordinate.ModuleCoordinate{Path: "example.com/m", Version: "v1.0.0"}
	if got != want {
		t.Errorf("want %+v, got %+v", want, got)
	}
	if stderr.Len() != 0 {
		t.Errorf("a pinned version needs no proxy resolution, but stderr got: %q", stderr.String())
	}
}

func TestResolveCoordForInspect_ParseError(t *testing.T) {
	var stderr bytes.Buffer
	if _, err := resolveCoordForInspect(context.Background(), "", "", "", &stderr); err == nil {
		t.Fatal("expected error for an empty module argument")
	} else if !strings.Contains(err.Error(), "invalid argument") {
		t.Errorf("unexpected error: %v", err)
	}
}
