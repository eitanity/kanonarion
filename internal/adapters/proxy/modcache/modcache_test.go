package modcache

import (
	"archive/zip"
	"bytes"
	"context"
	"io"
	"os"
	"path/filepath"
	"testing"

	domain2 "github.com/eitanity/kanonarion/internal/fetch/domain"
	"golang.org/x/mod/sumdb/dirhash"
)

func newCoord(t *testing.T, path, version string) domain2.ModuleCoordinate {
	t.Helper()
	c, err := domain2.NewModuleCoordinate(path, version)
	if err != nil {
		t.Fatalf("NewModuleCoordinate: %v", err)
	}
	return c
}

// buildModuleZip returns a minimal but valid module zip for coord, containing a
// single go.mod entry under the canonical module@version/ prefix.
func buildModuleZip(t *testing.T, coord domain2.ModuleCoordinate, goMod []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	w, err := zw.Create(coord.Path + "@" + coord.Version + "/go.mod")
	if err != nil {
		t.Fatalf("zip create: %v", err)
	}
	if _, err := w.Write(goMod); err != nil {
		t.Fatalf("zip write: %v", err)
	}
	if err := zw.Close(); err != nil {
		t.Fatalf("zip close: %v", err)
	}
	return buf.Bytes()
}

func seedEntry(t *testing.T, dir string, coord domain2.ModuleCoordinate, ext string, content []byte) string {
	t.Helper()
	base := filepath.Join(dir, "cache", "download", filepath.FromSlash(coord.Path), "@v")
	if err := os.MkdirAll(base, 0o750); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	path := filepath.Join(base, coord.Version+ext)
	if err := os.WriteFile(path, content, 0o600); err != nil {
		t.Fatalf("write %s: %v", ext, err)
	}
	return path
}

func TestInfo_ReadsCacheInfo(t *testing.T) {
	dir := t.TempDir()
	coord := newCoord(t, "github.com/example/mod", "v1.2.3")
	seedEntry(t, dir, coord, ".info", []byte(`{"Version":"v1.2.3","Time":"2024-01-02T03:04:05Z"}`))

	p := New(dir, "", "", nil)
	info, err := p.Info(context.Background(), coord)
	if err != nil {
		t.Fatalf("Info: %v", err)
	}
	if info.Version != "v1.2.3" {
		t.Errorf("Version = %q, want v1.2.3", info.Version)
	}
	if info.Origin != nil {
		t.Errorf("Origin = %+v, want nil (no VCS provenance in modcache mode)", info.Origin)
	}
}

func TestDownload_ComputesHashesFromBytes(t *testing.T) {
	dir := t.TempDir()
	coord := newCoord(t, "github.com/example/mod", "v1.2.3")
	goMod := []byte("module github.com/example/mod\n\ngo 1.21\n")
	zipBytes := buildModuleZip(t, coord, goMod)
	zipPath := seedEntry(t, dir, coord, ".zip", zipBytes)
	seedEntry(t, dir, coord, ".mod", goMod)

	p := New(dir, "", "", nil)
	dl, err := p.Download(context.Background(), coord)
	if err != nil {
		t.Fatalf("Download: %v", err)
	}
	defer func() { _ = dl.Zip.Close(); _ = dl.GoMod.Close() }()

	// Zip hash must match dirhash's own computation over the same file.
	wantZip, err := dirhash.HashZip(zipPath, dirhash.Hash1)
	if err != nil {
		t.Fatalf("dirhash.HashZip: %v", err)
	}
	if dl.ZipHash.String() != wantZip {
		t.Errorf("ZipHash = %q, want %q", dl.ZipHash, wantZip)
	}

	wantMod, err := dirhash.Hash1([]string{"go.mod"}, func(string) (io.ReadCloser, error) {
		return io.NopCloser(bytes.NewReader(goMod)), nil
	})
	if err != nil {
		t.Fatalf("dirhash.Hash1: %v", err)
	}
	if dl.GoModHash.String() != wantMod {
		t.Errorf("GoModHash = %q, want %q", dl.GoModHash, wantMod)
	}

	gotMod, _ := io.ReadAll(dl.GoMod)
	if !bytes.Equal(gotMod, goMod) {
		t.Errorf("returned go.mod bytes = %q, want %q", gotMod, goMod)
	}
}

func TestDownload_CacheMissInvokesGoAndReportsFailure(t *testing.T) {
	dir := t.TempDir()
	coord := newCoord(t, "github.com/example/mod", "v1.2.3")
	// Nothing seeded → cache miss → download shells out. Point goBinary at a
	// command that always fails so the miss path is exercised offline and the
	// error is surfaced (not swallowed).
	p := New(dir, "/bin/false", t.TempDir(), nil)
	_, err := p.Download(context.Background(), coord)
	if err == nil {
		t.Fatalf("Download on a cache miss with a failing go binary: want error, got nil")
	}
}

func TestDownload_InvalidZipErrors(t *testing.T) {
	dir := t.TempDir()
	coord := newCoord(t, "github.com/example/mod", "v1.2.3")
	seedEntry(t, dir, coord, ".mod", []byte("module github.com/example/mod\n"))
	seedEntry(t, dir, coord, ".zip", []byte("this is not a zip archive"))
	p := New(dir, "", "", nil)
	if _, err := p.Download(context.Background(), coord); err == nil {
		t.Fatalf("Download on an invalid zip: want error, got nil")
	}
}

func TestInfo_EmptyVersionFallsBackToCoordinate(t *testing.T) {
	dir := t.TempDir()
	coord := newCoord(t, "github.com/example/mod", "v1.2.3")
	seedEntry(t, dir, coord, ".info", []byte(`{"Time":"2024-01-02T03:04:05Z"}`))
	p := New(dir, "", "", nil)
	info, err := p.Info(context.Background(), coord)
	if err != nil {
		t.Fatalf("Info: %v", err)
	}
	if info.Version != coord.Version {
		t.Errorf("Version = %q, want fallback to coordinate version %q", info.Version, coord.Version)
	}
}

func TestInfo_InvalidJSONErrors(t *testing.T) {
	dir := t.TempDir()
	coord := newCoord(t, "github.com/example/mod", "v1.2.3")
	seedEntry(t, dir, coord, ".info", []byte("not-json"))
	p := New(dir, "", "", nil)
	if _, err := p.Info(context.Background(), coord); err == nil {
		t.Fatalf("Info on invalid JSON: want error, got nil")
	}
}
