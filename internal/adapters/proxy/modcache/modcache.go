// Package modcache implements ports.ModuleProxy against a local Go module cache
// ($GOMODCACHE) instead of a network module proxy. It is the proxy adapter used
// in --from-modcache mode.
//
// The module cache stores the module-proxy protocol on disk:
//
//	$GOMODCACHE/cache/download/<escapedPath>/@v/<escapedVersion>.{info,mod,zip}
//
// Info and Download read those files directly and compute h1 hashes from the
// bytes, exactly as the direct (network) proxy does. When an entry is missing —
// which should not happen after a build has populated the cache — the adapter
// shells out to `go mod download` to fetch it into the cache, then re-reads.
// No bytes are ever fetched over kanonarion's own HTTP client.
package modcache

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"time"

	domain2 "github.com/eitanity/kanonarion/internal/fetch/domain"
	"github.com/eitanity/kanonarion/internal/fetch/ports"
	"golang.org/x/mod/module"
	"golang.org/x/mod/sumdb/dirhash"
)

// maxZipBytes matches Go's own limit for module zips (500 MB).
const maxZipBytes = 500 << 20

// Proxy is the module-cache-backed proxy adapter.
type Proxy struct {
	dir        string // GOMODCACHE root
	goBinary   string // resolved via PATH when empty
	projectDir string // directory holding go.mod; the cwd for `go mod download`
	logger     *slog.Logger
}

var _ ports.ModuleProxy = (*Proxy)(nil)

// New constructs a module-cache proxy rooted at dir. goBinary may be empty (the
// adapter then uses "go" from PATH). projectDir is the module directory used as
// the working directory for any `go mod download` fallback; it may be empty, in
// which case the fallback runs in the process working directory.
func New(dir, goBinary, projectDir string, logger *slog.Logger) *Proxy {
	if logger == nil {
		logger = slog.Default()
	}
	return &Proxy{dir: dir, goBinary: goBinary, projectDir: projectDir, logger: logger}
}

// Info returns the .info metadata for a module version, fetching it into the
// cache first if absent. Origin is always nil: VCS provenance is not tracked in
// module-cache mode.
func (p *Proxy) Info(ctx context.Context, coord domain2.ModuleCoordinate) (ports.ModuleInfo, error) {
	base, err := p.entryBase(coord)
	if err != nil {
		return ports.ModuleInfo{}, err
	}
	data, err := p.readOrDownload(ctx, coord, base+".info")
	if err != nil {
		return ports.ModuleInfo{}, fmt.Errorf("reading module-cache info for %s: %w", coord, err)
	}
	var raw struct {
		Version string    `json:"Version"`
		Time    time.Time `json:"Time"`
	}
	if err := json.Unmarshal(data, &raw); err != nil {
		return ports.ModuleInfo{}, fmt.Errorf("decoding module-cache info for %s: %w", coord, err)
	}
	version := raw.Version
	if version == "" {
		version = coord.Version
	}
	return ports.ModuleInfo{Version: version, Time: raw.Time}, nil
}

// Download reads the module zip and go.mod from the cache (fetching them first
// if absent) and returns them with h1 hashes computed from the bytes.
func (p *Proxy) Download(ctx context.Context, coord domain2.ModuleCoordinate) (ports.ModuleDownload, error) {
	base, err := p.entryBase(coord)
	if err != nil {
		return ports.ModuleDownload{}, err
	}

	goModBytes, err := p.readOrDownload(ctx, coord, base+".mod")
	if err != nil {
		return ports.ModuleDownload{}, fmt.Errorf("reading module-cache go.mod for %s: %w", coord, err)
	}
	goModHashStr, err := dirhash.Hash1([]string{"go.mod"}, func(string) (io.ReadCloser, error) {
		return io.NopCloser(bytes.NewReader(goModBytes)), nil
	})
	if err != nil {
		return ports.ModuleDownload{}, fmt.Errorf("computing go.mod hash for %s: %w", coord, err)
	}
	goModHash, err := domain2.ParseModuleHash(goModHashStr)
	if err != nil {
		return ports.ModuleDownload{}, fmt.Errorf("parsing go.mod hash for %s: %w", coord, err)
	}

	zipBytes, err := p.readOrDownload(ctx, coord, base+".zip")
	if err != nil {
		return ports.ModuleDownload{}, fmt.Errorf("reading module-cache zip for %s: %w", coord, err)
	}
	if int64(len(zipBytes)) > maxZipBytes {
		return ports.ModuleDownload{}, fmt.Errorf("module zip for %s exceeds %d MB limit", coord, maxZipBytes>>20)
	}
	zipHashStr, err := hashZipBytes(zipBytes)
	if err != nil {
		return ports.ModuleDownload{}, fmt.Errorf("computing zip hash for %s: %w", coord, err)
	}
	zipHash, err := domain2.ParseModuleHash(zipHashStr)
	if err != nil {
		return ports.ModuleDownload{}, fmt.Errorf("parsing zip hash for %s: %w", coord, err)
	}

	return ports.ModuleDownload{
		Zip:       io.NopCloser(bytes.NewReader(zipBytes)),
		GoMod:     io.NopCloser(bytes.NewReader(goModBytes)),
		ZipHash:   zipHash,
		GoModHash: goModHash,
	}, nil
}

// entryBase returns the "@v/<version>" path prefix for a coordinate inside the
// module cache. Callers append the entry suffix (.info, .mod, .zip).
func (p *Proxy) entryBase(coord domain2.ModuleCoordinate) (string, error) {
	escapedPath, err := module.EscapePath(coord.Path)
	if err != nil {
		return "", fmt.Errorf("escaping module path %q: %w", coord.Path, err)
	}
	escapedVersion, err := module.EscapeVersion(coord.Version)
	if err != nil {
		return "", fmt.Errorf("escaping module version %q: %w", coord.Version, err)
	}
	return filepath.Join(p.dir, "cache", "download", filepath.FromSlash(escapedPath), "@v", escapedVersion), nil
}

// readOrDownload reads path from the cache. On a cache miss it runs
// `go mod download` for the coordinate — populating the cache and verifying
// against go.sum — then reads again.
func (p *Proxy) readOrDownload(ctx context.Context, coord domain2.ModuleCoordinate, path string) ([]byte, error) {
	data, err := os.ReadFile(path) // #nosec G304 -- path derived from an escaped module coordinate under the cache dir
	if err == nil {
		return data, nil
	}
	if !os.IsNotExist(err) {
		return nil, fmt.Errorf("reading %s: %w", path, err)
	}
	if derr := p.download(ctx, coord); derr != nil {
		return nil, derr
	}
	data, err = os.ReadFile(path) // #nosec G304 -- path derived from an escaped module coordinate under the cache dir
	if err != nil {
		return nil, fmt.Errorf("reading %s after download: %w", path, err)
	}
	return data, nil
}

// download shells out to `go mod download` to populate the module cache with
// the coordinate. GOMODCACHE is pinned to the adapter's cache directory so the
// download lands where the reads expect it.
func (p *Proxy) download(ctx context.Context, coord domain2.ModuleCoordinate) error {
	goBin := p.goBinary
	if goBin == "" {
		goBin = "go"
	}
	arg := coord.Path + "@" + coord.Version
	p.logger.InfoContext(ctx, "modcache_go_mod_download", slog.String("module", arg))
	cmd := exec.CommandContext(ctx, goBin, "mod", "download", arg) // #nosec G204 -- goBin is operator-configured; arg is a validated coordinate
	cmd.Dir = p.projectDir
	cmd.Env = append(os.Environ(), "GOMODCACHE="+p.dir)
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("go mod download %s: %w: %s", arg, err, bytes.TrimSpace(out))
	}
	return nil
}

// hashZipBytes computes the h1 hash of a module zip's contents using the
// canonical dirhash algorithm. The result matches go.sum entries.
func hashZipBytes(data []byte) (string, error) {
	zr, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		return "", fmt.Errorf("opening zip: %w", err)
	}
	files := make([]string, len(zr.File))
	byName := make(map[string]*zip.File, len(zr.File))
	for i, f := range zr.File {
		files[i] = f.Name
		byName[f.Name] = f
	}
	hash, err := dirhash.Hash1(files, func(name string) (io.ReadCloser, error) {
		f := byName[name]
		if f == nil {
			return nil, fmt.Errorf("file %q not in zip", name)
		}
		return f.Open()
	})
	if err != nil {
		return "", fmt.Errorf("hashing zip contents: %w", err)
	}
	return hash, nil
}
