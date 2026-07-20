package modcache

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/eitanity/kanonarion/internal/coordinate"

	fetchports "github.com/eitanity/kanonarion/internal/fetch/ports"
	"golang.org/x/mod/module"
)

// Populate writes module metadata for each coordinate into a GOMODCACHE-compatible
// directory layout. Zip and go.mod blobs are symlinked to avoid duplicating data
// from the blob store; if symlinking fails (cross-filesystem or Windows without
// privileges) the blob is copied instead. Small metadata files (.info,.ziphash,
// .lock) are always written directly.
//
// Modules whose fact record is not found are silently skipped — govulncheck will
// fall back to downloading them from the network if needed.
func Populate(
	ctx context.Context,
	facts fetchports.FactStore,
	blobs fetchports.BlobStore,
	cacheDir string,
	coords []coordinate.ModuleCoordinate,
	pipelineVersion string,
) error {
	for _, coord := range coords {
		// Best-effort: skip modules we can't populate.
		_ = populateOne(ctx, facts, blobs, cacheDir, coord, pipelineVersion)
	}
	return nil
}

func populateOne(
	ctx context.Context,
	facts fetchports.FactStore,
	blobs fetchports.BlobStore,
	cacheDir string,
	coord coordinate.ModuleCoordinate,
	pipelineVersion string,
) error {
	record, ok, err := facts.GetFetchRecord(ctx, coord, pipelineVersion)
	if err != nil {
		return fmt.Errorf("getting fact record for %s: %w", coord, err)
	}
	if !ok {
		return fmt.Errorf("fact record not found for %s", coord)
	}

	base, err := cacheEntryBase(cacheDir, coord)
	if err != nil {
		return err
	}

	// Zip and go.mod — symlink first, fall back to copy.
	if err := linkOrCopy(ctx, blobs, fetchports.BlobHandle(record.ContentLocation), base+".zip"); err != nil {
		return fmt.Errorf("writing zip: %w", err)
	}
	if record.GoModLocation != "" {
		if err := linkOrCopy(ctx, blobs, fetchports.BlobHandle(record.GoModLocation), base+".mod"); err != nil {
			return fmt.Errorf("writing mod: %w", err)
		}
	}

	if err := writeInfo(base, coord.Version, record.FetchedAt); err != nil {
		return err
	}

	// .ziphash — h1: hash of the zip, used by the Go tool to avoid re-hashing.
	if err := writeIfAbsent(base+".ziphash", []byte(record.ModuleHash+"\n")); err != nil {
		return fmt.Errorf("writing ziphash: %w", err)
	}

	// .lock — empty sentinel required by the Go module cache protocol.
	if err := writeIfAbsent(base+".lock", nil); err != nil {
		return fmt.Errorf("writing lock: %w", err)
	}

	return nil
}

// PopulateGoMod writes only the go.mod entry (plus its .info and .lock
// siblings) for each coordinate — never the zip. It exists for the superseded
// intermediate versions that MVS reads to rebuild the module graph but never
// compiles: their go.mod is enough for version comparison, and fetching or
// writing their (potentially large) zips would be wasted work. Coordinates
// whose fact record is missing, or whose record carries no standalone go.mod
// blob, are silently skipped — an incomplete cache degrades to the toolchain
// resolving that one version elsewhere, it does not fail the whole populate.
func PopulateGoMod(
	ctx context.Context,
	facts fetchports.FactStore,
	blobs fetchports.BlobStore,
	cacheDir string,
	coords []coordinate.ModuleCoordinate,
	pipelineVersion string,
) error {
	for _, coord := range coords {
		_ = populateGoModOne(ctx, facts, blobs, cacheDir, coord, pipelineVersion)
	}
	return nil
}

func populateGoModOne(
	ctx context.Context,
	facts fetchports.FactStore,
	blobs fetchports.BlobStore,
	cacheDir string,
	coord coordinate.ModuleCoordinate,
	pipelineVersion string,
) error {
	record, ok, err := facts.GetFetchRecord(ctx, coord, pipelineVersion)
	if err != nil {
		return fmt.Errorf("getting fact record for %s: %w", coord, err)
	}
	if !ok {
		return fmt.Errorf("fact record not found for %s", coord)
	}
	if record.GoModLocation == "" {
		return fmt.Errorf("no standalone go.mod blob for %s", coord)
	}

	base, err := cacheEntryBase(cacheDir, coord)
	if err != nil {
		return err
	}

	if err := linkOrCopy(ctx, blobs, fetchports.BlobHandle(record.GoModLocation), base+".mod"); err != nil {
		return fmt.Errorf("writing mod: %w", err)
	}
	if err := writeInfo(base, coord.Version, record.FetchedAt); err != nil {
		return err
	}
	// .lock — empty sentinel required by the Go module cache protocol.
	if err := writeIfAbsent(base+".lock", nil); err != nil {
		return fmt.Errorf("writing lock: %w", err)
	}
	return nil
}

// cacheEntryBase returns the "@v/<version>" path prefix for a coordinate inside
// a GOMODCACHE-layout directory, creating the parent directory. Callers append
// the entry suffix (.zip, .mod, .info, …).
func cacheEntryBase(cacheDir string, coord coordinate.ModuleCoordinate) (string, error) {
	escapedPath, err := module.EscapePath(coord.Path)
	if err != nil {
		return "", fmt.Errorf("escaping module path %q: %w", coord.Path, err)
	}
	escapedVersion, err := module.EscapeVersion(coord.Version)
	if err != nil {
		return "", fmt.Errorf("escaping module version %q: %w", coord.Version, err)
	}
	versionDir := filepath.Join(cacheDir, "cache", "download", filepath.FromSlash(escapedPath), "@v")
	if err := os.MkdirAll(versionDir, 0o750); err != nil {
		return "", fmt.Errorf("creating cache dir: %w", err)
	}
	return filepath.Join(versionDir, escapedVersion), nil
}

// writeInfo writes the small .info JSON sidecar (version + fetch time) the Go
// tool reads for a cached module version.
func writeInfo(base, version string, fetchedAt time.Time) error {
	type infoFile struct {
		Version string    `json:"Version"`
		Time    time.Time `json:"Time"`
	}
	infoData, _ := json.Marshal(infoFile{Version: version, Time: fetchedAt.UTC()})
	if err := writeIfAbsent(base+".info", infoData); err != nil {
		return fmt.Errorf("writing info: %w", err)
	}
	return nil
}

// linkOrCopy creates dst as a symlink to the blob's on-disk path. If the store
// does not expose a path or os.Symlink fails, the blob content is copied instead.
func linkOrCopy(ctx context.Context, blobs fetchports.BlobStore, h fetchports.BlobHandle, dst string) error {
	if _, err := os.Lstat(dst); err == nil {
		return nil // already present
	}

	if opt, ok := blobs.(fetchports.BlobPathOptimizer); ok {
		if src, err := opt.GetPath(ctx, h); err == nil {
			if err := os.Symlink(src, dst); err == nil {
				return nil
			}
		}
	}

	rc, err := blobs.Get(ctx, h)
	if err != nil {
		return fmt.Errorf("reading blob: %w", err)
	}
	defer func() { _ = rc.Close() }()

	f, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600) /* #nosec G304 -- path constructed from module coordinate, not user input */
	if err != nil {
		return fmt.Errorf("creating dst file: %w", err)
	}
	defer func() { _ = f.Close() }()

	if _, err := io.Copy(f, rc); err != nil {
		return fmt.Errorf("copying blob content: %w", err)
	}
	return nil
}

func writeIfAbsent(path string, data []byte) error {
	if _, err := os.Lstat(path); err == nil {
		return nil
	}
	if err := os.WriteFile(path, data, 0o600); err != nil { /* #nosec G306 -- module cache files are user-readable only */
		return fmt.Errorf("writing module cache file %q: %w", path, err)
	}
	return nil
}
