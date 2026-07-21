package modcache

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/eitanity/kanonarion/internal/coordinate"

	fetchports "github.com/eitanity/kanonarion/internal/fetch/ports"
	"golang.org/x/mod/modfile"
	"golang.org/x/mod/module"
)

// CoordinateFailure names a single coordinate that could not be populated and
// the reason. It exists so a best-effort batch can still account for every
// coordinate it failed to write rather than discarding the reason.
type CoordinateFailure struct {
	Coordinate coordinate.ModuleCoordinate
	Err        error
}

// Report is the outcome of a cache population: how many coordinates were
// written and, for each one that was not, why. A caller must be able to tell a
// populate that wrote everything from one that wrote nothing, so Requested is
// carried alongside Written rather than left for the caller to recompute from
// its input slice — the two counts are only equal when Failures is empty.
type Report struct {
	Requested int
	Written   int
	Failures  []CoordinateFailure
}

// Complete reports whether every requested coordinate was written.
func (r Report) Complete() bool { return len(r.Failures) == 0 }

// FailureSummary renders up to max failures as "coord: err" strings, with a
// trailing "+N more" when the list is longer. It bounds what a caller puts in a
// log line without hiding the true failure count.
func (r Report) FailureSummary(max int) string {
	if len(r.Failures) == 0 {
		return ""
	}
	shown := r.Failures
	overflow := 0
	if max > 0 && len(shown) > max {
		overflow = len(shown) - max
		shown = shown[:max]
	}
	parts := make([]string, 0, len(shown)+1)
	for _, f := range shown {
		parts = append(parts, fmt.Sprintf("%s: %v", f.Coordinate, f.Err))
	}
	if overflow > 0 {
		parts = append(parts, fmt.Sprintf("+%d more", overflow))
	}
	return strings.Join(parts, "; ")
}

// Populate writes module metadata for each coordinate into a GOMODCACHE-compatible
// directory layout. Zip and go.mod blobs are symlinked to avoid duplicating data
// from the blob store; if symlinking fails (cross-filesystem or Windows without
// privileges) the blob is copied instead. Small metadata files (.info,.ziphash,
// .lock) are always written directly.
//
// Population is best-effort: a coordinate that cannot be written (no fact
// record, unreadable blob) does not abort the batch, because a partially
// populated cache still spares the toolchain most of its network fetches. It is
// not silent, though — every such coordinate is returned in the Report's
// Failures with the reason, so a caller can state what actually reached the
// cache instead of assuming its whole input did.
func Populate(
	ctx context.Context,
	facts fetchports.FactStore,
	blobs fetchports.BlobStore,
	cacheDir string,
	coords []coordinate.ModuleCoordinate,
	pipelineVersion string,
) Report {
	report := Report{Requested: len(coords)}
	for _, coord := range coords {
		if err := populateOne(ctx, facts, blobs, cacheDir, coord, pipelineVersion); err != nil {
			report.Failures = append(report.Failures, CoordinateFailure{Coordinate: coord, Err: err})
			continue
		}
		report.Written++
	}
	return report
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
// blob, are skipped rather than failing the whole populate — an incomplete
// cache degrades to the toolchain resolving that one version elsewhere. Each
// skip is reported in the Report's Failures: under GOPROXY=off "elsewhere" does
// not exist, so a missing entry is the difference between a module that resolves
// and one that does not, and the caller must be able to name it.
func PopulateGoMod(
	ctx context.Context,
	facts fetchports.FactStore,
	blobs fetchports.BlobStore,
	cacheDir string,
	coords []coordinate.ModuleCoordinate,
	pipelineVersion string,
) Report {
	report := Report{Requested: len(coords)}
	for _, coord := range coords {
		if err := populateGoModOne(ctx, facts, blobs, cacheDir, coord, pipelineVersion); err != nil {
			report.Failures = append(report.Failures, CoordinateFailure{Coordinate: coord, Err: err})
			continue
		}
		report.Written++
	}
	return report
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

// PopulateGoModClosure writes the go.mod of every seed coordinate and then, to a
// fixpoint, the go.mod of every requirement those go.mod files introduce that is
// not already in the cache.
//
// One level is not enough. A pre-pruning (go<1.17) main module makes the
// toolchain load the complete module graph, and that load is transitive over
// go.mod files: reading a superseded requirement's go.mod introduces that
// version's own requirements, which must themselves be readable, and so on.
// Those deeper versions appear on no edge of the walk graph — the walk records
// the requirements of selected versions only — so they cannot be discovered by
// inspecting the graph. They are discovered here, by reading each go.mod as it
// lands in the cache and following what it requires.
//
// Only go.mod files are written, never zips: these versions are read for module
// graph arithmetic and never compiled. A coordinate whose go.mod is already
// present (written by Populate for a selected version, or earlier in this walk)
// is not rewritten, but its requirements are still followed, so the closure is
// complete regardless of the order coordinates are reached in.
//
// ensure, when non-nil, is called with each newly discovered batch before it is
// written, so a caller can fetch coordinates its fact store is missing. The
// returned Report accounts for every coordinate the closure reached.
func PopulateGoModClosure(
	ctx context.Context,
	facts fetchports.FactStore,
	blobs fetchports.BlobStore,
	cacheDir string,
	seeds []coordinate.ModuleCoordinate,
	pipelineVersion string,
	ensure func(context.Context, []coordinate.ModuleCoordinate),
) Report {
	var report Report
	seen := make(map[coordinate.ModuleCoordinate]struct{}, len(seeds))
	queue := make([]coordinate.ModuleCoordinate, 0, len(seeds))
	for _, c := range seeds {
		if _, dup := seen[c]; dup {
			continue
		}
		seen[c] = struct{}{}
		queue = append(queue, c)
	}

	for len(queue) > 0 {
		batch := queue
		queue = nil

		// A coordinate already in the cache needs no fetch; asking for it would
		// be a pointless proxy round-trip on every walk.
		missing := make([]coordinate.ModuleCoordinate, 0, len(batch))
		for _, coord := range batch {
			if present, err := goModInCache(cacheDir, coord); err == nil && !present {
				missing = append(missing, coord)
			}
		}
		if ensure != nil && len(missing) > 0 {
			ensure(ctx, missing)
		}

		for _, coord := range batch {
			report.Requested++
			modPath, err := writeGoModEntry(ctx, facts, blobs, cacheDir, coord, pipelineVersion)
			if err != nil {
				report.Failures = append(report.Failures, CoordinateFailure{Coordinate: coord, Err: err})
				continue
			}
			report.Written++

			// Follow what this go.mod requires. A parse failure is reported
			// rather than swallowed: it means the closure below this coordinate
			// is unexplored, which is exactly the kind of hole that later shows
			// up as an unexplained offline resolution failure.
			requires, err := goModRequirements(modPath)
			if err != nil {
				report.Failures = append(report.Failures, CoordinateFailure{
					Coordinate: coord,
					Err:        fmt.Errorf("reading requirements (closure below this version unexplored): %w", err),
				})
				continue
			}
			for _, req := range requires {
				if _, dup := seen[req]; dup {
					continue
				}
				seen[req] = struct{}{}
				queue = append(queue, req)
			}
		}
	}
	return report
}

// writeGoModEntry writes a coordinate's go.mod (plus .info and .lock) into the
// cache and returns the path to the written .mod. When the entry is already
// present the existing path is returned without a rewrite.
func writeGoModEntry(
	ctx context.Context,
	facts fetchports.FactStore,
	blobs fetchports.BlobStore,
	cacheDir string,
	coord coordinate.ModuleCoordinate,
	pipelineVersion string,
) (string, error) {
	base, err := cacheEntryPath(cacheDir, coord)
	if err != nil {
		return "", err
	}
	if _, statErr := os.Lstat(base + ".mod"); statErr == nil {
		return base + ".mod", nil
	}
	if err := populateGoModOne(ctx, facts, blobs, cacheDir, coord, pipelineVersion); err != nil {
		return "", err
	}
	return base + ".mod", nil
}

// goModInCache reports whether a coordinate's go.mod is already written.
func goModInCache(cacheDir string, coord coordinate.ModuleCoordinate) (bool, error) {
	base, err := cacheEntryPath(cacheDir, coord)
	if err != nil {
		return false, err
	}
	if _, err := os.Lstat(base + ".mod"); err != nil {
		return false, nil //nolint:nilerr // absence is the answer, not an error
	}
	return true, nil
}

// goModRequirements parses a go.mod file and returns its required module
// versions. Both direct and indirect requirements are returned: the full module
// graph load reads every version named in a require directive, regardless of
// which block it sits in or whether it is marked indirect.
func goModRequirements(modPath string) ([]coordinate.ModuleCoordinate, error) {
	data, err := os.ReadFile(modPath) /* #nosec G304 -- path built from a module coordinate inside the cache dir */
	if err != nil {
		return nil, fmt.Errorf("reading go.mod: %w", err)
	}
	f, err := modfile.Parse(modPath, data, nil)
	if err != nil {
		return nil, fmt.Errorf("parsing go.mod: %w", err)
	}
	out := make([]coordinate.ModuleCoordinate, 0, len(f.Require))
	for _, req := range f.Require {
		if req == nil || req.Mod.Path == "" || req.Mod.Version == "" {
			continue
		}
		out = append(out, coordinate.ModuleCoordinate{Path: req.Mod.Path, Version: req.Mod.Version})
	}
	return out, nil
}

// cacheEntryBase returns the "@v/<version>" path prefix for a coordinate inside
// a GOMODCACHE-layout directory, creating the parent directory. Callers append
// the entry suffix (.zip, .mod, .info, …).
func cacheEntryBase(cacheDir string, coord coordinate.ModuleCoordinate) (string, error) {
	base, err := cacheEntryPath(cacheDir, coord)
	if err != nil {
		return "", err
	}
	if err := os.MkdirAll(filepath.Dir(base), 0o750); err != nil {
		return "", fmt.Errorf("creating cache dir: %w", err)
	}
	return base, nil
}

// cacheEntryPath is cacheEntryBase without the directory creation, for callers
// that only need to test whether an entry is already present.
func cacheEntryPath(cacheDir string, coord coordinate.ModuleCoordinate) (string, error) {
	escapedPath, err := module.EscapePath(coord.Path)
	if err != nil {
		return "", fmt.Errorf("escaping module path %q: %w", coord.Path, err)
	}
	escapedVersion, err := module.EscapeVersion(coord.Version)
	if err != nil {
		return "", fmt.Errorf("escaping module version %q: %w", coord.Version, err)
	}
	versionDir := filepath.Join(cacheDir, "cache", "download", filepath.FromSlash(escapedPath), "@v")
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
