// Package localfs provides a walk adapter that implements
// walkports.LocalModuleFetcher by creating FactRecords from local filesystem
// source trees instead of fetching from a module proxy. It is used when a
// go.mod replace directive points to an on-disk directory and local-replace
// analysis has been enabled.
package localfs

import (
	"archive/zip"
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/eitanity/kanonarion/internal/adapters/ziparchive"
	"github.com/eitanity/kanonarion/internal/coordinate"
	fetchdomain "github.com/eitanity/kanonarion/internal/fetch/domain"
	fetchports "github.com/eitanity/kanonarion/internal/fetch/ports"
	walkports "github.com/eitanity/kanonarion/internal/walk/ports"
	"golang.org/x/mod/module"
	"golang.org/x/mod/sumdb/dirhash"
	modzip "golang.org/x/mod/zip"
)

// PipelineVersion identifies the local-FS fetch pipeline. Bump when the
// ingestion logic changes such that cached records would differ on re-ingestion.
const PipelineVersion = "local-0.1.0"

// Fetcher creates FactRecords from local filesystem Go module source trees.
// It implements walkports.LocalModuleFetcher.
type Fetcher struct {
	blobs fetchports.BlobStore
	facts fetchports.FactStore
	clock fetchports.Clock
}

// New constructs a Fetcher backed by the given infrastructure.
func New(blobs fetchports.BlobStore, facts fetchports.FactStore, clock fetchports.Clock) *Fetcher {
	return &Fetcher{blobs: blobs, facts: facts, clock: clock}
}

// EnsureFetchedFromPath ingests the Go module rooted at absPath as coord.
// It creates a module-spec zip, hashes it, stores both the zip and the
// go.mod in the BlobStore, and persists a FactRecord in the FactStore.
// Results are cached: a second call with the same coord and PipelineVersion
// returns the stored record without re-reading the filesystem.
//
// Exception: a coordinate at the synthetic local version (the project-walk
// root) is never served from cache. The working tree mutates between runs, so
// a cached snapshot would be stale; the tree is re-read and the stored record
// overwritten on every call. Local-replace targets keep their pinned semver
// coordinates and remain cacheable.
func (f *Fetcher) EnsureFetchedFromPath(
	ctx context.Context,
	coord coordinate.ModuleCoordinate,
	absPath string,
) (walkports.LocalModuleFetchResult, error) {
	if !coord.IsLocal() {
		existing, ok, err := f.facts.GetFetchRecord(ctx, coord, PipelineVersion)
		if err != nil {
			return walkports.LocalModuleFetchResult{}, fmt.Errorf("checking cache for %s: %w", coord, err)
		}
		if ok {
			return walkports.LocalModuleFetchResult{Record: existing, FromCache: true}, nil
		}
	}

	goModData, err := os.ReadFile(filepath.Join(absPath, "go.mod")) /* #nosec G304 -- absPath supplied by trusted caller */
	if err != nil {
		return walkports.LocalModuleFetchResult{}, fmt.Errorf("reading go.mod from %q: %w", absPath, err)
	}

	// modzip insists on a canonical semver, which the synthetic local version
	// is not. Zip the project root under a placeholder version, then rewrite
	// the entry prefix back to the local coordinate so every zip consumer can
	// keep deriving the prefix from the coordinate.
	zipVersion := coord.Version()
	if coord.IsLocal() {
		placeholder, perr := localZipPlaceholderVersion(coord.Path())
		if perr != nil {
			return walkports.LocalModuleFetchResult{}, fmt.Errorf("choosing a zip version for %s: %w", coord, perr)
		}
		zipVersion = placeholder
	}
	mv := module.Version{Path: coord.Path(), Version: zipVersion}
	var zipBuf bytes.Buffer
	if err := modzip.CreateFromDir(&zipBuf, mv, absPath); err != nil {
		return walkports.LocalModuleFetchResult{}, fmt.Errorf("creating zip from %q: %w", absPath, err)
	}
	zipData := zipBuf.Bytes()
	if coord.IsLocal() {
		rewritten, err := rewriteZipPrefix(zipData,
			coord.Path()+"@"+zipVersion+"/",
			coord.Path()+"@"+coord.Version()+"/",
		)
		if err != nil {
			return walkports.LocalModuleFetchResult{}, fmt.Errorf("rewriting zip prefix for %s: %w", coord, err)
		}
		zipData = rewritten
	}

	zipHashStr, err := ziparchive.HashModuleZip(zipData)
	if err != nil {
		return walkports.LocalModuleFetchResult{}, fmt.Errorf("hashing local zip for %s: %w", coord, err)
	}
	zipHash, err := fetchdomain.ParseModuleHash(zipHashStr)
	if err != nil {
		return walkports.LocalModuleFetchResult{}, fmt.Errorf("parsing zip hash for %s: %w", coord, err)
	}

	goModHashStr, err := hashGoMod(goModData)
	if err != nil {
		return walkports.LocalModuleFetchResult{}, fmt.Errorf("hashing go.mod for %s: %w", coord, err)
	}
	goModHash, err := fetchdomain.ParseModuleHash(goModHashStr)
	if err != nil {
		return walkports.LocalModuleFetchResult{}, fmt.Errorf("parsing go.mod hash for %s: %w", coord, err)
	}

	zipIdentity, err := fetchports.NewBlobIdentity(fetchports.BlobKindZip, zipHash)
	if err != nil {
		return walkports.LocalModuleFetchResult{}, fmt.Errorf("addressing zip blob for %s: %w", coord, err)
	}
	if err := f.blobs.Put(ctx, zipIdentity, bytes.NewReader(zipData)); err != nil {
		return walkports.LocalModuleFetchResult{}, fmt.Errorf("storing zip blob for %s: %w", coord, err)
	}
	goModIdentity, err := fetchports.NewBlobIdentity(fetchports.BlobKindGoMod, goModHash)
	if err != nil {
		return walkports.LocalModuleFetchResult{}, fmt.Errorf("addressing go.mod blob for %s: %w", coord, err)
	}
	if err := f.blobs.Put(ctx, goModIdentity, bytes.NewReader(goModData)); err != nil {
		return walkports.LocalModuleFetchResult{}, fmt.Errorf("storing go.mod blob for %s: %w", coord, err)
	}

	m := fetchdomain.FetchedModule{
		Coordinate:         coord,
		ModuleHash:         zipHash,
		GoModHash:          goModHash,
		VerificationStatus: fetchdomain.LocalSource,
		// A directory has no go.sum entry by construction — the toolchain
		// writes a checksum for a module it downloads, never for one it reads
		// off disk — so the absence is stated rather than left to look like a
		// check that passed. Nothing verified this tree; that is the fact.
		VerificationDetail: "local filesystem path: " + absPath +
			"; no checksum is available for a filesystem source, so none was checked",
		FetchedAt:       f.clock.Now().UTC(),
		PipelineVersion: PipelineVersion,
		ContentLocation: zipIdentity.String(),
		GoModLocation:   goModIdentity.String(),
		AcquisitionMode: fetchdomain.AcquisitionLocal,
		MeasurementKind: fetchdomain.MeasurementAcquired,
	}
	sealed, err := fetchdomain.Seal(m)
	if err != nil {
		return walkports.LocalModuleFetchResult{}, fmt.Errorf("sealing local measurement of %s: %w", coord, err)
	}
	if err := f.facts.PutFetchRecord(ctx, sealed); err != nil {
		return walkports.LocalModuleFetchResult{}, fmt.Errorf("appending fact record for %s: %w", coord, err)
	}
	composed, err := fetchdomain.Compose([]fetchdomain.FactRecord{sealed.Record()})
	if err != nil {
		return walkports.LocalModuleFetchResult{}, fmt.Errorf("composing local measurement of %s: %w", coord, err)
	}
	return walkports.LocalModuleFetchResult{Record: composed, FromCache: false}, nil
}

// localZipPlaceholderVersion returns the canonical semver under which the
// project-walk root is zipped before its entry prefix is rewritten to the
// synthetic local version.
//
// The version cannot be a constant. modzip validates the path/version pair
// before it writes anything, and Go requires a path carrying a major-version
// suffix to carry a version of that major: github.com/caddyserver/caddy/v2 at
// v0.0.0 is rejected, so a fixed v0.0.0 could only ever serve paths at major 0
// or 1. The major is read off the path with the toolchain's own splitter rather
// than a hand-rolled one, because gopkg.in spells the major as a dot on the
// last element (gopkg.in/yaml.v3) rather than a slash-separated element, and a
// "/vN" parser would build a path that cannot exist.
//
// This is the intermediate zip only. The entry prefix is rewritten to the
// synthetic local coordinate immediately afterwards, so no stored coordinate
// and no record shape depends on which placeholder was chosen.
func localZipPlaceholderVersion(modulePath string) (string, error) {
	_, pathMajor, ok := module.SplitPathVersion(modulePath)
	if !ok {
		return "", fmt.Errorf("module path %q is not a valid module path", modulePath)
	}
	if pathMajor == "" {
		// Majors 0 and 1 share the unsuffixed path, and v0.0.0 satisfies both.
		return "v0.0.0", nil
	}
	// pathMajor is the suffix with its separator: "/v2", or ".v3" for gopkg.in.
	version := pathMajor[1:] + ".0.0"
	if err := module.Check(modulePath, version); err != nil {
		return "", fmt.Errorf("placeholder %s does not agree with module path %q: %w", version, modulePath, err)
	}
	return version, nil
}

// rewriteZipPrefix re-writes a module zip, renaming every entry that starts
// with oldPrefix to start with newPrefix instead. Entries are recompressed;
// the input order is preserved.
func rewriteZipPrefix(data []byte, oldPrefix, newPrefix string) ([]byte, error) {
	zr, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		return nil, fmt.Errorf("opening zip: %w", err)
	}
	var out bytes.Buffer
	zw := zip.NewWriter(&out)
	for _, f := range zr.File {
		name := f.Name
		if rest, ok := strings.CutPrefix(name, oldPrefix); ok {
			name = newPrefix + rest
		}
		w, werr := zw.Create(name)
		if werr != nil {
			return nil, fmt.Errorf("creating zip entry %q: %w", name, werr)
		}
		r, rerr := f.Open()
		if rerr != nil {
			return nil, fmt.Errorf("opening zip entry %q: %w", f.Name, rerr)
		}
		if _, cerr := io.Copy(w, r); cerr != nil { /* #nosec G110 -- local source tree supplied by trusted caller */
			_ = r.Close()
			return nil, fmt.Errorf("copying zip entry %q: %w", f.Name, cerr)
		}
		if cerr := r.Close(); cerr != nil {
			return nil, fmt.Errorf("closing zip entry %q: %w", f.Name, cerr)
		}
	}
	if err := zw.Close(); err != nil {
		return nil, fmt.Errorf("closing zip: %w", err)
	}
	return out.Bytes(), nil
}

// hashGoMod computes the h1 dirhash of a go.mod file, matching the hash
// format the Go proxy/checksum database uses for standalone go.mod entries.
func hashGoMod(data []byte) (string, error) {
	h, err := dirhash.Hash1([]string{"go.mod"}, func(string) (io.ReadCloser, error) {
		return io.NopCloser(bytes.NewReader(data)), nil
	})
	if err != nil {
		return "", fmt.Errorf("hashing go.mod: %w", err)
	}
	return h, nil
}
