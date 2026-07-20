package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"

	"github.com/eitanity/kanonarion/internal/coordinate"

	"github.com/eitanity/kanonarion/internal/adapters/blobstore/localfs"
	factstoresqlite "github.com/eitanity/kanonarion/internal/adapters/factstore/sqlite"
	fetchapp "github.com/eitanity/kanonarion/internal/fetch/application"

	"github.com/eitanity/kanonarion/internal/fetch/ports"
	"github.com/eitanity/kanonarion/internal/sqlitestore"
	walksqlite "github.com/eitanity/kanonarion/internal/walk/adapters/walks/sqlite"
	walkports "github.com/eitanity/kanonarion/internal/walk/ports"
	"github.com/spf13/cobra"
	"golang.org/x/mod/sumdb/dirhash"
)

type useFlags struct {
	modCache  string
	recursive bool
}

func newUseCmd(stdout, stderr io.Writer) *cobra.Command {
	f := useFlags{}
	cmd := &cobra.Command{
		Use:   "use <module@version>",
		Short: "Copy walked modules from kanonarion's store to your local Go module cache",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runUse(cmd.Context(), f, args[0], stdout, stderr)
		},
	}

	cmd.Flags().StringVar(&f.modCache, "mod-cache", "", "destination Go module cache directory (defaults to GOMODCACHE or GOPATH/pkg/mod)")
	cmd.Flags().BoolVar(&f.recursive, "recursive", false, "copy dependencies as well (based on walk record)")

	return cmd
}

func runUse(ctx context.Context, f useFlags, targetArg string, stdout, stderr io.Writer) error {
	logger := buildLogger(logLevel, stderr)
	coord, err := parseCoordinate(targetArg)
	if err != nil {
		return err
	}

	dbPath := filepath.Join(storeRoot, "mirror.db")
	dbHandle, err := sqlitestore.Open(dbPath, nil)
	if err != nil {
		return fmt.Errorf("opening store: %w", err)
	}
	defer func() { _ = dbHandle.Close() }()

	walkStore := walksqlite.New(dbHandle)
	factStore := factstoresqlite.New(dbHandle)
	blobStore := localfs.New(storeRoot)

	// 1. Find the latest successful walk for this target.
	summaries, err := walkStore.ListWalks(ctx, walkports.WalkFilter{
		Target: &coord,
		Limit:  1,
	})
	if err != nil {
		return fmt.Errorf("listing walks: %w", err)
	}
	if len(summaries) == 0 {
		return fmt.Errorf("no walk record found for %s — run 'kanonarion walk' first", coord)
	}

	walk, err := walkStore.GetWalk(ctx, summaries[0].ID)
	if err != nil {
		return fmt.Errorf("getting walk %s: %w", summaries[0].ID, err)
	}

	modCache := f.modCache
	if modCache == "" {
		modCache = os.Getenv("GOMODCACHE")
		if modCache == "" {
			gopath := os.Getenv("GOPATH")
			if gopath == "" {
				home, err := os.UserHomeDir()
				if err != nil {
					return fmt.Errorf("GOMODCACHE not set and cannot find home dir")
				}
				gopath = filepath.Join(home, "go")
			}
			modCache = filepath.Join(gopath, "pkg", "mod")
		}
	}

	logger.InfoContext(ctx, "use.start",
		slog.String("target", coord.String()),
		slog.String("gomodcache", modCache),
		slog.Int("node_count", len(walk.Graph.Nodes)),
	)

	// 2. Identify modules to copy.
	var modules []coordinate.ModuleCoordinate
	if f.recursive {
		for _, node := range walk.Graph.Nodes {
			modules = append(modules, node.Coordinate)
		}
	} else {
		modules = append(modules, coord)
	}

	// Resolve the pipeline version per node from the walk's per-node
	// FetchRecord. FactStore.GetFetchRecord requires an exact pipeline-version
	// match, so the compile-time fetchapp.PipelineVersion is only safe as a
	// last-resort fallback for legacy walks predating the per-node
	// FetchRecord — using it unconditionally would hide records stored under
	// any earlier pipeline version.
	for _, m := range modules {
		pv := fetchapp.PipelineVersion
		if nr, ok := walk.PerNodeResults[m]; ok && nr.FetchRecord != nil && nr.FetchRecord.PipelineVersion != "" {
			pv = nr.FetchRecord.PipelineVersion
		}
		if err := copyToModCache(ctx, m, factStore, blobStore, modCache, pv, logger); err != nil {
			logger.WarnContext(ctx, "copy_failed",
				slog.String("module", m.String()),
				slog.String("error", err.Error()),
			)
		} else {
			_, _ = fmt.Fprintf(stdout, "Copied %s to local cache\n", m)
		}
	}

	return nil
}

func copyToModCache(
	ctx context.Context,
	coord coordinate.ModuleCoordinate,
	facts ports.FactStore,
	blobs ports.BlobStore,
	modCache string,
	pipelineVersion string,
	logger *slog.Logger,
) error {
	record, ok, err := facts.GetFetchRecord(ctx, coord, pipelineVersion)
	if err != nil {
		return fmt.Errorf("getting fact record: %w", err)
	}
	if !ok {
		return fmt.Errorf("fact record not found")
	}

	// Paths in GOMODCACHE:
	// cache/download/[module-path]/@v/[version].{zip,mod,info,ziphash}

	// Escape module path for filesystem (Go convention: uppercase replaced by !lowercase)
	escapedPath, err := escapePath(coord.Path)
	if err != nil {
		return fmt.Errorf("escaping path: %w", err)
	}

	baseDir := filepath.Join(modCache, "cache", "download", escapedPath, "@v")
	root, err := os.OpenRoot(modCache)
	if err != nil {
		return fmt.Errorf("opening mod cache root: %w", err)
	}
	defer func() { _ = root.Close() }()

	if err := root.MkdirAll(filepath.Join("cache", "download", escapedPath, "@v"), 0o750); err != nil {
		return fmt.Errorf("creating dir %s: %w", baseDir, err)
	}

	// 1. Copy ZIP
	relZipPath := filepath.Join("cache", "download", escapedPath, "@v", coord.Version+".zip")
	if err := copyBlob(ctx, blobs, ports.BlobHandle(record.ContentLocation), root, relZipPath); err != nil {
		return fmt.Errorf("copying zip: %w", err)
	}

	zipDst := filepath.Join(baseDir, coord.Version+".zip")

	// 1b. Verify ZIP hash
	computedZipHash, err := dirhash.HashZip(zipDst, dirhash.Hash1)
	if err != nil {
		return fmt.Errorf("hashing zip: %w", err)
	}
	if record.ModuleHash != computedZipHash {
		return fmt.Errorf("checksum mismatch for %s zip: recorded %s, computed %s", coord, record.ModuleHash, computedZipHash)
	}

	// 2. Copy MOD
	if record.GoModLocation != "" {
		relModPath := filepath.Join("cache", "download", escapedPath, "@v", coord.Version+".mod")
		if err := copyBlob(ctx, blobs, ports.BlobHandle(record.GoModLocation), root, relModPath); err != nil {
			return fmt.Errorf("copying mod: %w", err)
		}

		// 2b. Verify MOD hash
		modBytes, err := root.ReadFile(filepath.Join("cache", "download", escapedPath, "@v", coord.Version+".mod"))
		if err != nil {
			return fmt.Errorf("reading copied mod: %w", err)
		}
		computedModHash, err := dirhash.Hash1([]string{"go.mod"}, func(string) (io.ReadCloser, error) {
			return io.NopCloser(bytes.NewReader(modBytes)), nil
		})
		if err != nil {
			return fmt.Errorf("hashing mod: %w", err)
		}
		if record.GoModHash != computedModHash {
			return fmt.Errorf("checksum mismatch for %s go.mod: recorded %s, computed %s", coord, record.GoModHash, computedModHash)
		}
	} else {
		// Fallback for older records if any (unlikely to work without the mod file)
		logger.WarnContext(ctx, "missing_go_mod_location", slog.String("module", coord.String()))
	}

	// 3. Create INFO
	info := struct {
		Version string
		Time    string
		Origin  struct {
			VCS  string
			URL  string
			Hash string
			Ref  string
		}
	}{
		Version: coord.Version,
		Time:    record.FetchedAt.Format("2006-01-02T15:04:05Z"),
	}
	info.Origin.VCS = "git"
	info.Origin.URL = record.GitURL
	info.Origin.Hash = record.GitCommitHash
	info.Origin.Ref = record.GitRef

	infoData, _ := json.Marshal(info)
	if _, err := root.Stat(filepath.Join("cache", "download", escapedPath, "@v", coord.Version+".info")); err != nil {
		if err := root.WriteFile(filepath.Join("cache", "download", escapedPath, "@v", coord.Version+".info"), infoData, 0o600); err != nil {
			return fmt.Errorf("writing info: %w", err)
		}
	}

	// 4. Create ZIPHASH
	zipHashData := fmt.Sprintf("%s %s\n", coord.Path, record.ModuleHash)
	if _, err := root.Stat(filepath.Join("cache", "download", escapedPath, "@v", coord.Version+".ziphash")); err != nil {
		if err := root.WriteFile(filepath.Join("cache", "download", escapedPath, "@v", coord.Version+".ziphash"), []byte(zipHashData), 0o600); err != nil {
			return fmt.Errorf("writing ziphash: %w", err)
		}
	}

	// 5. Create LOCK (empty)
	if _, err := root.Stat(filepath.Join("cache", "download", escapedPath, "@v", coord.Version+".lock")); err != nil {
		if err := root.WriteFile(filepath.Join("cache", "download", escapedPath, "@v", coord.Version+".lock"), nil, 0o600); err != nil {
			return fmt.Errorf("writing lock: %w", err)
		}
	}

	return nil
}

func copyBlob(ctx context.Context, blobs ports.BlobStore, handle ports.BlobHandle, root *os.Root, relPath string) error {
	_, err := root.Stat(relPath)
	if err == nil {
		// File already exists, skip
		return nil
	}

	src, err := blobs.Get(ctx, handle)
	if err != nil {
		return fmt.Errorf("getting blob: %w", err)
	}
	defer func() { _ = src.Close() }()

	out, err := root.Create(relPath)
	if err != nil {
		return fmt.Errorf("creating dst: %w", err)
	}
	defer func() { _ = out.Close() }()

	if _, err := io.Copy(out, src); err != nil {
		return fmt.Errorf("copying: %w", err)
	}
	return nil
}

// escapePath follows Go's module path escaping rules.
func escapePath(path string) (string, error) {
	var out strings.Builder
	for _, r := range path {
		if r >= 'A' && r <= 'Z' {
			out.WriteByte('!')
			out.WriteByte(byte(r + 'a' - 'A'))
		} else {
			out.WriteRune(r)
		}
	}
	return out.String(), nil
}
