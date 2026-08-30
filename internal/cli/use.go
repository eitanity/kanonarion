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

	"github.com/eitanity/kanonarion/internal/adapters/goenv"
	"github.com/eitanity/kanonarion/internal/adapters/sqlitestore"
	"github.com/eitanity/kanonarion/internal/fetch/ports"
	walksqlite "github.com/eitanity/kanonarion/internal/walk/adapters/walks/sqlite"
	walkdomain "github.com/eitanity/kanonarion/internal/walk/domain"
	walkports "github.com/eitanity/kanonarion/internal/walk/ports"
	"github.com/spf13/cobra"
	"golang.org/x/mod/sumdb/dirhash"
)

type useFlags struct {
	modCache  string
	recursive bool
	walkID    string
}

func newUseCmd(stdout, stderr io.Writer) *cobra.Command {
	f := useFlags{}
	cmd := &cobra.Command{
		Use: "use <module@version>",
		Annotations: map[string]string{
			annotationStoreIntent: StoreIntentRead,
			annotationNetworkUse:  NetworkNever,
		},
		Short: "Copy walked modules from kanonarion's store to your local Go module cache",
		Long: `Copies the version set of one walk of <module>@<version> out of the store
and into a Go module cache a later go build can compile against.

stdout carries one line per module that landed, and nothing else. The walk that
supplied the bytes, any module that failed to land, and a copied-of-total
summary go to stderr.

Some selected nodes have no artefact anywhere in the store and never will: a
project walk's own root at @local, the standard library, and a require
redirected by a local replace. A build reads all three from somewhere other than
the module cache, so they are counted apart, named in the summary, and do not
make the run report a loss.

Exit codes:
  0  every module with a stored artefact reached the cache (including when
     there was nothing to copy)
  1  some, but not all, reached it — the cache is incomplete and the message
     says how many of how many
  2  nothing reached the cache, though at least one module had an artefact
  4  no walk record for the target, or a --walk-id the store does not hold
  20 bad invocation, or a --walk-id rooted at a different target`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runUse(cmd.Context(), f, args[0], stdout, stderr)
		},
	}

	cmd.Flags().StringVar(&f.modCache, "mod-cache", "", "destination Go module cache directory (defaults to GOMODCACHE or GOPATH/pkg/mod)")
	cmd.Flags().BoolVar(&f.recursive, "recursive", false, "copy dependencies as well (based on walk record)")
	cmd.Flags().StringVar(&f.walkID, "walk-id", "", "copy the version set of this walk instead of the one the default rule picks")

	return cmd
}

// useTargetWalk selects the walk `use` will copy from, and is the seam its miss
// is exercisable through: the command opens the store itself, so the branch that
// answers a module which has never been walked would otherwise need a live one.
//
// The walk is the version set that lands on disk. `use --recursive` copies every
// node of it into a module cache a later `go build` compiles against, so picking
// the wrong walk of a target that has several is not a wrong answer the caller
// can re-run — it is the wrong bytes, sitting in a cache, with nothing on them
// saying which walk put them there. So the walk is either the one the caller
// pinned with --walk-id, or one picked by the shared rule, and the copy names it
// either way.
func useTargetWalk(ctx context.Context, walks QueryWalksUseCase, coord coordinate.ModuleCoordinate,
	walkID string, stderr io.Writer,
) (walkdomain.WalkRecord, error) {
	if walkID != "" {
		rec, err := resolvePinnedWalk(ctx, walks, walkID, coord)
		if err != nil {
			return walkdomain.WalkRecord{}, err
		}
		useWalkProvenance(pinnedWalkChoice(rec), stderr)
		return rec, nil
	}
	summaries, err := walks.ListWalks(ctx, walkports.WalkFilter{Target: &coord})
	if err != nil {
		return walkdomain.WalkRecord{}, fmt.Errorf("listing walks: %w", err)
	}
	if len(summaries) == 0 {
		return walkdomain.WalkRecord{}, walkTargetMiss(ctx, walks, coord, stderr)
	}
	choice := chooseWalk(ctx, walks, summaries, "")
	rec, err := choice.walkRecord(ctx, walks)
	if err != nil {
		return walkdomain.WalkRecord{}, err
	}
	useWalkProvenance(choice, stderr)
	return rec, nil
}

// useWalkProvenance writes, to stderr, which walk supplied the bytes and — when
// there was more than one to choose from — which rule chose it and how to pin
// another. It goes on stderr because stdout carries the list of modules copied.
//
// The walk is named on every run, not only when a choice was made: the copy
// leaves no record of its own on disk, so the run's output is the only place the
// provenance of the cache entries is ever stated.
func useWalkProvenance(choice walkChoice, stderr io.Writer) {
	_, _ = fmt.Fprintf(stderr, "==> use: copying the version set of walk %s (frame %s)\n",
		choice.summary.ID, choice.summary.BuildFrame())
	if note := choice.statement(); note != "" {
		_, _ = fmt.Fprint(stderr, note)
	}
}

func runUse(ctx context.Context, f useFlags, targetArg string, stdout, stderr io.Writer) error {
	logger := buildLogger(logLevel, stderr)
	coord, err := parseCoordinate(targetArg)
	if err != nil {
		return err
	}

	dbPath := filepath.Join(storeRoot, "mirror.db")
	// `use` rewrites the caller's go.mod from a stored walk; it records nothing,
	// so it reads the store and does not bring one into existence.
	dbHandle, err := sqlitestore.Open(dbPath, nil, sqlitestore.IntentRead)
	if err != nil {
		return fmt.Errorf("opening store: %w", err)
	}
	defer func() { _ = dbHandle.Close() }()

	walkStore := walksqlite.New(dbHandle)
	factStore := factstoresqlite.New(dbHandle)
	blobStore := localfs.New(storeRoot)

	// 1. Find the walk whose version set is copied.
	walk, err := useTargetWalk(ctx, walkStore, coord, f.walkID, stderr)
	if err != nil {
		return err
	}

	modCache := f.modCache
	if modCache == "" {
		modCache = goenv.Value("GOMODCACHE")
		if modCache == "" {
			gopath := goenv.Value("GOPATH")
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
	selection := useSelection(walk, coord, f.recursive)

	// No pipeline version is resolved per node any more. This command used to dig
	// the version out of the walk's per-node FetchRecord and fall back to the
	// compile-time fetch version for walks predating it — a workaround for the
	// version-keyed read, kept correct by hand. The composed read asks the ledger
	// what it has measured about each artefact, so the workaround and its
	// last-resort fallback both go.
	tally := copySelection(ctx, selection, factStore, blobStore, modCache, logger, stdout, stderr)
	writeUseSummary(tally, stderr)

	return useCopyExit(tally)
}

// useCandidate is one module a run was asked to put in the cache, carried
// alongside the walk node's resolution source. The source is what separates a
// coordinate that never had bytes from one whose bytes should be in the store,
// and it is only knowable from the walk — the coordinate of a local replace is
// the original require and looks like any other published module.
type useCandidate struct {
	coord  coordinate.ModuleCoordinate
	source walkdomain.ResolutionSource
}

// useFailure is a module that should have reached the cache and did not.
type useFailure struct {
	coord coordinate.ModuleCoordinate
	err   error
}

// useTally is what a run established about the cache it wrote: which modules
// landed, which ones failed to, and which ones were never going to because the
// coordinate has no artefact behind it. The three are kept apart because the
// exit code and the summary both turn on the difference — a module with nothing
// to copy is not a loss, and counting it as one made a complete cache report as
// short of its own project root on every project walk.
type useTally struct {
	copied     []coordinate.ModuleCoordinate
	failed     []useFailure
	noArtefact []useCandidate
}

// copyable is the number of modules in the selection that own an artefact — the
// denominator the run's completeness is measured against.
func (t useTally) copyable() int { return len(t.copied) + len(t.failed) }

// selected is the number of modules the run was asked about, artefact or not.
func (t useTally) selected() int { return t.copyable() + len(t.noArtefact) }

// useSelection lists the modules one run copies, each with the resolution
// source the walk recorded for it. With --recursive that is every node of the
// walk's graph; otherwise it is the named target alone, looked up in the graph
// so it carries its source too. A target the graph does not name falls back to
// ResolutionTarget, which owns an artefact — the run then behaves as it did
// before, reporting a missing record as a failure.
func useSelection(walk walkdomain.WalkRecord, target coordinate.ModuleCoordinate, recursive bool) []useCandidate {
	if recursive {
		out := make([]useCandidate, 0, len(walk.Graph.Nodes))
		for _, node := range walk.Graph.Nodes {
			out = append(out, useCandidate{coord: node.Coordinate, source: node.ResolutionSource})
		}
		return out
	}
	for _, node := range walk.Graph.Nodes {
		if node.Coordinate == target {
			return []useCandidate{{coord: target, source: node.ResolutionSource}}
		}
	}
	return []useCandidate{{coord: target, source: walkdomain.ResolutionTarget}}
}

// copySelection materialises every candidate that has an artefact and tallies
// what happened to each one.
//
// A candidate with no artefact is not attempted and is not a failure: the
// lookup for it can only miss, so attempting it produced a copy_failed warning
// for a project's own root and for the standard library on every recursive run,
// and those warnings were indistinguishable from a module whose bytes have gone
// missing from the blob store.
//
// A genuine failure is named on stderr as it happens. It used to be a WARN in
// the log stream and nothing else, which is the whole defect: the run knows
// which module did not land and why, and a caller reading the exit code learned
// none of it. The WARN is not kept alongside the plain line — one failure said
// twice is noise, and 126 of them said twice is a wall.
//
// stdout keeps carrying only the modules that did land, which is the channel
// callers read as data.
func copySelection(
	ctx context.Context,
	selection []useCandidate,
	factStore ports.FactStore,
	blobStore ports.BlobStore,
	modCache string,
	logger *slog.Logger,
	stdout, stderr io.Writer,
) useTally {
	var tally useTally
	for _, c := range selection {
		if !c.source.HasFetchedArtefact() {
			tally.noArtefact = append(tally.noArtefact, c)
			continue
		}
		if err := copyToModCache(ctx, c.coord, factStore, blobStore, modCache, logger); err != nil {
			tally.failed = append(tally.failed, useFailure{coord: c.coord, err: err})
			_, _ = fmt.Fprintf(stderr, "==> use: %s did not reach the cache: %v\n", c.coord, err)
			continue
		}
		tally.copied = append(tally.copied, c.coord)
		_, _ = fmt.Fprintf(stdout, "Copied %s to local cache\n", c.coord)
	}
	return tally
}

// writeUseSummary states copied-of-copyable on stderr, and names what had no
// artefact when anything did.
//
// It goes on stderr beside the walk provenance for the same reason that does:
// stdout is the list of modules that landed, and a caller reading it as data
// must not have to filter a report out of it. The line is written on every run,
// including a complete one — a caller that only ever sees output when something
// is wrong cannot tell a complete run from a run that produced no output at all.
func writeUseSummary(t useTally, stderr io.Writer) {
	line := fmt.Sprintf("==> use: copied %d of %d modules with a stored artefact", len(t.copied), t.copyable())
	if len(t.noArtefact) > 0 {
		line += fmt.Sprintf("; %d of %d selected have no artefact to copy (%s)",
			len(t.noArtefact), t.selected(), noArtefactBreakdown(t.noArtefact))
	}
	_, _ = fmt.Fprintln(stderr, line)
}

// noArtefactBreakdown renders the expected absences as "1 local main module,
// 1 Go standard library", in the order the sources are first met, so the reader
// sees what the skipped modules were rather than only how many.
func noArtefactBreakdown(absent []useCandidate) string {
	var order []walkdomain.ResolutionSource
	counts := make(map[walkdomain.ResolutionSource]int, len(absent))
	for _, c := range absent {
		if _, seen := counts[c.source]; !seen {
			order = append(order, c.source)
		}
		counts[c.source]++
	}
	parts := make([]string, 0, len(order))
	for _, s := range order {
		noun := s.ArtefactAbsenceNoun()
		if noun == "" {
			noun = string(s)
		}
		parts = append(parts, fmt.Sprintf("%d %s", counts[s], noun))
	}
	return strings.Join(parts, ", ")
}

// useCopyExit maps what the run established about the cache onto the process
// exit code, on the same principle vuln-scan's coverage exit follows: the code
// says whether the work completed, measured against what the run could have
// done, not against what it was handed.
//
// The denominator is the modules that own an artefact. A project walk selects
// its own local root and the standard library, neither of which has bytes to
// copy; failing the run for them would fail every project walk, and the cache
// would be complete regardless — a build reads the root from the working tree
// and the standard library from the toolchain.
//
// Nothing to copy is exit 0. The run is not incomplete; there was nothing owed.
func useCopyExit(t useTally) error {
	switch {
	case len(t.failed) == 0:
		return nil
	case len(t.copied) == 0:
		return &exitError{code: ExitFailed, msg: fmt.Sprintf(
			"no module reached the cache (%d of %d with a stored artefact failed to copy); nothing was materialised",
			len(t.failed), t.copyable())}
	default:
		return &exitError{code: ExitPartial, msg: fmt.Sprintf(
			"%d of %d modules with a stored artefact did not reach the cache; it is incomplete",
			len(t.failed), t.copyable())}
	}
}

func copyToModCache(
	ctx context.Context,
	coord coordinate.ModuleCoordinate,
	facts ports.FactStore,
	blobs ports.BlobStore,
	modCache string,
	logger *slog.Logger,
) error {
	record, ok, err := ports.ComposedFetchRecord(ctx, facts, coord)
	if err != nil {
		return fmt.Errorf("getting fact record: %w", err)
	}
	if !ok {
		return &exitError{code: ExitNotFound, msg: "fact record not found"}
	}

	// Paths in GOMODCACHE:
	// cache/download/[module-path]/@v/[version].{zip,mod,info,ziphash}

	// Escape module path for filesystem (Go convention: uppercase replaced by !lowercase)
	escapedPath, err := escapePath(coord.Path())
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
	zipIdentity, hasZip, err := ports.ZipIdentity(record.FactRecord)
	if err != nil {
		return fmt.Errorf("deriving zip address for %s: %w", coord, err)
	}
	if !hasZip {
		return fmt.Errorf("fact record for %s carries no module zip", coord)
	}
	relZipPath := filepath.Join("cache", "download", escapedPath, "@v", coord.Version()+".zip")
	if err := copyBlob(ctx, blobs, zipIdentity, root, relZipPath); err != nil {
		return fmt.Errorf("copying zip: %w", err)
	}

	zipDst := filepath.Join(baseDir, coord.Version()+".zip")

	// 1b. Verify ZIP hash
	computedZipHash, err := dirhash.HashZip(zipDst, dirhash.Hash1)
	if err != nil {
		return fmt.Errorf("hashing zip: %w", err)
	}
	if record.ModuleHash != computedZipHash {
		return fmt.Errorf("checksum mismatch for %s zip: recorded %s, computed %s", coord, record.ModuleHash, computedZipHash)
	}

	// 2. Copy MOD
	goModIdentity, hasGoMod, err := ports.GoModIdentity(record.FactRecord)
	if err != nil {
		return fmt.Errorf("deriving go.mod address for %s: %w", coord, err)
	}
	if hasGoMod {
		relModPath := filepath.Join("cache", "download", escapedPath, "@v", coord.Version()+".mod")
		if err := copyBlob(ctx, blobs, goModIdentity, root, relModPath); err != nil {
			return fmt.Errorf("copying mod: %w", err)
		}

		// 2b. Verify MOD hash
		modBytes, err := root.ReadFile(filepath.Join("cache", "download", escapedPath, "@v", coord.Version()+".mod"))
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
		Version: coord.Version(),
		Time:    record.FirstFetchedAt.Format("2006-01-02T15:04:05Z"),
	}
	info.Origin.VCS = "git"
	info.Origin.URL = record.GitURL
	info.Origin.Hash = record.GitCommitHash
	info.Origin.Ref = record.GitRef

	infoData, _ := json.Marshal(info)
	if _, err := root.Stat(filepath.Join("cache", "download", escapedPath, "@v", coord.Version()+".info")); err != nil {
		if err := root.WriteFile(filepath.Join("cache", "download", escapedPath, "@v", coord.Version()+".info"), infoData, 0o600); err != nil {
			return fmt.Errorf("writing info: %w", err)
		}
	}

	// 4. Create ZIPHASH
	zipHashData := fmt.Sprintf("%s %s\n", coord.Path(), record.ModuleHash)
	if _, err := root.Stat(filepath.Join("cache", "download", escapedPath, "@v", coord.Version()+".ziphash")); err != nil {
		if err := root.WriteFile(filepath.Join("cache", "download", escapedPath, "@v", coord.Version()+".ziphash"), []byte(zipHashData), 0o600); err != nil {
			return fmt.Errorf("writing ziphash: %w", err)
		}
	}

	// 5. Create LOCK (empty)
	if _, err := root.Stat(filepath.Join("cache", "download", escapedPath, "@v", coord.Version()+".lock")); err != nil {
		if err := root.WriteFile(filepath.Join("cache", "download", escapedPath, "@v", coord.Version()+".lock"), nil, 0o600); err != nil {
			return fmt.Errorf("writing lock: %w", err)
		}
	}

	return nil
}

func copyBlob(ctx context.Context, blobs ports.BlobStore, identity ports.BlobIdentity, root *os.Root, relPath string) error {
	_, err := root.Stat(relPath)
	if err == nil {
		// File already exists, skip
		return nil
	}

	src, err := blobs.Get(ctx, identity)
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
