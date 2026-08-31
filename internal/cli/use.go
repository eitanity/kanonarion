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

With --json, stdout is one document instead: the destination cache, and every
selected module with its outcome — copied, already present, failed, or having no
artefact to copy. A module that failed to land is in that document rather than
on stderr, so a consumer reading stdout is not left with only the successes.

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
	tally := copySelection(ctx, selection, factStore, blobStore, modCache, logger,
		useLineWriter(stdout, jsonOut), stderr)
	writeUseSummary(tally, stderr)

	if jsonOut {
		if err := encodeJSON(stdout, useDocumentOf(coord, walk, f.recursive, modCache, tally)); err != nil {
			return err
		}
	}

	return useCopyExit(tally)
}

// useLineWriter is where the per-module lines go.
//
// Under --json stdout carries one document and nothing else, so they go
// nowhere: a "Copied ..." line in front of the document is prose a parser must
// read past, and the same modules are in the document anyway. Everything else
// about the run is unchanged, stderr included — the walk that supplied the
// bytes and the modules that did not reach the cache are stated in both modes.
func useLineWriter(stdout io.Writer, jsonMode bool) io.Writer {
	if jsonMode {
		return io.Discard
	}
	return stdout
}

// useDocument is `use --json`: what one run put in one module cache.
//
// It exists because the run's answer was split across two streams. stdout
// carried a line per module that landed and the failures went to stderr, so a
// consumer reading stdout saw only what worked and concluded the copy was
// complete. Every selected module is here, whatever became of it.
//
// The destination cache is named once, at the top. Each module says where it
// sits INSIDE it, because repeating the cache root on all 128 entries states
// one fact 128 times and still leaves the reader deriving the directory.
type useDocument struct {
	Target string `json:"target"`
	// WalkID and WalkFrame name the version set that was copied and the build it
	// answers in. The copy leaves no record of its own on disk, so a cache entry
	// carries nothing saying which walk put it there; this document and the
	// stderr line are the only places it is ever stated.
	WalkID    string `json:"walk_id"`
	WalkFrame string `json:"walk_frame"`
	// Recursive says whether the run was asked for the walk's whole closure or
	// for the target alone — the difference between a cache a build can compile
	// against and one module sitting in it.
	Recursive bool            `json:"recursive"`
	ModCache  string          `json:"mod_cache"`
	Modules   []useModuleJSON `json:"modules"`
	Counts    useCountsJSON   `json:"counts"`
}

// useModuleJSON is one selected module and what became of it.
type useModuleJSON struct {
	Module     string `json:"module"`
	Version    string `json:"version"`
	Coordinate string `json:"coordinate"`
	// Outcome is "copied", "already_present", "failed" or "no_artefact". It is
	// the axis a consumer branches on, and it is on every entry: three of the
	// four are readable from no other field, and two of them were
	// indistinguishable on stdout.
	Outcome string `json:"outcome"`
	// AlreadyPresent is the same fact as a yes/no, derived from Outcome and
	// emitted on every entry. A consumer asking whether these bytes are this
	// run's work must not have to compare a string, and must not read an absent
	// key as a no.
	AlreadyPresent bool `json:"already_present"`
	// CachePath is where the module's files are, relative to ModCache. Present
	// for the modules the cache holds; one that failed or never had an artefact
	// occupies no directory, and the field beside it says why.
	CachePath string `json:"cache_path,omitempty"`
	// Error is why a module that owed bytes did not reach the cache. It is the
	// same sentence stderr carries, on the stream a consumer reads.
	Error string `json:"error,omitempty"`
	// NoArtefactReason names what a module with nothing to copy is: a local main
	// module, the Go standard library, a require redirected by a local replace.
	// A build reads all three from somewhere other than the module cache, so
	// this is an expected absence and not a loss.
	NoArtefactReason string `json:"no_artefact_reason,omitempty"`
}

// useCountsJSON is the run as numbers, every one of them emitted.
//
// Zero is a value here. A run that copied nothing says so with a count, because
// an answer that omits what it did not find is indistinguishable from one that
// never measured it.
type useCountsJSON struct {
	// Selected is every module the run was asked about, artefact or not.
	Selected int `json:"selected"`
	// WithArtefact is how many of them own bytes in the store — the denominator
	// the run's completeness and its exit code are measured against.
	WithArtefact   int `json:"with_artefact"`
	Copied         int `json:"copied"`
	AlreadyPresent int `json:"already_present"`
	// InCache is Copied plus AlreadyPresent: how many selected modules the cache
	// holds now. It is the numerator the summary line states, and it is the
	// number a build cares about — the cache does not know which run filled it.
	InCache    int `json:"in_cache"`
	Failed     int `json:"failed"`
	NoArtefact int `json:"no_artefact"`
}

// useDocumentOf renders the run.
func useDocumentOf(target coordinate.ModuleCoordinate, walk walkdomain.WalkRecord, recursive bool,
	modCache string, t useTally,
) useDocument {
	modules := make([]useModuleJSON, 0, len(t.outcomes))
	for _, o := range t.outcomes {
		m := useModuleJSON{
			Module:         o.candidate.coord.Path(),
			Version:        o.candidate.coord.Version(),
			Coordinate:     o.candidate.coord.String(),
			Outcome:        o.kind,
			AlreadyPresent: o.kind == useAlreadyPresent,
			CachePath:      o.dir,
		}
		if o.err != nil {
			m.Error = o.err.Error()
		}
		if o.kind == useNoArtefact {
			m.NoArtefactReason = noArtefactNoun(o.candidate.source)
		}
		modules = append(modules, m)
	}
	return useDocument{
		Target:    target.String(),
		WalkID:    walk.ID,
		WalkFrame: walk.Graph.Frame().Text,
		Recursive: recursive,
		ModCache:  modCache,
		Modules:   modules,
		Counts: useCountsJSON{
			Selected:       t.selected(),
			WithArtefact:   t.copyable(),
			Copied:         len(t.of(useCopied)),
			AlreadyPresent: len(t.of(useAlreadyPresent)),
			InCache:        t.inCache(),
			Failed:         len(t.of(useFailed)),
			NoArtefact:     len(t.of(useNoArtefact)),
		},
	}
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

// What became of one selected module. Copied and already-present are kept
// apart because they answer different questions — what this run wrote, and
// what the cache holds — and stdout says the same word for both, so a caller
// reading it cannot tell a run that copied 126 modules from one that copied
// none and found them all already there.
const (
	useCopied         = "copied"
	useAlreadyPresent = "already_present"
	useFailed         = "failed"
	useNoArtefact     = "no_artefact"
)

// useOutcome is one selected module and what became of it.
type useOutcome struct {
	candidate useCandidate
	kind      string
	// dir is where the module's files sit in the destination cache, relative to
	// its root. Set for a module whose bytes are in the cache.
	dir string
	// err is why a module that owed bytes did not get them.
	err error
}

// useTally is what a run established about the cache it wrote: one outcome per
// selected module, in selection order.
//
// The kinds are kept apart because the exit code and the summary both turn on
// the difference — a module with nothing to copy is not a loss, and counting it
// as one made a complete cache report as short of its own project root on every
// project walk.
type useTally struct {
	outcomes []useOutcome
}

// of returns the outcomes of one kind, in selection order.
func (t useTally) of(kind string) []useOutcome {
	var out []useOutcome
	for _, o := range t.outcomes {
		if o.kind == kind {
			out = append(out, o)
		}
	}
	return out
}

// inCache is how many selected modules the cache holds once the run is over:
// the ones it wrote and the ones it found already there. It is the numerator
// the summary states, because a build compiling against the cache asks whether
// the module is in it, not which run put it there.
func (t useTally) inCache() int { return len(t.of(useCopied)) + len(t.of(useAlreadyPresent)) }

// copyable is the number of modules in the selection that own an artefact — the
// denominator the run's completeness is measured against.
func (t useTally) copyable() int { return t.inCache() + len(t.of(useFailed)) }

// selected is the number of modules the run was asked about, artefact or not.
func (t useTally) selected() int { return len(t.outcomes) }

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

// copySelection materialises every candidate that has an artefact and records
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
// stdout keeps carrying only the modules that are in the cache, which is the
// channel callers read as data; the document renders the same run in full.
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
			tally.outcomes = append(tally.outcomes, useOutcome{candidate: c, kind: useNoArtefact})
			continue
		}
		landed, err := copyToModCache(ctx, c.coord, factStore, blobStore, modCache, logger)
		if err != nil {
			tally.outcomes = append(tally.outcomes, useOutcome{candidate: c, kind: useFailed, err: err})
			_, _ = fmt.Fprintf(stderr, "==> use: %s did not reach the cache: %v\n", c.coord, err)
			continue
		}
		kind := useCopied
		if landed.alreadyPresent {
			kind = useAlreadyPresent
		}
		tally.outcomes = append(tally.outcomes, useOutcome{candidate: c, kind: kind, dir: landed.dir})
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
	line := fmt.Sprintf("==> use: copied %d of %d modules with a stored artefact", t.inCache(), t.copyable())
	absent := t.of(useNoArtefact)
	if len(absent) > 0 {
		line += fmt.Sprintf("; %d of %d selected have no artefact to copy (%s)",
			len(absent), t.selected(), noArtefactBreakdown(absent))
	}
	_, _ = fmt.Fprintln(stderr, line)
}

// noArtefactBreakdown renders the expected absences as "1 local main module,
// 1 Go standard library", in the order the sources are first met, so the reader
// sees what the skipped modules were rather than only how many.
func noArtefactBreakdown(absent []useOutcome) string {
	var order []walkdomain.ResolutionSource
	counts := make(map[walkdomain.ResolutionSource]int, len(absent))
	for _, o := range absent {
		src := o.candidate.source
		if _, seen := counts[src]; !seen {
			order = append(order, src)
		}
		counts[src]++
	}
	parts := make([]string, 0, len(order))
	for _, s := range order {
		parts = append(parts, fmt.Sprintf("%d %s", counts[s], noArtefactNoun(s)))
	}
	return strings.Join(parts, ", ")
}

// noArtefactNoun names what a module with nothing to copy is, in one place, so
// the summary line and the document cannot come to call it different things. An
// absence this build has no noun for is named by its raw source rather than left
// blank: the reader is told what the run met, not nothing.
func noArtefactNoun(s walkdomain.ResolutionSource) string {
	if noun := s.ArtefactAbsenceNoun(); noun != "" {
		return noun
	}
	return string(s)
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
	failed := len(t.of(useFailed))
	switch {
	case failed == 0:
		return nil
	case t.inCache() == 0:
		return &exitError{code: ExitFailed, msg: fmt.Sprintf(
			"no module reached the cache (%d of %d with a stored artefact failed to copy); nothing was materialised",
			failed, t.copyable())}
	default:
		return &exitError{code: ExitPartial, msg: fmt.Sprintf(
			"%d of %d modules with a stored artefact did not reach the cache; it is incomplete",
			failed, t.copyable())}
	}
}

// useLanding is what copying one module established: where its files are in
// the destination cache, and whether they were there before this run.
//
// The cache is a shared destination and an existing entry is left untouched, so
// "in the cache" and "put there by this run" are different facts. stdout says
// the same word for both, and only the document tells them apart.
type useLanding struct {
	// dir is the module's directory relative to the cache root, which the
	// document names once rather than repeating on every module.
	dir            string
	alreadyPresent bool
}

func copyToModCache(
	ctx context.Context,
	coord coordinate.ModuleCoordinate,
	facts ports.FactStore,
	blobs ports.BlobStore,
	modCache string,
	logger *slog.Logger,
) (useLanding, error) {
	record, ok, err := ports.ComposedFetchRecord(ctx, facts, coord)
	if err != nil {
		return useLanding{}, fmt.Errorf("getting fact record: %w", err)
	}
	if !ok {
		return useLanding{}, &exitError{code: ExitNotFound, msg: "fact record not found"}
	}

	// Paths in GOMODCACHE:
	// cache/download/[module-path]/@v/[version].{zip,mod,info,ziphash}

	// Escape module path for filesystem (Go convention: uppercase replaced by !lowercase)
	escapedPath, err := escapePath(coord.Path())
	if err != nil {
		return useLanding{}, fmt.Errorf("escaping path: %w", err)
	}

	relDir := filepath.Join("cache", "download", escapedPath, "@v")
	baseDir := filepath.Join(modCache, relDir)
	root, err := os.OpenRoot(modCache)
	if err != nil {
		return useLanding{}, fmt.Errorf("opening mod cache root: %w", err)
	}
	defer func() { _ = root.Close() }()

	if err := root.MkdirAll(relDir, 0o750); err != nil {
		return useLanding{}, fmt.Errorf("creating dir %s: %w", baseDir, err)
	}

	// 1. Copy ZIP
	zipIdentity, hasZip, err := ports.ZipIdentity(record.FactRecord)
	if err != nil {
		return useLanding{}, fmt.Errorf("deriving zip address for %s: %w", coord, err)
	}
	if !hasZip {
		return useLanding{}, fmt.Errorf("fact record for %s carries no module zip", coord)
	}
	relZipPath := filepath.Join(relDir, coord.Version()+".zip")
	// The zip is the module's bytes, so whether it was already there is what
	// makes this module already present: the files written beside it are
	// derived from the record and are written only when absent too.
	zipPresent, err := copyBlob(ctx, blobs, zipIdentity, root, relZipPath)
	if err != nil {
		return useLanding{}, fmt.Errorf("copying zip: %w", err)
	}
	landing := useLanding{dir: relDir, alreadyPresent: zipPresent}

	zipDst := filepath.Join(baseDir, coord.Version()+".zip")

	// 1b. Verify ZIP hash
	computedZipHash, err := dirhash.HashZip(zipDst, dirhash.Hash1)
	if err != nil {
		return useLanding{}, fmt.Errorf("hashing zip: %w", err)
	}
	if record.ModuleHash != computedZipHash {
		return useLanding{}, fmt.Errorf("checksum mismatch for %s zip: recorded %s, computed %s", coord, record.ModuleHash, computedZipHash)
	}

	// 2. Copy MOD
	goModIdentity, hasGoMod, err := ports.GoModIdentity(record.FactRecord)
	if err != nil {
		return useLanding{}, fmt.Errorf("deriving go.mod address for %s: %w", coord, err)
	}
	if hasGoMod {
		relModPath := filepath.Join(relDir, coord.Version()+".mod")
		if _, err := copyBlob(ctx, blobs, goModIdentity, root, relModPath); err != nil {
			return useLanding{}, fmt.Errorf("copying mod: %w", err)
		}

		// 2b. Verify MOD hash
		modBytes, err := root.ReadFile(relModPath)
		if err != nil {
			return useLanding{}, fmt.Errorf("reading copied mod: %w", err)
		}
		computedModHash, err := dirhash.Hash1([]string{"go.mod"}, func(string) (io.ReadCloser, error) {
			return io.NopCloser(bytes.NewReader(modBytes)), nil
		})
		if err != nil {
			return useLanding{}, fmt.Errorf("hashing mod: %w", err)
		}
		if record.GoModHash != computedModHash {
			return useLanding{}, fmt.Errorf("checksum mismatch for %s go.mod: recorded %s, computed %s", coord, record.GoModHash, computedModHash)
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
	if _, err := root.Stat(filepath.Join(relDir, coord.Version()+".info")); err != nil {
		if err := root.WriteFile(filepath.Join(relDir, coord.Version()+".info"), infoData, 0o600); err != nil {
			return useLanding{}, fmt.Errorf("writing info: %w", err)
		}
	}

	// 4. Create ZIPHASH
	zipHashData := fmt.Sprintf("%s %s\n", coord.Path(), record.ModuleHash)
	if _, err := root.Stat(filepath.Join(relDir, coord.Version()+".ziphash")); err != nil {
		if err := root.WriteFile(filepath.Join(relDir, coord.Version()+".ziphash"), []byte(zipHashData), 0o600); err != nil {
			return useLanding{}, fmt.Errorf("writing ziphash: %w", err)
		}
	}

	// 5. Create LOCK (empty)
	if _, err := root.Stat(filepath.Join(relDir, coord.Version()+".lock")); err != nil {
		if err := root.WriteFile(filepath.Join(relDir, coord.Version()+".lock"), nil, 0o600); err != nil {
			return useLanding{}, fmt.Errorf("writing lock: %w", err)
		}
	}

	return landing, nil
}

// copyBlob writes the blob at identity into the cache, reporting whether the
// file was already there. An existing entry is left untouched — the cache is
// shared with every build on the machine — and the answer is what separates a
// module this run wrote from one it found.
func copyBlob(ctx context.Context, blobs ports.BlobStore, identity ports.BlobIdentity, root *os.Root, relPath string) (bool, error) {
	_, err := root.Stat(relPath)
	if err == nil {
		// File already exists, skip
		return true, nil
	}

	src, err := blobs.Get(ctx, identity)
	if err != nil {
		return false, fmt.Errorf("getting blob: %w", err)
	}
	defer func() { _ = src.Close() }()

	out, err := root.Create(relPath)
	if err != nil {
		return false, fmt.Errorf("creating dst: %w", err)
	}
	defer func() { _ = out.Close() }()

	if _, err := io.Copy(out, src); err != nil {
		return false, fmt.Errorf("copying: %w", err)
	}
	return false, nil
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
