package cgchild

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"syscall"

	"code.eitanity.com/kanonarion/internal/adapters/childproc"
	"code.eitanity.com/kanonarion/internal/adapters/clock"
	"code.eitanity.com/kanonarion/internal/adapters/goenv"
	"code.eitanity.com/kanonarion/internal/adapters/interrupt"
	"code.eitanity.com/kanonarion/internal/adapters/recordseal"
	"code.eitanity.com/kanonarion/internal/adapters/sqlitestore"
	cganalyser "code.eitanity.com/kanonarion/internal/callgraph/adapters/analyser/staticcha"
	cgmodulecache "code.eitanity.com/kanonarion/internal/callgraph/adapters/modulecache"
	cgapp "code.eitanity.com/kanonarion/internal/callgraph/application"
	cgdomain "code.eitanity.com/kanonarion/internal/callgraph/domain"
	cgports "code.eitanity.com/kanonarion/internal/callgraph/ports"
	"code.eitanity.com/kanonarion/internal/composition"
	"code.eitanity.com/kanonarion/internal/composition/storage"
	sqlitestorage "code.eitanity.com/kanonarion/internal/composition/storage/sqlite"
	"code.eitanity.com/kanonarion/internal/coordinate"
	"code.eitanity.com/kanonarion/internal/exitcode"
	fetchports "code.eitanity.com/kanonarion/internal/fetch/ports"
	vulnfetch "code.eitanity.com/kanonarion/internal/vuln/adapters/fetch"
)

// Args is a call-graph child's command line, parsed.
type Args struct {
	Coordinate   string
	Narrate      bool
	Force        bool
	FromWalk     string
	StoreRoot    string
	FromModcache string
	Config       string
}

// Parse reads the argv a parent starts the child with: ChildCommand, one
// coordinate, and flags from cgports.ChildFlags as --name, --name=value or
// --name value. Anything else is refused.
func Parse(args []string) (Args, error) {
	if len(args) == 0 || args[0] != cgports.ChildCommand {
		return Args{}, fmt.Errorf("the call-graph child serves only %q, not %q", cgports.ChildCommand, args)
	}
	var out Args
	values := map[string]*string{
		cgports.ChildFlagFromWalk: &out.FromWalk, cgports.ChildFlagStoreRoot: &out.StoreRoot,
		cgports.ChildFlagFromModcache: &out.FromModcache, cgports.ChildFlagConfig: &out.Config,
	}
	bools := map[string]*bool{cgports.ChildFlagNarrate: &out.Narrate, cgports.ChildFlagForce: &out.Force}
	var positional []string
	for i := 1; i < len(args); i++ {
		a := args[i]
		name, ok := strings.CutPrefix(a, "--")
		if !ok || name == "" {
			positional = append(positional, a)
			continue
		}
		name, value, hasValue := strings.Cut(name, "=")
		if b, isBool := bools[name]; isBool {
			switch {
			case !hasValue || value == "true":
				*b = true
			case value == "false":
				*b = false
			default:
				return Args{}, fmt.Errorf("--%s takes no value, got %q", name, value)
			}
			continue
		}
		v, known := values[name]
		if !known {
			return Args{}, fmt.Errorf("the call-graph child takes no flag --%s", name)
		}
		if !hasValue {
			if i+1 >= len(args) {
				return Args{}, fmt.Errorf("--%s needs a value", name)
			}
			i++
			value = args[i]
		}
		*v = value
	}
	if len(positional) != 1 {
		return Args{}, fmt.Errorf("the call-graph child takes one <module>@<version>, got %q", positional)
	}
	out.Coordinate = positional[0]
	return out, nil
}

// Serve runs the call-graph child an importing application serves and returns
// its exit code: it opens the store the parent named, through the backend its
// configuration selects among this process's registrations, extracts the
// coordinate's call graph there, and exits as the kanonarion binary's
// callgraph command does. Errors are printed to stderr, where the parent
// reads them.
func Serve(args []string, stdout, stderr io.Writer) int {
	_ = stdout
	a, err := Parse(args)
	if err != nil {
		return report(err, stderr)
	}
	// A ceiling the parent set is adopted before anything runs, so an analysis
	// that cannot fit says so and stops instead of being taken by the kernel.
	childproc.EnforceMemoryCeiling(os.Getenv, stderr, func() { os.Exit(exitcode.Failed) })
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM, syscall.SIGHUP)
	defer stop()
	sqlitestore.ResetRetries()
	interrupt.Reset()
	defer func() {
		// The parent folds this child's lock waits into its own count.
		if notice := sqlitestore.ContentionNotice(sqlitestore.Retries()); notice != "" {
			_, _ = fmt.Fprint(stderr, notice)
		}
	}()
	refused := &refusals{}
	err = surfaceRefusal(run(ctx, a, refused, stderr), refused)
	if err != nil && ctx.Err() != nil && !errors.Is(err, fetchports.ErrBlobTampered) {
		_, _ = fmt.Fprintln(stderr, interrupt.Statement(context.Cause(ctx)))
		return exitcode.Cancelled
	}
	return report(err, stderr)
}

// report prints err as the binary does and returns the exit code it maps to.
func report(err error, stderr io.Writer) int {
	if err == nil {
		return exitcode.OK
	}
	_, _ = fmt.Fprintf(stderr, "error: %v\n", err)
	return exitcode.Of(err, nil)
}

func run(ctx context.Context, a Args, refused *refusals, stderr io.Writer) (retErr error) {
	if a.FromModcache != "" {
		return &exitcode.Error{Code: exitcode.Config, Msg: "--" + cgports.ChildFlagFromModcache +
			" is served by the kanonarion binary only: an application's call-graph child reads module bytes through its storage backend"}
	}
	coord, err := parseCoordinate(a.Coordinate)
	if err != nil {
		return err
	}
	root := storeRoot(a.StoreRoot)
	cfgPath := a.Config
	if cfgPath == "" {
		cfgPath = os.Getenv("KANONARION_CONFIG")
	}
	if cfgPath == "" {
		cfgPath = filepath.Join(root, "config.yaml")
	}
	cfg, err := composition.LoadConfigFile(ctx, cfgPath)
	if err != nil {
		return &exitcode.Error{Code: exitcode.Config, Msg: err.Error()}
	}
	recordseal.SetStoreLocation(sqlitestorage.DatabasePath(root))
	logger := NewLogger(cfg.Preferences.LogLevel, cfg.Preferences.JSON, stderr)
	var narration io.Writer
	if a.Narrate || cfg.Preferences.Progress {
		narration = stderr
	}

	st, err := composition.OpenStorage(ctx, storage.Request{
		StoreRoot: root, Intent: storage.IntentCreate, Logger: logger, Config: cfg,
		Command: "kanonarion " + cgports.ChildCommand, OnBlobRefused: refused.observe,
	})
	if err != nil {
		return fmt.Errorf("initialising store: %w", err)
	}
	defer func() { retErr = errors.Join(retErr, closeStorage(st)) }()
	if verr := st.Validate(); verr != nil {
		return fmt.Errorf("initialising store: opening store: %w", verr)
	}
	if st.Writable != nil {
		if werr := st.Writable(ctx); werr != nil {
			return &exitcode.Error{Code: exitcode.Config, Msg: werr.Error()}
		}
	}

	clk, stopwatch := clock.System{}, clock.Monotonic{}
	fetchUC, err := composition.NewDriverFetch(st, root, cfg, clk, stopwatch, logger)
	if err != nil {
		return fmt.Errorf("initialising store: %w", err)
	}
	cganalyser.SetToolchainProbe(GoToolchainVersionProbe)
	cganalyser.SetSourceDirsProbe(GoSourceDirsProbe)
	// The module cache an isolated load reads is built from the bytes the store
	// holds, fetching what it is missing, as in the binary.
	analyser := cganalyser.New("0.1.0", "", logger).WithProgress(narration).
		WithModuleCache(cgmodulecache.New(st.Facts, st.Blobs, logger).WithFetcher(vulnfetch.NewFetchModuleAdapter(fetchUC)))
	module := cgapp.NewExtractCallGraphUseCase(cgapp.Config{
		Facts: st.Facts, Blobs: st.Blobs, Store: st.CallGraphs,
		Analyser: analyser, Clock: clk, Logger: logger, Stopwatch: stopwatch,
		Exclusions: cfg.Callgraph.Exclude, Toolchain: ToolchainNamer,
	}).WithAudit(st.Audit)
	stdlib := cgapp.NewExtractStdlibCallGraphUseCase(cgapp.StdlibConfig{
		Store: st.CallGraphs, Analyser: analyser,
		Toolchains: NewToolchainLocator(""),
		Custody:    StdlibCustodyProjection{Reader: st.Stdlib},
		Clock:      clk, Stopwatch: stopwatch, Logger: logger,
	}).WithAudit(st.Audit)

	var target goenv.Target
	var tinyGo goenv.TinyGo
	out, err := Extract(ctx, Deps{
		Walks: st.Walks, Module: module.Execute, Stdlib: stdlib.Execute, Stderr: stderr,
		Frame: Frame{
			Current: func() cgdomain.BuildFrame { return cganalyser.DeclaredFrame(target, tinyGo) },
			Declare: func(t goenv.Target, tg goenv.TinyGo) {
				target, tinyGo = t, tg
				analyser.WithTarget(t).WithTinyGo(tg)
			},
		},
	}, Request{Coordinate: coord, Force: a.Force, FromWalk: a.FromWalk})
	if err != nil {
		return err
	}
	if err := NoteReuse(stderr, out.Result); err != nil {
		return err
	}
	return RecordExit(out.Result.Record)
}

// storeRoot is --store-root, else KANONARION_STORE, else ~/.kanonarion.
func storeRoot(flag string) string {
	if flag != "" {
		return flag
	}
	if env := os.Getenv("KANONARION_STORE"); env != "" {
		return env
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return ".kanonarion"
	}
	return filepath.Join(home, ".kanonarion")
}

func closeStorage(st *storage.Storage) error {
	if st == nil || st.Close == nil {
		return nil
	}
	return st.Close()
}

// refusals is every stored artefact the blob store refused in this run; a
// later write that replaced the refused bytes clears it.
type refusals struct {
	mu   sync.Mutex
	list []*fetchports.BlobTamperedError
}

func (r *refusals) observe(id fetchports.BlobIdentity, refusal *fetchports.BlobTamperedError) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.list = slices.DeleteFunc(r.list, func(x *fetchports.BlobTamperedError) bool { return x.Identity == id })
	if refusal != nil {
		r.list = append(r.list, refusal)
	}
}

func (r *refusals) first() *fetchports.BlobTamperedError {
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(r.list) == 0 {
		return nil
	}
	return r.list[0]
}

// refusalError is a run that refused a stored artefact: it prints the
// refusal's own sentence, which carries the marker the parent reads, and
// unwraps to both the run's error and the refusal.
type refusalError struct {
	err     error
	refusal *fetchports.BlobTamperedError
}

func (e *refusalError) Error() string { return e.refusal.Error() }

func (e *refusalError) Unwrap() []error {
	if e.err == nil {
		return []error{e.refusal}
	}
	return []error{e.err, e.refusal}
}

// surfaceRefusal makes a refused stored artefact the run's answer: the one in
// err's chain, or else the first the store recorded.
func surfaceRefusal(err error, refused *refusals) error {
	var refusal *fetchports.BlobTamperedError
	if errors.As(err, &refusal) {
		return &refusalError{err: err, refusal: refusal}
	}
	if errors.Is(err, fetchports.ErrBlobTampered) {
		return err
	}
	if refusal = refused.first(); refusal != nil {
		return &refusalError{err: err, refusal: refusal}
	}
	return err
}

// parseCoordinate reads <module>@<version> as the binary's callgraph command does.
func parseCoordinate(arg string) (coordinate.ModuleCoordinate, error) {
	at := strings.LastIndex(arg, "@")
	if at < 0 {
		return coordinate.ModuleCoordinate{}, fmt.Errorf("invalid coordinate %q: expected module@version, got %q", arg, arg)
	}
	coord, err := coordinate.NewModuleCoordinate(arg[:at], arg[at+1:])
	if err != nil {
		return coordinate.ModuleCoordinate{}, fmt.Errorf("invalid coordinate %q: invalid module coordinate: %w", arg, err)
	}
	return coord, nil
}
