package cli

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/eitanity/kanonarion/internal/coordinate"

	fetchadapterproxy "github.com/eitanity/kanonarion/internal/adapters/proxy/direct"

	"github.com/eitanity/kanonarion/internal/walk/application"
	"github.com/eitanity/kanonarion/internal/walk/domain"
	walkports "github.com/eitanity/kanonarion/internal/walk/ports"
	"github.com/spf13/cobra"
)

// commonWalkFlags are flags shared by subcommands that need store access.
type commonWalkFlags struct {
	goproxy string
}

// registerStdlibFromGoModFlag registers the shared --stdlib-from-gomod flag on
// cmd, binding it to p. The flag pins the synthetic stdlib node to the go.mod
// toolchain/go directive instead of the effective build toolchain
// (go env GOVERSION). Walk, sbom, audit, and inspect all drive a project walk
// that injects the stdlib node, so they share this one registration to keep the
// flag name, default, and help string from drifting apart.
func registerStdlibFromGoModFlag(cmd *cobra.Command, p *bool) {
	cmd.Flags().BoolVar(p, "stdlib-from-gomod", false, "pin the stdlib node to the go.mod toolchain/go directive instead of the effective build toolchain (go env GOVERSION)")
}

// ---- walk command ----

// walkFlags holds every flag the walk command registers. They live in one
// struct, rather than in a local variable each, so that a flag one dispatch
// path never receives is visible per field rather than only as a missing
// argument.
type walkFlags struct {
	goproxy         string
	force           bool
	allowPartial    bool
	workerCount     int
	operator        string
	policyPath      string
	gomodPath       string
	skipVCSVerify   bool
	tool            bool
	project         bool
	shallow         bool
	analyseLocal    bool
	analyseRoot     bool
	stdlibFromGoMod bool
	noProgress      bool
}

func newWalkCmd(stdout, stderr io.Writer) *cobra.Command {
	var f walkFlags

	cmd := &cobra.Command{
		Use:   "walk <module@version>",
		Short: "Walk the dependency graph for a module and persist the walk record",
		Example: `  kanonarion walk github.com/spf13/cobra@v1.8.1
  kanonarion walk github.com/spf13/cobra@v1.8.1 --json
  kanonarion walk github.com/spf13/cobra@v1.8.1 --force --store-root /var/mirror
  kanonarion walk github.com/spf13/cobra@v1.8.1 --policy .kanonarion/policy.yaml
  kanonarion walk github.com/spf13/cobra@v1.8.1 --shallow
  kanonarion walk
  kanonarion walk --gomod ./go.mod --store-root /var/mirror
  kanonarion walk --gomod ./go.mod --tool
  kanonarion walk --gomod ./go.mod --project
  kanonarion walk --gomod ./go.mod --analyse-root
  kanonarion walk --gomod ./go.mod --analyse-local`,
		RunE: func(cmd *cobra.Command, args []string) error {
			// With no positional module, default to a go.mod walk; --gomod
			// defaults to./go.mod via resolveGoModPath.
			if f.gomodPath != "" || len(args) == 0 {
				if len(args) > 0 {
					return fmt.Errorf("--gomod and positional module argument are mutually exclusive")
				}
				resolved, rerr := resolveGoModPath(f.gomodPath)
				if rerr != nil {
					return rerr
				}
				f.gomodPath = resolved
			} else {
				if len(args) > 1 {
					return fmt.Errorf("accepts 1 arg, received %d", len(args))
				}
				path, version, err := parseModuleArg(args[0])
				if err != nil {
					return fmt.Errorf("invalid argument %q: %w", args[0], err)
				}
				if version == "" {
					return fmt.Errorf("version required: use %s@<version> or %s@latest", path, path)
				}
			}
			isGoMod := f.gomodPath != ""

			// A go.mod (project) walk has a local go.sum available: layer it on as
			// an always-on offline integrity check.
			if isGoMod {
				resolveProjectGoSum(f.gomodPath)
			}
			logger := buildLogger(logLevel, stderr)
			ctr, cleanup, err := NewContainer(storeRoot, f.goproxy, "", f.skipVCSVerify, activeConfig, logger)
			if err != nil {
				return fmt.Errorf("initialising store: %w", err)
			}
			defer func() { _ = cleanup() }()
			progress := newWalkProgressReporter(stderr, f.noProgress, activeConfig, logLevel)
			if isGoMod {
				return runWalkCmdProject(cmd.Context(), f, progress, ctr.ExecuteWalk, ctr.QueryFetch, stdout, stderr)
			}
			return runWalkCmdModule(cmd.Context(), args[0], f, progress, ctr.ExecuteWalk, ctr.QueryFetch, stdout, stderr)
		},
	}

	cmd.Flags().StringVar(&f.goproxy, "goproxy", "", "override GOPROXY (default: $GOPROXY or proxy.golang.org)")
	cmd.Flags().BoolVar(&f.force, "force", false, "re-fetch all modules even if cached")
	registerAllowVerificationDowngradeFlag(cmd)
	cmd.Flags().BoolVar(&f.allowPartial, "allow-partial", false, "exit 0 even when walk status is partial")
	cmd.Flags().IntVar(&f.workerCount, "workers", 0, "concurrent fetch workers (default: 16)")
	cmd.Flags().StringVar(&f.operator, "operator", "", "operator identifier recorded on the walk record (default: unrecorded)")
	cmd.Flags().StringVar(&f.policyPath, "policy", "", "path to depth policy YAML (default: search for .kanonarion/policy.yaml)")
	cmd.Flags().StringVar(&f.gomodPath, "gomod", "", "path to a go.mod file; walk the project's code dependencies (default: ./go.mod)")
	cmd.Flags().BoolVar(&f.skipVCSVerify, "skip-vcs-verify", false, "skip git cross-verification; sumdb verification still runs")
	cmd.Flags().BoolVar(&f.tool, "tool", false, "scope to the tooling supply chain (the go.mod tool directives' closure) instead of the project's own code")
	cmd.Flags().BoolVar(&f.project, "project", false, "scope to the complete set: the project's code AND tooling (the full Go build list)")
	cmd.Flags().BoolVar(&f.shallow, "shallow", false, "fetch only the target module; list go.mod require entries as unresolved nodes (positional module walk only)")
	cmd.Flags().BoolVar(&f.analyseLocal, "analyse-local", false, "ingest local-replace targets from disk so callgraph/iface/license analyse them (requires --gomod)")
	cmd.Flags().BoolVar(&f.analyseRoot, "analyse-root", false, "ingest the project's own working tree so all extraction stages analyse the project's own packages; re-reads the tree fresh on every run (requires a go.mod walk)")
	registerStdlibFromGoModFlag(cmd, &f.stdlibFromGoMod)
	registerNoProgressFlag(cmd, &f.noProgress)
	return cmd
}

// runWalkCmdProject is the walk command's go.mod dispatch path. It resolves the
// dependency scope — default = code (the project's own build deps), --tool = the
// tooling supply chain, --project = complete (build + tooling) — refuses the
// flags a project walk cannot act on, and hands the rest to the shared project
// walk that audit, sbom and inspect also drive.
func runWalkCmdProject(ctx context.Context, f walkFlags, progress walkports.ProgressReporter, uc ExecuteWalkUseCase, records fetchRecordReader, stdout, stderr io.Writer) error {
	if f.shallow {
		return fmt.Errorf("--shallow applies to a positional module walk, not a go.mod walk")
	}
	scope, scopeErr := scopeFromFlags(f.tool, f.project)
	if scopeErr != nil {
		return scopeErr
	}
	if f.analyseRoot && scope == scopeTool {
		return fmt.Errorf("--analyse-root analyses the project's own packages, which a --tool walk does not cover; drop --tool")
	}
	// LocalReplaceBase resolves local-path replace targets against the go.mod's
	// own directory, so it is derived here, on the only path that has one.
	var localReplaceBase string
	if f.analyseLocal {
		localReplaceBase = filepath.Dir(f.gomodPath)
	}
	_, err := runWalkProject(ctx, f.gomodPath, f.force, f.allowPartial, f.workerCount, f.operator,
		f.policyPath, f.skipVCSVerify, scope, domain.WalkDepthFull, localReplaceBase, f.analyseRoot,
		f.stdlibFromGoMod, progress, uc, records, stdout, stderr)
	return err
}

// runWalkCmdModule is the walk command's positional dispatch path. A walk of a
// published coordinate has no project go.mod and no local working tree behind
// it, so the flags that read one are refused by name here rather than parsed
// and dropped: each left the output byte-identical to a run without it.
func runWalkCmdModule(ctx context.Context, arg string, f walkFlags, progress walkports.ProgressReporter, uc ExecuteWalkUseCase, records fetchRecordReader, stdout, stderr io.Writer) error {
	if f.tool || f.project {
		return fmt.Errorf("--tool and --project apply to a go.mod walk, not a positional module walk")
	}
	if f.analyseRoot {
		return fmt.Errorf("--analyse-root requires a go.mod walk (only a project walk has a local root to analyse)")
	}
	if err := refuseInapplicableFlags("walk <module@version>", walkGoModOnlyFlags(f)); err != nil {
		return err
	}
	depth := domain.WalkDepthFull
	if f.shallow {
		depth = domain.WalkDepthShallow
	}
	// No local source context, so no local-replace base: a positional walk
	// resolves replace targets from the proxy or not at all.
	_, err := runWalk(ctx, arg, commonWalkFlags{goproxy: f.goproxy}, f.force, f.allowPartial, f.workerCount,
		f.operator, f.policyPath, f.skipVCSVerify, domain.WalkScopeCode, depth, "", progress, uc, records,
		stdout, stderr)
	return err
}

// runWalkProject runs a single project-rooted walk: the local main module is
// the graph root (version=local) and its set is the Go toolchain build list. It
// produces ONE record whose Target is the local module, so the SBOM subject
// (metadata.component) is the project itself.
//
// scope selects the projection of the build list, consistent with every other
// go.mod command: scopeCode (default) keeps the project's own build deps,
// scopeTool the tooling supply chain, scopeComplete the whole build list. For
// code/tool the build-list graph is restricted to the scope's module set,
// resolved via the shared Go-toolchain resolver.
func runWalkProject(ctx context.Context, gomodPath string, force, allowPartial bool, workerCount int, operator, policyPath string, skipVCSVerify bool, scope depScope, depth domain.WalkDepth, localReplaceBase string, analyseRoot, stdlibFromGoMod bool, progress walkports.ProgressReporter, uc ExecuteWalkUseCase, records fetchRecordReader, stdout, stderr io.Writer) (application.ExecuteWalkResult, error) {
	logger := buildLogger(logLevel, stderr)

	modulePath, err := readGoModulePath(gomodPath)
	if err != nil {
		return application.ExecuteWalkResult{}, err
	}
	goModBytes, err := os.ReadFile(filepath.Clean(gomodPath))
	if err != nil {
		return application.ExecuteWalkResult{}, fmt.Errorf("reading go.mod %q: %w", gomodPath, err)
	}
	// The project directory (holding go.mod/go.sum) roots the Go-toolchain build
	// list and, when --analyse-root is set, the project's own package analysis.
	// Always resolve it for a project walk.
	projectDir, err := filepath.Abs(filepath.Dir(gomodPath))
	if err != nil {
		return application.ExecuteWalkResult{}, fmt.Errorf("resolving project directory of %q: %w", gomodPath, err)
	}

	// The main module is local and unpublished; pin it at the synthetic
	// LocalVersion rather than a semver.
	target, err := coordinate.NewLocalCoordinate(modulePath)
	if err != nil {
		return application.ExecuteWalkResult{}, fmt.Errorf("project coordinate for %s: %w", modulePath, err)
	}

	policy, policyHash, err := loadPolicy(ctx, policyPath, logger)
	if err != nil {
		return application.ExecuteWalkResult{}, fmt.Errorf("loading policy: %w", err)
	}

	// The complete scope keeps the whole build list (nil = no restriction); the
	// code and tool scopes restrict it to their toolchain-resolved module set,
	// the same set every other go.mod command uses for that scope.
	var scopeModules []string
	if scope != scopeComplete {
		scopeModules, err = resolveScopeModules(gomodPath, scope)
		if err != nil {
			return application.ExecuteWalkResult{}, fmt.Errorf("resolving %s scope: %w", scope, err)
		}
		scopeModules = coordsToPaths(scopeModules)
	}

	result, err := uc.Execute(ctx, application.WalkRequest{
		Target:           target,
		Force:            force,
		WorkerCount:      workerCount,
		SkipVCSVerify:    skipVCSVerify,
		Policy:           &policy,
		PolicyHash:       policyHash,
		Scope:            domain.WalkScope(scope),
		ScopeModules:     scopeModules,
		Depth:            depth,
		LocalReplaceBase: localReplaceBase,
		Operator:         operator,
		ProjectMode:      true,
		MainModuleGoMod:  goModBytes,
		AnalyseLocalRoot: analyseRoot,
		ProjectDir:       projectDir,
		ResolutionDir:    projectDir,
		StdlibFromGoMod:  stdlibFromGoMod,
		Progress:         progress,
	})
	if err != nil {
		return application.ExecuteWalkResult{}, fmt.Errorf("executing walk: %w", err)
	}

	rec := result.Record
	// A project walk resolves a manifest; a vendored project compiles something
	// else. The disclosure rides on stderr with the coverage aggregate and for
	// the same reason: the walk record on stdout is the content-hashed artefact,
	// and a fact about the run is not part of what the seal covers.
	//
	// It is gated on the same nil reader the coverage aggregate is, and this is
	// what that gate means here: a nil reader is a caller using the walk as a
	// means rather than presenting it as the answer — audit, inspect and sbom —
	// and each of those states the disclosure itself, about its own answer.
	// Without the gate a single audit says it twice.
	if records != nil {
		if verr := writeBuildVendoring(stderr, detectBuildVendoringForGoMod(gomodPath)); verr != nil {
			return result, verr
		}
	}
	// The aggregate goes to stderr, never stdout: the walk record on stdout is
	// the content-hashed artefact, and a report about the run is not part of it.
	if cerr := reportGraphVerificationCoverage(ctx, rec.Graph.Nodes, records, stderr); cerr != nil {
		return result, cerr
	}
	if jsonOut {
		if encErr := writeWalkRecordJSON(stdout, rec); encErr != nil {
			return result, fmt.Errorf("encoding JSON: %w", encErr)
		}
	} else {
		if _, pErr := fmt.Fprintf(stdout, "walk %s: %s depth=%s (%d nodes, %d failed)\n",
			rec.ID, rec.OverallStatus.String(), string(rec.Depth),
			len(rec.Graph.Nodes),
			countFailures(rec),
		); pErr != nil {
			return result, fmt.Errorf("writing output: %w", pErr)
		}
	}

	switch rec.OverallStatus {
	case domain.WalkFailed:
		return result, &exitError{code: ExitFailed, msg: "walk failed: project go.mod could not be resolved"}
	case domain.WalkCancelled:
		return result, &exitError{code: ExitCancelled, msg: "walk cancelled"}
	case domain.WalkPartial:
		if !allowPartial {
			return result, &exitError{code: ExitPartial, msg: "walk partial: some dependencies could not be fetched"}
		}
	}
	return result, nil
}

// runWalk walks one published coordinate and returns the walk it produced.
//
// The result is returned rather than only the error so a caller that walks and
// then reads what it walked names the record this run resolved to, instead of
// asking the store for "the newest walk of that coordinate" afterwards. Those
// are not the same walk: identity reuse serves an existing record when the
// resolution is unchanged, and reuse keeps that record's original started_at, so
// the walk a run produced can be older than another walk of the same target.
func runWalk(ctx context.Context, arg string, f commonWalkFlags, force, allowPartial bool, workerCount int, operator, policyPath string, skipVCSVerify bool, scope domain.WalkScope, depth domain.WalkDepth, localReplaceBase string, progress walkports.ProgressReporter, uc ExecuteWalkUseCase, records fetchRecordReader, stdout, stderr io.Writer) (application.ExecuteWalkResult, error) {
	logger := buildLogger(logLevel, stderr)

	path, version, err := parseModuleArg(arg)
	if err != nil {
		return application.ExecuteWalkResult{}, fmt.Errorf("invalid argument %q: %w", arg, err)
	}
	if version == "" {
		return application.ExecuteWalkResult{}, fmt.Errorf("version required: use %s@<version> or %s@latest", path, path)
	}

	var coord coordinate.ModuleCoordinate
	if version == "latest" {
		proxy, proxyErr := fetchadapterproxy.New(f.goproxy, false)
		if proxyErr != nil {
			return application.ExecuteWalkResult{}, proxyAdapterError(proxyErr)
		}
		coord, err = resolveLatest(ctx, path, proxy, stderr)
		if err != nil {
			return application.ExecuteWalkResult{}, err
		}
	} else {
		coord, err = coordinate.NewModuleCoordinate(path, version)
		if err != nil {
			return application.ExecuteWalkResult{}, fmt.Errorf("invalid coordinate %q: %w", arg, err)
		}
	}

	policy, policyHash, err := loadPolicy(ctx, policyPath, logger)
	if err != nil {
		return application.ExecuteWalkResult{}, fmt.Errorf("loading policy: %w", err)
	}

	result, err := uc.Execute(ctx, application.WalkRequest{
		Target:           coord,
		Force:            force,
		WorkerCount:      workerCount,
		SkipVCSVerify:    skipVCSVerify,
		Policy:           &policy,
		PolicyHash:       policyHash,
		Scope:            scope,
		Depth:            depth,
		LocalReplaceBase: localReplaceBase,
		Operator:         operator,
		Progress:         progress,
	})
	if err != nil {
		return application.ExecuteWalkResult{}, fmt.Errorf("executing walk: %w", err)
	}

	rec := result.Record
	// The aggregate goes to stderr, never stdout: the walk record on stdout is
	// the content-hashed artefact, and a report about the run is not part of it.
	if cerr := reportGraphVerificationCoverage(ctx, rec.Graph.Nodes, records, stderr); cerr != nil {
		return result, cerr
	}
	if jsonOut {
		if encErr := writeWalkRecordJSON(stdout, rec); encErr != nil {
			return result, fmt.Errorf("encoding JSON: %w", encErr)
		}
	} else {
		if _, pErr := fmt.Fprintf(stdout, "walk %s: %s depth=%s (%d nodes, %d failed)\n",
			rec.ID, rec.OverallStatus.String(), string(rec.Depth),
			len(rec.Graph.Nodes),
			countFailures(rec),
		); pErr != nil {
			return result, fmt.Errorf("writing output: %w", pErr)
		}
	}

	switch rec.OverallStatus {
	case domain.WalkFailed:
		return result, &exitError{code: ExitFailed, msg: "walk failed: target module could not be fetched"}
	case domain.WalkCancelled:
		return result, &exitError{code: ExitCancelled, msg: "walk cancelled"}
	case domain.WalkPartial:
		if !allowPartial {
			return result, &exitError{code: ExitPartial, msg: "walk partial: some dependencies could not be fetched"}
		}
	}
	return result, nil
}

// ---- walk-list command ----

// ---- walk-show command ----

// ---- walk-diff command ----

// ---- walk-diff JSON types ----
