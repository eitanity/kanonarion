package cli

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"

	fetchadapterproxy "github.com/eitanity/kanonarion/internal/adapters/proxy/direct"
	fetchdomain "github.com/eitanity/kanonarion/internal/fetch/domain"
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

func newWalkCmd(stdout, stderr io.Writer) *cobra.Command {
	var f commonWalkFlags
	var force bool
	var allowPartial bool
	var workerCount int
	var operator string
	var policyPath string
	var gomodPath string
	var skipVCSVerify bool
	var toolScope bool
	var shallow bool
	var analyseLocal bool
	var projectComplete bool
	var analyseRoot bool
	var stdlibFromGoMod bool
	var noProgress bool

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
			if gomodPath != "" || len(args) == 0 {
				if len(args) > 0 {
					return fmt.Errorf("--gomod and positional module argument are mutually exclusive")
				}
				resolved, rerr := resolveGoModPath(gomodPath)
				if rerr != nil {
					return rerr
				}
				gomodPath = resolved
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
			// A go.mod walk produces one project-rooted record. The dependency
			// scope is consistent with every other go.mod command: default = code
			// (the project's own build deps — the vuln/licence/copyright triage
			// set), --tool = the tooling supply chain, --project = complete (build
			// + tooling). --shallow is a positional-only depth lens.
			isGoMod := gomodPath != ""
			scope, scopeErr := scopeFromFlags(toolScope, projectComplete)
			if scopeErr != nil {
				return scopeErr
			}
			if !isGoMod {
				if toolScope || projectComplete {
					return fmt.Errorf("--tool and --project apply to a go.mod walk, not a positional module walk")
				}
				if analyseRoot {
					return fmt.Errorf("--analyse-root requires a go.mod walk (only a project walk has a local root to analyse)")
				}
			} else {
				if shallow {
					return fmt.Errorf("--shallow applies to a positional module walk, not a go.mod walk")
				}
				if analyseRoot && scope == scopeTool {
					return fmt.Errorf("--analyse-root analyses the project's own packages, which a --tool walk does not cover; drop --tool")
				}
			}
			depth := domain.WalkDepthFull
			if shallow {
				depth = domain.WalkDepthShallow
			}

			// Derive LocalReplaceBase from the go.mod directory when
			// --analyse-local is set. For positional walks there is no local
			// source context, so the flag has no effect.
			var localReplaceBase string
			if analyseLocal && isGoMod {
				localReplaceBase = filepath.Dir(gomodPath)
			}

			logger := buildLogger(logLevel, stderr)
			ctr, cleanup, err := NewContainer(storeRoot, f.goproxy, "", skipVCSVerify, activeConfig, logger)
			if err != nil {
				return fmt.Errorf("initialising store: %w", err)
			}
			defer func() { _ = cleanup() }()
			progress := newWalkProgressReporter(stderr, noProgress, activeConfig, logLevel)
			if isGoMod {
				return runWalkProject(cmd.Context(), gomodPath, f, force, allowPartial, workerCount, operator, policyPath, skipVCSVerify, scope, depth, localReplaceBase, analyseRoot, stdlibFromGoMod, progress, ctr.ExecuteWalk, stdout, stderr)
			}
			return runWalk(cmd.Context(), args[0], f, force, allowPartial, workerCount, operator, policyPath, skipVCSVerify, domain.WalkScopeCode, depth, localReplaceBase, progress, ctr.ExecuteWalk, stdout, stderr)
		},
	}

	cmd.Flags().StringVar(&f.goproxy, "goproxy", "", "override GOPROXY (default: $GOPROXY or proxy.golang.org)")
	cmd.Flags().BoolVar(&force, "force", false, "re-fetch all modules even if cached")
	cmd.Flags().BoolVar(&allowPartial, "allow-partial", false, "exit 0 even when walk status is partial")
	cmd.Flags().IntVar(&workerCount, "workers", 0, "concurrent fetch workers (default: 16)")
	cmd.Flags().StringVar(&operator, "operator", "", "operator identifier (defaults to $USER)")
	cmd.Flags().StringVar(&policyPath, "policy", "", "path to depth policy YAML (default: search for .kanonarion/policy.yaml)")
	cmd.Flags().StringVar(&gomodPath, "gomod", "", "path to a go.mod file; walk the project's code dependencies (default: ./go.mod)")
	cmd.Flags().BoolVar(&skipVCSVerify, "skip-vcs-verify", false, "skip git cross-verification; sumdb verification still runs")
	cmd.Flags().BoolVar(&toolScope, "tool", false, "scope to the tooling supply chain (the go.mod tool directives' closure) instead of the project's own code")
	cmd.Flags().BoolVar(&projectComplete, "project", false, "scope to the complete set: the project's code AND tooling (the full Go build list)")
	cmd.Flags().BoolVar(&shallow, "shallow", false, "fetch only the target module; list go.mod require entries as unresolved nodes (positional module walk only)")
	cmd.Flags().BoolVar(&analyseLocal, "analyse-local", false, "ingest local-replace targets from disk so callgraph/iface/license analyse them (requires --gomod)")
	cmd.Flags().BoolVar(&analyseRoot, "analyse-root", false, "ingest the project's own working tree so all extraction stages analyse the project's own packages; re-reads the tree fresh on every run (requires a go.mod walk)")
	registerStdlibFromGoModFlag(cmd, &stdlibFromGoMod)
	cmd.Flags().BoolVar(&noProgress, "no-progress", false, "suppress the stderr fetch-progress heartbeat (default: heartbeat on for long runs)")
	return cmd
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
func runWalkProject(
	ctx context.Context,
	gomodPath string,
	f commonWalkFlags,
	force bool,
	allowPartial bool,
	workerCount int,
	operator string,
	policyPath string,
	skipVCSVerify bool,
	scope depScope,
	depth domain.WalkDepth,
	localReplaceBase string,
	analyseRoot bool,
	stdlibFromGoMod bool,
	progress walkports.ProgressReporter,
	uc ExecuteWalkUseCase,
	stdout, stderr io.Writer,
) error {
	_ = operator // operator is bound on the use case at construction, as in runWalk
	logger := buildLogger(logLevel, stderr)

	modulePath, err := readGoModulePath(gomodPath)
	if err != nil {
		return err
	}
	goModBytes, err := os.ReadFile(filepath.Clean(gomodPath))
	if err != nil {
		return fmt.Errorf("reading go.mod %q: %w", gomodPath, err)
	}
	// The project directory (holding go.mod/go.sum) roots the Go-toolchain build
	// list and, when --analyse-root is set, the project's own package analysis.
	// Always resolve it for a project walk.
	projectDir, err := filepath.Abs(filepath.Dir(gomodPath))
	if err != nil {
		return fmt.Errorf("resolving project directory of %q: %w", gomodPath, err)
	}

	// The main module is local and unpublished; pin it at the synthetic
	// LocalVersion rather than a semver. NewModuleCoordinate is bypassed because
	// "local" is not valid semver — the constant is the one exception it allows.
	target := fetchdomain.ModuleCoordinate{Path: modulePath, Version: fetchdomain.LocalVersion}

	policy, policyHash, err := loadPolicy(ctx, policyPath, logger)
	if err != nil {
		return fmt.Errorf("loading policy: %w", err)
	}

	// The complete scope keeps the whole build list (nil = no restriction); the
	// code and tool scopes restrict it to their toolchain-resolved module set,
	// the same set every other go.mod command uses for that scope.
	var scopeModules []string
	if scope != scopeComplete {
		scopeModules, err = resolveScopeModules(gomodPath, scope)
		if err != nil {
			return fmt.Errorf("resolving %s scope: %w", scope, err)
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
		ProjectMode:      true,
		MainModuleGoMod:  goModBytes,
		AnalyseLocalRoot: analyseRoot,
		ProjectDir:       projectDir,
		StdlibFromGoMod:  stdlibFromGoMod,
		Progress:         progress,
	})
	if err != nil {
		return fmt.Errorf("executing walk: %w", err)
	}

	rec := result.Record
	if jsonOut {
		if encErr := writeWalkRecordJSON(stdout, rec); encErr != nil {
			return fmt.Errorf("encoding JSON: %w", encErr)
		}
	} else {
		if _, pErr := fmt.Fprintf(stdout, "walk %s: %s depth=%s (%d nodes, %d failed)\n",
			rec.ID, rec.OverallStatus.String(), string(rec.Depth),
			len(rec.Graph.Nodes),
			countFailures(rec),
		); pErr != nil {
			return fmt.Errorf("writing output: %w", pErr)
		}
	}

	switch rec.OverallStatus {
	case domain.WalkFailed:
		return &exitError{code: ExitFailed, msg: "walk failed: project go.mod could not be resolved"}
	case domain.WalkCancelled:
		return &exitError{code: ExitCancelled, msg: "walk cancelled"}
	case domain.WalkPartial:
		if !allowPartial {
			return &exitError{code: ExitPartial, msg: "walk partial: some dependencies could not be fetched"}
		}
	}
	return nil
}

func runWalk(
	ctx context.Context,
	arg string,
	f commonWalkFlags,
	force bool,
	allowPartial bool,
	workerCount int,
	operator string,
	policyPath string,
	skipVCSVerify bool,
	scope domain.WalkScope,
	depth domain.WalkDepth,
	localReplaceBase string,
	progress walkports.ProgressReporter,
	uc ExecuteWalkUseCase,
	stdout, stderr io.Writer,
) error {
	logger := buildLogger(logLevel, stderr)

	path, version, err := parseModuleArg(arg)
	if err != nil {
		return fmt.Errorf("invalid argument %q: %w", arg, err)
	}
	if version == "" {
		return fmt.Errorf("version required: use %s@<version> or %s@latest", path, path)
	}

	var coord fetchdomain.ModuleCoordinate
	if version == "latest" {
		proxy, proxyErr := fetchadapterproxy.New(f.goproxy, false)
		if proxyErr != nil {
			return fmt.Errorf("creating proxy: %w", proxyErr)
		}
		coord, err = resolveLatest(ctx, path, proxy, stderr)
		if err != nil {
			return err
		}
	} else {
		coord, err = fetchdomain.NewModuleCoordinate(path, version)
		if err != nil {
			return fmt.Errorf("invalid coordinate %q: %w", arg, err)
		}
	}

	policy, policyHash, err := loadPolicy(ctx, policyPath, logger)
	if err != nil {
		return fmt.Errorf("loading policy: %w", err)
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
		Progress:         progress,
	})
	if err != nil {
		return fmt.Errorf("executing walk: %w", err)
	}

	rec := result.Record
	if jsonOut {
		if encErr := writeWalkRecordJSON(stdout, rec); encErr != nil {
			return fmt.Errorf("encoding JSON: %w", encErr)
		}
	} else {
		if _, pErr := fmt.Fprintf(stdout, "walk %s: %s depth=%s (%d nodes, %d failed)\n",
			rec.ID, rec.OverallStatus.String(), string(rec.Depth),
			len(rec.Graph.Nodes),
			countFailures(rec),
		); pErr != nil {
			return fmt.Errorf("writing output: %w", pErr)
		}
	}

	switch rec.OverallStatus {
	case domain.WalkFailed:
		return &exitError{code: ExitFailed, msg: "walk failed: target module could not be fetched"}
	case domain.WalkCancelled:
		return &exitError{code: ExitCancelled, msg: "walk cancelled"}
	case domain.WalkPartial:
		if !allowPartial {
			return &exitError{code: ExitPartial, msg: "walk partial: some dependencies could not be fetched"}
		}
	}
	return nil
}

// ---- walk-list command ----

// ---- walk-show command ----

// ---- walk-diff command ----

// ---- walk-diff JSON types ----
