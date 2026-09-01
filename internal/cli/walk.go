package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/eitanity/kanonarion/internal/coordinate"

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
	fromModcache    string
	// excludeTests is parsed only so the refusal can name it. A walk record names
	// its scope and not its test axis; see refuseTestScopeOnRecordingCommand.
	excludeTests bool
}

func newWalkCmd(stdout, stderr io.Writer) *cobra.Command {
	var f walkFlags

	cmd := &cobra.Command{
		Use: "walk <module@version>",
		Annotations: map[string]string{
			annotationStoreIntent: StoreIntentCreate,
			// --from-modcache is the offline walk: module bytes come from a
			// module cache and go.sum verifies them, so the reach is avoidable
			// rather than inherent. The declaration moved with the flag.
			annotationNetworkUse:   NetworkAvoidable,
			annotationOfflineFlags: "--from-modcache",
		},
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
  kanonarion walk --gomod ./go.mod --analyse-local
  kanonarion walk --gomod ./go.mod --from-modcache`,
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
			if f.gomodPath != "" {
				return runWalkGoMod(cmd.Context(), f, stdout, stderr)
			}
			return runWalkModule(cmd.Context(), args[0], f, stdout, stderr)
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
	registerFromModcacheFlag(cmd, &f.fromModcache)
	registerNoProgressFlag(cmd, &f.noProgress)
	registerRecordedTestScopeFlag(cmd, &f.excludeTests)
	return cmd
}

// walkRuntime is the store access and progress reporting one walk invocation
// runs against, opened once the path's fetch mode is settled.
type walkRuntime struct {
	execute  ExecuteWalkUseCase
	records  fetchRecordReader
	progress walkports.ProgressReporter
	cleanup  func() error
}

// openWalkRuntime opens the store container and progress reporter for a walk.
//
// It is called by the dispatch path rather than before dispatch because
// NewContainer wires its fetch adapters from the process-wide fetch mode:
// anything that decides where module bytes come from has to have run first, and
// only the path knows what it decided.
func openWalkRuntime(f walkFlags, stderr io.Writer) (walkRuntime, error) {
	logger := buildLogger(logLevel, stderr)
	ctr, cleanup, err := NewContainer(storeRoot, f.goproxy, "", f.skipVCSVerify, activeConfig, logger)
	if err != nil {
		return walkRuntime{}, fmt.Errorf("initialising store: %w", err)
	}
	return walkRuntime{
		execute:  ctr.ExecuteWalk,
		records:  ctr.QueryFetch,
		progress: newWalkProgressReporter(stderr, f.noProgress, activeConfig, logLevel),
		cleanup:  cleanup,
	}, nil
}

// runWalkGoMod is the go.mod path's entry point. It settles where this walk's
// module bytes come from and what verifies them — the decision --from-modcache
// makes — before opening the store, then runs the project walk.
func runWalkGoMod(ctx context.Context, f walkFlags, stdout, stderr io.Writer) error {
	// --from-modcache is the offline walk: bytes come from an existing module
	// cache and the go.sum beside this go.mod is their sole anchor. Resolved
	// first because resolveProjectGoSum is a no-op under it, and because the
	// container below wires its adapters from the mode it sets.
	if err := resolveModcacheMode(ctx, f.fromModcache, f.gomodPath); err != nil {
		return err
	}
	// On the network path the project's go.sum layers on as an always-on offline
	// integrity check.
	resolveProjectGoSum(f.gomodPath)

	rt, err := openWalkRuntime(f, stderr)
	if err != nil {
		return err
	}
	defer func() { _ = rt.cleanup() }()
	return runWalkCmdProject(ctx, f, rt.progress, rt.execute, rt.records, stdout, stderr)
}

// runWalkModule is the positional path's entry point. A published coordinate
// carries no project go.mod, so there is no fetch mode for it to settle: the
// flags that would have named one are refused by name in runWalkCmdModule.
func runWalkModule(ctx context.Context, arg string, f walkFlags, stdout, stderr io.Writer) error {
	rt, err := openWalkRuntime(f, stderr)
	if err != nil {
		return err
	}
	defer func() { _ = rt.cleanup() }()
	return runWalkCmdModule(ctx, arg, f, rt.progress, rt.execute, rt.records, stdout, stderr)
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
	if rerr := refuseTestScopeOnRecordingCommand("walk --gomod", f.excludeTests); rerr != nil {
		return rerr
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
	if rerr := refuseTestScopeOnRecordingCommand("walk <module@version>", f.excludeTests); rerr != nil {
		return rerr
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
	res := newScopeResolution(scope, false)
	if scope != scopeComplete {
		var mods []scopeModule
		mods, res, err = resolveScopeModules(ctx, gomodPath, scope, false)
		if err != nil {
			return application.ExecuteWalkResult{}, fmt.Errorf("resolving %s scope: %w", scope, err)
		}
		// The require paths: the graph filter keys scope membership on them and
		// retains a replaced node through its OriginalCoordinate, so naming the
		// replacement here would be naming a path the build list does not hold.
		scopeModules = coordsToPaths(requiredCoords(mods))
	}
	// The test axis this walk was resolved over, stated on the same channel as
	// the build-vendoring and coverage disclosures and for the same reason: the
	// record on stdout is the content-hashed artefact and a fact about the run is
	// not part of what the seal covers. The axis is not narrowable here — the
	// record has no field to name it — so no flag is offered in the line.
	//
	// It is gated on the same nil reader those two are: a nil reader is a caller
	// using the walk as a means (audit, inspect, the vuln-scan re-walk), and each
	// of those states the scope of its own answer.
	if records != nil {
		var nerr error
		if scope == scopeComplete {
			nerr = writeDepScopeAxisNotice(stderr, res)
		} else {
			nerr = writeDepScopeNotice(stderr, res, len(scopeModules), false)
		}
		if nerr != nil {
			return application.ExecuteWalkResult{}, nerr
		}
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
	// The aggregate is stated on stderr and, under --json, in the document: the
	// record's own bytes stay the content-hashed artefact, and the coverage is a
	// key beside them rather than inside them.
	coverage, cerr := walkCoverageReport(ctx, rec, records, stderr)
	if cerr != nil {
		return result, cerr
	}
	if jsonOut {
		if encErr := writeWalkRecordWithCoverageJSON(stdout, rec, coverage); encErr != nil {
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

	// A root ingest that did not happen is stated outright. The walk is
	// otherwise complete — the node count and failure count both read clean —
	// so without this line nothing in the output says the project's own
	// packages are absent from the surface the operator asked for.
	rootIngestErr := rootIngestFailure(rec)
	if rootIngestErr != "" {
		if _, wErr := fmt.Fprintf(stderr,
			"note: --analyse-root did not ingest %s, so this walk does not cover the project's own packages: %s\n",
			rec.Target.Path(), rootIngestErr); wErr != nil {
			return result, fmt.Errorf("writing output: %w", wErr)
		}
	}

	partialMsg := "walk partial: some dependencies could not be fetched"
	if rootIngestErr != "" {
		partialMsg = "walk partial: the dependency graph is complete, but the project's own packages were not ingested"
	}
	return result, walkExit(rec.OverallStatus, allowPartial,
		"walk failed: project go.mod could not be resolved", partialMsg)
}

// walkExit maps the recorded walk status onto the process exit code.
//
// Only Succeeded is enumerated as clean, and --allow-partial lifts Partial's
// code alone. A status this build does not recognise is not a completed walk, so
// it degrades to Partial rather than falling through to success.
func walkExit(status domain.WalkStatus, allowPartial bool, failedMsg, partialMsg string) error {
	switch status {
	case domain.WalkSucceeded:
		return nil
	case domain.WalkFailed:
		return &exitError{code: ExitFailed, msg: failedMsg}
	case domain.WalkCancelled:
		return &exitError{code: ExitCancelled, msg: "walk cancelled"}
	case domain.WalkPartial:
		if allowPartial {
			return nil
		}
		return &exitError{code: ExitPartial, msg: partialMsg}
	default:
		return &exitError{code: ExitPartial, msg: fmt.Sprintf(
			"the walk reports an unrecognised status %q; its completeness cannot be established", status)}
	}
}

// rootIngestFailure returns the reason --analyse-root did not ingest the
// project root, or "" when it did (or was never asked for). The failure rides
// on the root's otherwise-succeeded node result, because the root's go.mod was
// read and its graph resolved: only the project's own package analysis is
// missing.
func rootIngestFailure(rec domain.WalkRecord) string {
	r, ok := rec.PerNodeResults[rec.Target]
	if !ok || r.Error == nil || r.Error.Type != "local_root_ingest_failed" {
		return ""
	}
	return r.Error.Message
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
	// Stated on stderr and, under --json, in the document: see the same report on
	// the project path above.
	coverage, cerr := walkCoverageReport(ctx, rec, records, stderr)
	if cerr != nil {
		return result, cerr
	}
	if jsonOut {
		if encErr := writeWalkRecordWithCoverageJSON(stdout, rec, coverage); encErr != nil {
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

	return result, walkExit(rec.OverallStatus, allowPartial,
		"walk failed: target module could not be fetched",
		"walk partial: some dependencies could not be fetched")
}

// ---- what a walk states about how its graph was verified ----

// walkVerificationCoverageJSON is the chain of custody `walk --json` carries:
// how each module in the walk's graph was verified, and how many were not.
//
// It embeds the document the verification-coverage command publishes, so one
// fact keeps one spelling on both surfaces and a gate written against either
// reads the other. Measured states outright whether a measurement was taken: a
// run that took none must not read as a graph that was checked and came back
// clean.
type walkVerificationCoverageJSON struct {
	coverageJSON
	Measured bool `json:"measured"`
	// Statement is what the reader is shown on stderr, carried verbatim so the
	// document and the screen say the same thing in the same words.
	Statement string `json:"statement"`
}

// walkCoverageReport states how this walk's graph was verified, and returns the
// same measurement for the document.
//
// The text path keeps the shared reporter: only a document needs the figures
// back, and measuring a second time to get them is what would let the statement
// and the document disagree.
func walkCoverageReport(ctx context.Context, rec domain.WalkRecord, records fetchRecordReader, stderr io.Writer) (walkVerificationCoverageJSON, error) {
	if !jsonOut {
		return walkVerificationCoverageJSON{}, reportGraphVerificationCoverage(ctx, rec.Graph.Nodes, records, stderr)
	}
	// A nil reader is a caller driving this walk as a means to another answer —
	// audit, inspect, sbom — each of which reports coverage over its own.
	if records == nil {
		return unmeasuredWalkCoverage(rec,
			"this run drove the walk for a command that reports coverage over its own answer"), nil
	}
	rows := graphVerificationRows(ctx, rec.Graph.Nodes, records)
	obs := make([]fetchdomain.CoverageObservation, 0, len(rows))
	for _, r := range rows {
		obs = append(obs, r.observation)
	}
	coverage := fetchdomain.VerificationCoverageOf(obs)

	var statement strings.Builder
	if err := writeVerificationCoverage(&statement, coverage); err != nil {
		return walkVerificationCoverageJSON{}, err
	}
	if _, err := io.WriteString(stderr, statement.String()); err != nil {
		return walkVerificationCoverageJSON{}, fmt.Errorf("writing output: %w", err)
	}
	if coverage.Total == 0 {
		return unmeasuredWalkCoverage(rec, "this walk's graph holds no module to verify"), nil
	}
	return walkVerificationCoverageJSON{
		coverageJSON: verificationCoverageJSON(rec.ID, coverage, rows,
			detectBuildVendoringInDir(rec.ProjectDir), walkBuildOf(rec)),
		Measured:  true,
		Statement: strings.TrimRight(statement.String(), "\n"),
	}, nil
}

// unmeasuredWalkCoverage is the section for a run that measured no coverage. The
// key is present and says so in words: an absent key reads as a graph that was
// checked and had nothing to report, which is the opposite of what it means.
func unmeasuredWalkCoverage(rec domain.WalkRecord, reason string) walkVerificationCoverageJSON {
	return walkVerificationCoverageJSON{
		coverageJSON: verificationCoverageJSON(rec.ID, fetchdomain.VerificationCoverage{}, nil,
			detectBuildVendoringInDir(rec.ProjectDir), walkBuildOf(rec)),
		Measured:  false,
		Statement: "verification coverage was not measured: " + reason,
	}
}

// writeWalkRecordWithCoverageJSON writes the walk record with this run's
// verification coverage beside it.
//
// The record's own keys are spliced through as the hasher marshalled them —
// value for value, none moved, renamed or dropped — so the sealed artefact a
// consumer verifies is unchanged and the coverage is one added key next to it.
func writeWalkRecordWithCoverageJSON(w io.Writer, r domain.WalkRecord, coverage walkVerificationCoverageJSON) error {
	var h domain.WalkRecordHasher
	b, err := h.Marshal(r)
	if err != nil {
		return fmt.Errorf("marshalling walk record: %w", err)
	}
	doc := map[string]json.RawMessage{}
	if err := json.Unmarshal(b, &doc); err != nil {
		return fmt.Errorf("reading the marshalled walk record: %w", err)
	}
	cov, err := json.Marshal(coverage)
	if err != nil {
		return fmt.Errorf("marshalling verification coverage: %w", err)
	}
	doc["verification_coverage"] = cov
	out, err := json.Marshal(doc)
	if err != nil {
		return fmt.Errorf("marshalling walk document: %w", err)
	}
	if _, err := fmt.Fprintf(w, "%s\n", out); err != nil {
		return fmt.Errorf("writing walk record: %w", err)
	}
	return nil
}

// ---- walk-list command ----

// ---- walk-show command ----

// ---- walk-diff command ----

// ---- walk-diff JSON types ----
