package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/eitanity/kanonarion/internal/coordinate"

	"github.com/spf13/cobra"

	proxyadapter "github.com/eitanity/kanonarion/internal/adapters/proxy/direct"

	extractdomain "github.com/eitanity/kanonarion/internal/extract/domain"
	vendports "github.com/eitanity/kanonarion/internal/vendortree/ports"
	vulnapp "github.com/eitanity/kanonarion/internal/vuln/application"
	vuldomain "github.com/eitanity/kanonarion/internal/vuln/domain"
	"github.com/eitanity/kanonarion/internal/walk/application"
	domain "github.com/eitanity/kanonarion/internal/walk/domain"
	walkports "github.com/eitanity/kanonarion/internal/walk/ports"
)

type inspectFlags struct {
	goproxy         string
	goBinary        string
	gomodPath       string
	tool            bool
	project         bool
	force           bool
	fresh           bool
	reachable       bool
	skipVCS         bool
	sizeOnly        bool
	full            bool
	noProgress      bool
	stdlibFromGoMod bool
	policyPath      string
	// excludeTests is parsed only so the refusal can name it. inspect drives a
	// project walk; see refuseTestScopeOnRecordingCommand.
	excludeTests bool
}

func newInspectCmd(stdout, stderr io.Writer) *cobra.Command {
	var f inspectFlags

	cmd := &cobra.Command{
		Use: "inspect [<module>@<version>]",
		Annotations: map[string]string{
			annotationStoreIntent: StoreIntentCreate,
			annotationNetworkUse:  NetworkAlways,
		},
		Short: "Run the full pipeline (walk → extract → vuln-scan → context); no args: code deps of ./go.mod",
		Long: `Run the full pipeline (walk → extract → vuln-scan → context) for a module.

With no arguments, inspect defaults to --gomod ./go.mod and runs the pipeline
over the project's own code dependencies, printing a summary instead of
per-module context. The dependency scope is consistent with every go.mod
command: default = code, --tool = tooling, --project = complete (code +
tooling).

Memory: the vuln-scan stage sizes its module-scan pool against this host's
available memory, because a single source-mode scan of a cloud-SDK-heavy module
can hold several GB. That budget is per-process and is measured once, at the
start of the scan. Two inspect runs on one host therefore each admit a full pool
against the same free memory and share no budget with each other, so they can
still exhaust the host and have their scanners OOM-killed — which reports the
affected modules as unanalysed, not as clean. Run them one at a time on a host
that is tight on memory.`,
		Example: `  kanonarion inspect github.com/spf13/cobra@v1.8.1
  kanonarion inspect modernc.org/sqlite@latest --reachability
  kanonarion inspect
  kanonarion inspect --gomod ./go.mod
  kanonarion inspect --tool
  kanonarion inspect --project`,
		Args: cobra.RangeArgs(0, 1),
		RunE: func(cmd *cobra.Command, args []string) error {
			scope, serr := scopeFromFlags(f.tool, f.project)
			if serr != nil {
				return serr
			}
			if (f.tool || f.project) && len(args) > 0 {
				return fmt.Errorf("--tool and --project apply to a go.mod scan, not a positional module argument")
			}
			// With no positional module, default to a go.mod scan; --gomod
			// defaults to ./go.mod via resolveGoModPath.
			if f.gomodPath != "" || len(args) == 0 {
				if len(args) != 0 {
					return fmt.Errorf("--gomod and a module argument are mutually exclusive")
				}
				resolved, rerr := resolveGoModPath(f.gomodPath)
				if rerr != nil {
					return rerr
				}
				f.gomodPath = resolved
				return runInspectGoMod(cmd.Context(), f, scope, stdout, stderr)
			}
			return runInspect(cmd.Context(), args[0], f, stdout, stderr)
		},
	}

	cmd.Flags().StringVar(&f.goproxy, "goproxy", "", "override GOPROXY (default: $GOPROXY or proxy.golang.org)")
	cmd.Flags().StringVar(&f.goBinary, "go-binary", "", "path to 'go' binary if not in PATH")
	cmd.Flags().BoolVar(&f.force, "force", false, "re-fetch and re-extract even if cached records exist")
	cmd.Flags().BoolVar(&f.fresh, "fresh", false, "refresh the vulnerability advisory database: download a new snapshot only if an advisory listed for a module in this walk has changed")
	cmd.Flags().BoolVar(&f.reachable, "reachability", false, "enable call-graph reachability analysis during vuln-scan (--gomod: roots at the dependency closure, not the project's own code; use 'kanonarion local' to root at the app)")
	cmd.Flags().BoolVar(&f.skipVCS, "skip-vcs-verify", false, "skip git cross-verification; sumdb verification still runs")
	cmd.Flags().StringVar(&f.policyPath, "policy", "", "path to depth policy YAML (default: search for .kanonarion/policy.yaml)")
	cmd.Flags().BoolVar(&f.sizeOnly, "size-only", false, "print estimated token count and byte size of the context, then exit")
	cmd.Flags().BoolVar(&f.full, "full", false, "include full doc comments and complete example bodies (overrides --compact)")
	cmd.Flags().StringVar(&f.gomodPath, "gomod", "", "path to a go.mod file; run the pipeline over the project's code dependencies and print a summary (default: ./go.mod)")
	cmd.Flags().BoolVar(&f.tool, "tool", false, "scope to the tooling supply chain (the go.mod tool directives' closure)")
	cmd.Flags().BoolVar(&f.project, "project", false, "scope to the complete set: the project's code AND tooling")
	registerNoProgressFlag(cmd, &f.noProgress)
	registerStdlibFromGoModFlag(cmd, &f.stdlibFromGoMod)
	registerRecordedTestScopeFlag(cmd, &f.excludeTests)

	return cmd
}

func runInspect(ctx context.Context, arg string, f inspectFlags, stdout, stderr io.Writer) error {
	// --stdlib-from-gomod pins the stdlib node to a project go.mod's toolchain
	// directive, and --gomod/--tool/--project name a go.mod scope; a coordinate
	// walk has no project go.mod behind it, so it can act on none of them.
	// Refuse them by name rather than parse and drop them.
	var refused []inapplicableFlag
	if f.stdlibFromGoMod {
		refused = append(refused, inapplicableFlag{flag: "--stdlib-from-gomod", where: "inspect --gomod"})
	}
	refused = append(refused, inspectGoModOnlyFlags(f)...)
	if err := refuseInapplicableFlags("inspect <module>@<version>", refused); err != nil {
		return err
	}
	// A coordinate inspect walks the module named on the command line, so there
	// is no dependency scope to narrow — and it records that walk either way.
	if rerr := refuseTestScopeOnRecordingCommand("inspect <module>@<version>", f.excludeTests); rerr != nil {
		return rerr
	}

	wf := commonWalkFlags{
		goproxy: f.goproxy,
	}

	logger := buildLogger(logLevel, stderr)
	ctr, cleanup, err := NewContainer(storeRoot, f.goproxy, f.goBinary, f.skipVCS, activeConfig, logger)
	if err != nil {
		return fmt.Errorf("initialising store: %w", err)
	}
	defer func() { _ = cleanup() }()

	// Step 1: walk
	if _, err := fmt.Fprintf(stderr, "==> inspect: walking %s\n", arg); err != nil {
		return fmt.Errorf("writing output: %w", err)
	}
	progress := newWalkProgressReporter(stderr, f.noProgress, activeConfig, logLevel)
	walkResult, err := runWalk(ctx, arg, wf, f.force, true, 0, "", f.policyPath, f.skipVCS, domain.WalkScopeCode, domain.WalkDepthFull, "", progress, ctr.ExecuteWalk, nil, io.Discard, stderr)
	if err != nil {
		return fmt.Errorf("walk: %w", err)
	}

	// Resolve the coordinate (handles @latest) so the context step names the
	// coordinate the walk actually ran against.
	coord, err := resolveCoordForInspect(ctx, arg, storeRoot, f.goproxy, stderr)
	if err != nil {
		return err
	}

	// Step 2: the walk this run produced. No walk is selected here — the record
	// comes back from the walk above, so nothing has to guess which of the
	// store's walks of this coordinate the following steps mean. Asking the store
	// for the newest one instead was wrong in two ways at once: identity reuse
	// serves an existing record when the resolution is unchanged and keeps its
	// original started_at, so this run's walk need not be the newest; and the
	// lookup had no scope or build-environment axis, so another scope's or
	// another platform's walk of the same coordinate could answer for it.
	walkRec := walkResult.Record
	walkID := walkRec.ID

	// Step 3: extract. The banner names the frame the walk was resolved in.
	if _, err := fmt.Fprintf(stderr, "==> inspect: extracting walk %s (frame %s)\n", walkID, walkRec.Graph.Frame()); err != nil {
		return fmt.Errorf("writing output: %w", err)
	}
	ef := extractFlags{
		goBinary:   f.goBinary,
		stages:     []string{"license", "interface", "callgraph", "example"},
		force:      f.force,
		noProgress: f.noProgress,
	}
	extractRun, err := extractWalk(ctx, walkID, ef, stderr)
	if err != nil {
		return fmt.Errorf("extract: %w", err)
	}
	printExtractionFailures(stderr, extractRun)

	// Step 4: vuln-scan
	if _, err := fmt.Fprintf(stderr, "==> inspect: scanning vulnerabilities for walk %s (frame %s)\n", walkID, walkRec.Graph.Frame()); err != nil {
		return fmt.Errorf("writing output: %w", err)
	}
	// The scan's result channel goes to stderr, not io.Discard: it carries the
	// grouped roll-up (one heading per category, one line per coordinate) that
	// the per-module stream deliberately does not repeat. Discarding it left the
	// reader with the repetitive half of the presentation and threw away the
	// concise half. stdout stays the clean data channel because inspect always
	// scans with jsonOut=false, so nothing machine-readable is written here.
	scan, serr := runVulnScanReporting(ctx, walkID, f.force, f.fresh, f.reachable, 1, false, false, f.goBinary, os.Getenv("USER"), "", f.policyPath, vulnapp.ServeSurfaceInspect, false, f.noProgress, true, true, stderr, stderr)
	if serr != nil {
		return fmt.Errorf("vuln-scan: %w", serr)
	}

	// Step 5: context
	if _, err := fmt.Fprintf(stderr, "==> inspect: building context for %s\n", coord.String()); err != nil {
		return fmt.Errorf("writing output: %w", err)
	}
	cf := contextFlags{
		compact:  !f.full,
		sizeOnly: f.sizeOnly,
		full:     f.full,
	}
	// A walk or scan that failed returned above, so both stages completed: what
	// is left to state is whether each was measured here or served from the store.
	scanState := inspectScanState(scan, nil)
	return runInspectContext(ctx, coord.String(), cf, inspectRunSection{
		WalkID:    walkID,
		Walk:      inspectWalkState(walkResult, nil),
		ScanRunID: scan.RunID,
		Scan:      scanState,
		Snapshot:  scan.Snapshot,
		Toolchain: inspectToolchain(scan, scanState),
	}, stdout, stderr)
}

// resolveCoordForInspect parses the module arg, resolving @latest if needed.
func resolveCoordForInspect(ctx context.Context, arg, _, goproxy string, stderr io.Writer) (coordinate.ModuleCoordinate, error) {
	path, version, err := parseModuleArg(arg)
	if err != nil {
		return coordinate.ModuleCoordinate{}, fmt.Errorf("invalid argument %q: %w", arg, err)
	}
	if version == "latest" {
		proxy, err := proxyadapter.New(goproxy, false)
		if err != nil {
			return coordinate.ModuleCoordinate{}, proxyAdapterError(err)
		}
		return resolveLatest(ctx, path, proxy, stderr)
	}
	coord, err := coordinate.NewModuleCoordinate(path, version)
	if err != nil {
		return coordinate.ModuleCoordinate{}, fmt.Errorf("invalid coordinate %q: %w", arg, err)
	}
	return coord, nil
}

// inspectSummary is the aggregate result of an inspect --gomod run.
type inspectSummary struct {
	ModuleCount int `json:"module_count"`
	// The three failure tallies are counted by every run and emitted at zero. A
	// run in which nothing failed is the result a reader most needs stated, and
	// omitting the zeros made a clean run's summary the same document as one
	// from a build that does not count failures at all.
	NodeFails    int `json:"node_fails"`
	ExtractFails int `json:"extract_fails"`
	// ExtractFailures names what ExtractFails counts. A tally on its own tells a
	// reader that some module's public API is unmeasured without saying whose,
	// and there is no prose on either stream that does.
	ExtractFailures []extractStageFailure `json:"extract_failures"`
	ScanFails       int                   `json:"scan_fails"`
	OverallStatus   string                `json:"overall_status"`
	AffectedCount   int                   `json:"affected_count"`
	SnapshotVersion string                `json:"snapshot_version,omitempty"`
	WalkIDs         []string              `json:"walk_ids"`
	// WalkFrame is the GOOS/GOARCH the answering project walk resolved for, and
	// WalkFrameBasis the same fact as data: "platform", "not_platform_scoped" for
	// a module-rooted walk (no platform applies), or "unrecorded" (the platform
	// is not known). Both are always present: a reader cannot tell an unstated
	// frame from a missing one.
	WalkFrame      string `json:"walk_frame"`
	WalkFrameBasis string `json:"walk_frame_basis"`
	// DependencyScope names the go.mod dependency scope the pipeline ran over and
	// the test axis that scope applied. Always present, for the reason WalkFrame
	// is: both are axes that move the module count, and a summary that states one
	// and not the other invites the reader to treat the silent one as fixed.
	DependencyScope *scopeJSON         `json:"dependency_scope"`
	Directives      *directivesSection `json:"directives,omitempty"`
	GoDebug         *godebugSection    `json:"godebug,omitempty"`
	Vendor          *vendorSection     `json:"vendor,omitempty"`
	// Build states whether the project compiles from a vendored tree, so a
	// consumer of this document can see which of two things every other section
	// describes: the modules the manifest resolves, or the bytes that ship. It
	// is absent only when there was no project directory to look in — an
	// unanswered question, which is not the same as a negative answer, and the
	// two must not decode alike.
	Build *buildVendoring `json:"build,omitempty"`
	// Run is what this pipeline did: which walk answered, which scan, whether
	// either was reused, and what the toolchain was judged to be. Every other
	// field is about the modules; without this one the document reports an
	// analysis without saying what performed it.
	Run inspectRunSection `json:"run"`
}

// ---- what inspect states about the run it just performed ----

// The states a pipeline stage can be in. "not run" and "attempted and failed"
// are values the document states, never keys it leaves out: a stage that is
// simply absent reads as one that ran and found nothing.
const (
	inspectStageMeasured = "measured by this run"
	inspectStageReused   = "reused"
	inspectStageNotRun   = "not run"
	inspectStageFailed   = "attempted and failed"
)

// inspectRunSection is what inspect states about the run itself.
//
// The rest of the document is about a module, or about the modules a manifest
// resolved, and has nowhere to say which walk, which scan and which advisory
// database answered for them. inspect states all of it on stderr, where no
// machine reader sees it.
type inspectRunSection struct {
	WalkID string `json:"walk_id"`
	// Walk and Scan are the stage states above: what this run did, rather than
	// only what it ended up with.
	Walk      string `json:"walk"`
	ScanRunID string `json:"scan_run_id"`
	Scan      string `json:"scan"`
	// Snapshot is the advisory database generation the scan was judged against.
	Snapshot vulnScanSnapshotJSON `json:"snapshot"`
	// Toolchain is the scan's toolchain judgment, including the case where none
	// was made and why.
	Toolchain vulnScanToolchainJSON `json:"toolchain"`
}

// inspectWalkState names what this run did about the walk stage.
func inspectWalkState(result application.ExecuteWalkResult, err error) string {
	switch {
	case err != nil:
		return inspectStageFailed
	case result.Record.ID == "":
		return inspectStageNotRun
	case result.Reused:
		return inspectStageReused
	default:
		return inspectStageMeasured
	}
}

// inspectScanState names what this run did about the vulnerability scan.
//
// A scan that produced a run measured or reused one even where it exits non-zero
// for partial coverage — that gap is the summary's own field. Only a scan that
// produced no run at all is reported as failed.
func inspectScanState(facts vulnScanRunFacts, err error) string {
	switch {
	case facts.RunID != "" && facts.Reused:
		return inspectStageReused
	case facts.RunID != "":
		return inspectStageMeasured
	case err != nil:
		return inspectStageFailed
	default:
		return inspectStageNotRun
	}
}

// inspectToolchain carries the scan's toolchain judgment, or states why there is
// none. A run with no judgment says so and why: an absent one reads as a clear.
func inspectToolchain(facts vulnScanRunFacts, scanState string) vulnScanToolchainJSON {
	if facts.Toolchain.Status != "" {
		return facts.Toolchain
	}
	if scanState == inspectStageFailed {
		return unjudgedToolchainSection("the vulnerability scan did not complete, so it judged no toolchain")
	}
	return unjudgedToolchainSection("no vulnerability scan ran in this pipeline, so nothing judged the toolchain")
}

// inspectRunNotStarted is the run section for a pipeline that had nothing to
// run — an empty dependency scope stops before the walk.
func inspectRunNotStarted() inspectRunSection {
	return inspectRunSection{
		Walk:      inspectStageNotRun,
		Scan:      inspectStageNotRun,
		Toolchain: inspectToolchain(vulnScanRunFacts{}, inspectStageNotRun),
	}
}

// runInspectContext prints the context document with the facts of the run that
// produced it.
//
// Under --json the per-module content is passed through exactly as `context`
// rendered it — the same bytes, in the same order — and the run section is
// inserted beside it as one added key.
func runInspectContext(ctx context.Context, arg string, f contextFlags, run inspectRunSection, stdout, stderr io.Writer) error {
	if !jsonOut {
		return runContext(ctx, arg, f, stdout, stderr)
	}
	var doc bytes.Buffer
	if cerr := runContext(ctx, arg, f, &doc, stderr); cerr != nil {
		// Whatever it rendered before failing is still the reader's.
		if _, werr := stdout.Write(doc.Bytes()); werr != nil {
			return fmt.Errorf("writing output: %w", werr)
		}
		return cerr
	}
	out, serr := spliceInspectRun(doc.Bytes(), run)
	if serr != nil {
		return serr
	}
	if _, werr := stdout.Write(out); werr != nil {
		return fmt.Errorf("writing output: %w", werr)
	}
	return nil
}

// spliceInspectRun inserts the run section as the document's first key, leaving
// every byte that follows exactly as it was rendered.
//
// A document that is not an object is refused rather than printed without its
// run facts: there is nowhere to put the key, and printing the answer anyway is
// the silence this section exists to end.
func spliceInspectRun(doc []byte, run inspectRunSection) ([]byte, error) {
	section, err := json.MarshalIndent(run, "  ", "  ")
	if err != nil {
		return nil, fmt.Errorf("marshalling the run section: %w", err)
	}
	lead := len(doc) - len(bytes.TrimLeft(doc, " \t\r\n"))
	body := doc[lead:]
	if len(body) == 0 || body[0] != '{' {
		return nil, fmt.Errorf(
			"inspect cannot state the facts of its run: the context rendering is not a JSON object")
	}
	rest := body[1:]
	separator := ","
	if bytes.HasPrefix(bytes.TrimLeft(rest, " \t\r\n"), []byte("}")) {
		// An object with no other keys: a comma would leave trailing punctuation.
		separator = "\n"
	}
	var out bytes.Buffer
	out.Write(doc[:lead])
	out.WriteString("{\n  \"run\": ")
	out.Write(section)
	out.WriteString(separator)
	out.Write(rest)
	return out.Bytes(), nil
}

// inspectExtractTally reports how many stages failed, and which.
//
// From the recorded run, not a returned error: a partial extraction returns
// none, so deriving the tally from one could only ever read 0 or 1. An
// extraction that produced no run at all yields 1 — nothing to count, and zero
// is the answer it must not give.
func inspectExtractTally(run extractdomain.ExtractionRun, err error) (int, []extractStageFailure) {
	if err != nil {
		return 1, []extractStageFailure{}
	}
	failures := extractionFailures(run)
	return len(failures), failures
}

// inspectSummaryStatus derives the aggregate status for inspect's summary.
//
// Any failed stage — walk, extract, or vuln-scan — means part of the dependency
// set was not analysed, so the result must surface as partial rather than a
// confident AllClean: an unscanned set presented as clean is the
// absence-as-answer defect class.
//
// scanStatus is the underlying vuln-scan run's own verdict, which must be
// carried forward rather than re-derived: a run can be Partial (metadata-only
// or unscannable modules) or ScanFailed (every module failed, or the walk had
// no modules at all) without producing any stage failure here.
//
// The rule is deliberately inverted — AllClean is returned only when the scan
// run positively says AllClean. An empty scanStatus (no run recorded, or the
// run could not be read) and any status not enumerated here both fall through
// to Partial. Enumerating the non-clean statuses instead would silently report
// AllClean for a status added to the enum later, which is the same defect this
// function exists to prevent.
//
// The word is coverage-first and is not promoted to Affected by the finding
// count: scanStatus already collapses coverage over findings (a run left Partial
// by an unscannable module reports Partial even with findings), and the affected
// count is presented on its own line. Keying the word on the count instead would
// flip such a run's word to Affected and hide the coverage gap — the same
// two-axis collapse this cluster removes, and it would make inspect disagree with
// vuln-scan about the same run.
func inspectSummaryStatus(nodeFails, extractFails, scanFails int, scanStatus vuldomain.WalkScanStatus) string {
	switch {
	case scanStatus == vuldomain.WalkStatusFailed:
		return string(vuldomain.WalkStatusFailed)
	case nodeFails > 0 || extractFails > 0 || scanFails > 0:
		return string(vuldomain.WalkStatusPartial)
	case scanStatus == vuldomain.WalkStatusAffected:
		return string(vuldomain.WalkStatusAffected)
	case scanStatus == vuldomain.WalkStatusAllClean:
		return string(vuldomain.WalkStatusAllClean)
	default:
		return string(vuldomain.WalkStatusPartial)
	}
}

// inspectExit maps the summary roll-up onto the process exit code.
//
// Only Partial is mapped: part of the dependency set went unanalysed, which is
// exit 1's definition. The word alone was not enough — a caller reading the exit
// code learned nothing from a run that had already stopped saying AllClean.
func inspectExit(overallStatus string) error {
	if overallStatus != string(vuldomain.WalkStatusPartial) {
		return nil
	}
	return &exitError{code: ExitPartial, msg: "inspect partial: some of the dependency set was not analysed"}
}

// inspectBuildSection carries the vendoring answer into the summary document,
// and carries nothing when the question could not be answered. A pointer rather
// than a value because the absent case must decode as absent: a zero-valued
// object would read as "asked, and not vendored", which is a stronger claim
// than the run is entitled to make.
func inspectBuildSection(v buildVendoring) *buildVendoring {
	if !v.Known {
		return nil
	}
	return &v
}

// writeEmptyInspectScope emits inspect's answer for a scope that resolved to no
// dependencies, in the active output format. Under --json it is an
// inspectSummary object with zeroed counts and no walks — the same type the
// populated path emits, with status derived the same way a zero-module run
// derives it — so empty and populated results decode alike. On the text path it
// is the human sentence.
func writeEmptyInspectScope(scope depScope, gomodPath string, stdout io.Writer) error {
	if jsonOut {
		enc := json.NewEncoder(stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(inspectSummary{
			ExtractFailures: []extractStageFailure{},
			OverallStatus:   inspectSummaryStatus(0, 0, 0, ""),
			WalkIDs:         []string{},
			DependencyScope: newScopeJSON(newScopeResolution(scope, false)),
			Run:             inspectRunNotStarted(),
		}); err != nil {
			return fmt.Errorf("encoding summary: %w", err)
		}
		return nil
	}
	_, _ = fmt.Fprintf(stdout, "no %s dependencies found in %s\n", scope, gomodPath)
	return nil
}

// refuseInspectGoModFlags refuses the flags a go.mod inspect cannot act on.
//
// --full shapes a context document's rendering, and a --gomod inspect prints a
// pipeline summary instead. --exclude-tests narrows a dependency scope, which a
// command that records a walk cannot take: see
// refuseTestScopeOnRecordingCommand.
func refuseInspectGoModFlags(f inspectFlags) error {
	var refused []inapplicableFlag
	if f.full {
		refused = append(refused, inapplicableFlag{flag: "--full", where: "inspect <module>@<version>"})
	}
	if err := refuseInapplicableFlags("inspect --gomod", refused); err != nil {
		return err
	}
	return refuseTestScopeOnRecordingCommand("inspect --gomod", f.excludeTests)
}

// runInspectGoMod runs the full pipeline for the local project using a single
// project-rooted walk. The walk resolves Go's pruned module graph (the same
// validated build inputs every other go.mod command uses), then extract and
// vuln-scan operate on that one walk record.
func runInspectGoMod(ctx context.Context, f inspectFlags, scope depScope, stdout, stderr io.Writer) error {
	if err := refuseInspectGoModFlags(f); err != nil {
		return err
	}

	// For code and tool scopes, check whether the scope is empty before
	// spinning up the project walk. An empty import closure is valid but
	// produces no dependency analysis; surface it early and clearly.
	if scope != scopeComplete {
		mods, _, cerr := resolveScopeModules(ctx, f.gomodPath, scope, false)
		if cerr == nil && len(mods) == 0 {
			if f.sizeOnly {
				// A size question about an empty scope gets the zero-module size
				// report, matching what 'context --gomod --size-only' answers for
				// the same scope.
				var report contextSizeReport
				return report.write(jsonOut, stdout)
			}
			return writeEmptyInspectScope(scope, f.gomodPath, stdout)
		}
	}

	// A project walk has a local go.sum available: layer it on as an always-on
	// offline integrity check.
	resolveProjectGoSum(f.gomodPath)

	logger := buildLogger(logLevel, stderr)
	ctr, cleanup, err := NewContainer(storeRoot, f.goproxy, f.goBinary, f.skipVCS, activeConfig, logger)
	if err != nil {
		return fmt.Errorf("initialising store: %w", err)
	}
	defer func() { _ = cleanup() }()

	modulePath, err := readGoModulePath(f.gomodPath)
	if err != nil {
		return err
	}

	_, _ = fmt.Fprintf(stderr, "==> inspect --gomod: walking project %s\n", f.gomodPath)

	var nodeFails int
	progress := newWalkProgressReporter(stderr, f.noProgress, activeConfig, logLevel)
	walkResult, werr := runWalkProject(ctx, f.gomodPath, f.force, true, 0, "", f.policyPath, f.skipVCS, scope,
		domain.WalkDepthFull, "", false, f.stdlibFromGoMod, progress, ctr.ExecuteWalk, nil, io.Discard, stderr)
	if werr != nil {
		_, _ = fmt.Fprintf(stderr, "walk: %v\n", werr)
		nodeFails = 1
	}

	projectWalk, qerr := inspectProjectWalk(ctx, ctr, walkResult, modulePath, scope)
	if qerr != nil {
		return qerr
	}
	walkID, moduleCount, walkFails := projectWalk.ID, projectWalk.NodeCount, projectWalk.FailureCount
	if walkFails > 0 && nodeFails == 0 {
		nodeFails = walkFails
	}

	var extractFails, scanFails int
	var scanFacts vulnScanRunFacts
	scanState := inspectStageNotRun
	extractFailures := []extractStageFailure{}
	if walkID != "" {
		_, _ = fmt.Fprintf(stderr, "==> inspect --gomod: extracting walk %s (frame %s)\n", walkID, projectWalk.BuildFrame())
		ef := extractFlags{
			goBinary:   f.goBinary,
			stages:     []string{"license", "interface", "callgraph", "example"},
			force:      f.force,
			noProgress: f.noProgress,
		}
		extractRun, eerr := extractWalk(ctx, walkID, ef, stderr)
		extractFails, extractFailures = inspectExtractTally(extractRun, eerr)
		if eerr != nil {
			_, _ = fmt.Fprintf(stderr, "extract: %v\n", eerr)
		}
		printExtractionFailures(stderr, extractRun)

		// The project walk roots at the consumer module but analyses its own code
		// in consumer-mode, so the target's call graph is never loaded into the
		// store. Reachability therefore roots at the dependency closure, one hop
		// short of the project entrypoints. Disclose that up front so a reader
		// cannot mistake a dep-closure verdict for an app-rooted one.
		if f.reachable {
			printReachabilityClosureBanner(stderr, f.gomodPath)
		}

		_, _ = fmt.Fprintf(stderr, "==> inspect --gomod: vuln-scanning walk %s\n", walkID)
		// stderr, not io.Discard — see the note on the same call in runInspect:
		// the grouped roll-up is the concise presentation and belongs to the
		// reader, while stdout stays reserved for the context output.
		var verr error
		scanFacts, verr = runVulnScanReporting(ctx, walkID, f.force, f.fresh, f.reachable, 1, false, false, f.goBinary, os.Getenv("USER"), filepath.Dir(f.gomodPath), f.policyPath, vulnapp.ServeSurfaceInspect, false, f.noProgress, true, true, stderr, stderr)
		scanState = inspectScanState(scanFacts, verr)
		if verr != nil {
			_, _ = fmt.Fprintf(stderr, "vuln-scan: %v\n", verr)
			scanFails = 1
		}
	}

	// --size-only asks what the context this pipeline just made answerable
	// would cost to pull, so it replaces the summary — the summary's own job is
	// to point at 'context --gomod' for the context step, and that is the path
	// that answers the size question. Delegating keeps one answer shape: a
	// total plus a per-module breakdown, the same report the same question gets
	// from 'context --gomod --size-only' and 'context --walk-id --size-only'.
	if f.sizeOnly {
		return runContextGoMod(ctx, contextFlags{
			sizeOnly:  true,
			compact:   true,
			gomodPath: f.gomodPath,
		}, scope, stdout, stderr)
	}

	affectedCount, snapshotVersion, scanStatus := readInspectScanRun(ctx, ctr, walkID, stderr)

	walkIDs := []string{}
	if walkID != "" {
		walkIDs = []string{walkID}
	}

	overallStatus := inspectSummaryStatus(nodeFails, extractFails, scanFails, scanStatus)

	// What every section below is about. inspect runs the whole pipeline over a
	// manifest, so the ambiguity it carries is the widest of the four: the
	// vendor section measures shipped bytes and every other section measures
	// resolved modules, in one document.
	vendoring := detectBuildVendoringForGoMod(f.gomodPath)
	if verr := writeBuildVendoring(stderr, vendoring); verr != nil {
		return verr
	}

	if jsonOut {
		var directives *directivesSection
		if rec, derr := ctr.ExtractDirectives.Extract(ctx, f.gomodPath, activeConfig.DirectivePolicy); derr == nil {
			s := toDirectivesSection(rec)
			directives = &s
		} else {
			_, _ = fmt.Fprintf(stderr, "==> inspect: directive scan skipped: %v\n", derr)
		}
		var godebug *godebugSection
		if rec, derr := ctr.ExtractGoDebug.Extract(ctx, f.gomodPath, activeConfig.GoDebugPolicy); derr == nil {
			s := toGoDebugSection(rec)
			godebug = &s
		} else {
			_, _ = fmt.Fprintf(stderr, "==> inspect: godebug scan skipped: %v\n", derr)
		}
		var vendor *vendorSection
		if rec, derr := ctr.ExtractVendor.Extract(ctx, f.gomodPath, activeConfig.VendorPolicy.VendorOnly, activeConfig.VendorPolicy); derr == nil {
			s := toVendorSection(rec)
			vendor = &s
		} else if !errors.Is(derr, vendports.ErrNotVendored) {
			_, _ = fmt.Fprintf(stderr, "==> inspect: vendor scan skipped: %v\n", derr)
		}
		enc := json.NewEncoder(stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(inspectSummary{
			ModuleCount:     moduleCount,
			NodeFails:       nodeFails,
			ExtractFails:    extractFails,
			ExtractFailures: extractFailures,
			ScanFails:       scanFails,
			OverallStatus:   overallStatus,
			AffectedCount:   affectedCount,
			SnapshotVersion: snapshotVersion,
			WalkIDs:         walkIDs,
			WalkFrame:       projectWalk.Frame().Text,
			WalkFrameBasis:  string(projectWalk.Frame().Basis),
			DependencyScope: newScopeJSON(newScopeResolution(scope, false)),
			Directives:      directives,
			GoDebug:         godebug,
			Vendor:          vendor,
			Build:           inspectBuildSection(vendoring),
			Run: inspectRunSection{
				WalkID:    walkID,
				Walk:      inspectWalkState(walkResult, werr),
				ScanRunID: scanFacts.RunID,
				Scan:      scanState,
				Snapshot:  scanFacts.Snapshot,
				Toolchain: inspectToolchain(scanFacts, scanState),
			},
		}); err != nil {
			return fmt.Errorf("encoding summary: %w", err)
		}
		return inspectExit(overallStatus)
	}

	_, _ = fmt.Fprintf(stdout, "Status:   %s\n", overallStatus)
	// Beside the module count, never below it: the count is the figure the scope
	// decided, and the two axes that move it are the frame (already stated on the
	// walk line) and this one.
	_, _ = fmt.Fprintf(stdout, "Scope:    %s — %s\n", scope, newScopeResolution(scope, false).statement())
	_, _ = fmt.Fprintf(stdout, "Modules:  %d (%d failed)\n", moduleCount, nodeFails)
	_, _ = fmt.Fprintf(stdout, "Affected: %d\n", affectedCount)
	if extractFails > 0 {
		_, _ = fmt.Fprintf(stdout, "Extract fails: %d\n", extractFails)
	}
	if scanFails > 0 {
		_, _ = fmt.Fprintf(stdout, "Scan fails: %d (vulnerability status unknown)\n", scanFails)
	}
	if snapshotVersion != "" {
		_, _ = fmt.Fprintf(stdout, "Snapshot: %s\n", snapshotVersion)
	}
	if walkID != "" {
		_, _ = fmt.Fprintf(stdout, "Walk ID:  %s\n", walkID)
		_, _ = fmt.Fprintf(stdout, "Frame:    %s\n", projectWalk.BuildFrame())
		_, _ = fmt.Fprintf(stdout, "\nTo get module context: kanonarion context --gomod %s\n", f.gomodPath)
	}
	return inspectExit(overallStatus)
}

// printReachabilityClosureBanner discloses that --gomod reachability roots at
// the dependency closure rather than the project's own entrypoints. The
// consumer module is walked but analysed in consumer-mode, so its call graph is
// not in the store; a reachable verdict therefore means "reachable from the
// closure roots", one hop short of "reachable from a project entrypoint". This
// must be stated explicitly so the two cannot be confused. Directs the reader
// to `kanonarion local`, which ingests the target graph and roots at the app.
func printReachabilityClosureBanner(w io.Writer, gomodPath string) {
	projectDir := filepath.Dir(gomodPath)
	_, _ = fmt.Fprintln(w, "==> NOTE: reachability is rooted at the DEPENDENCY CLOSURE, not the project's own code.")
	_, _ = fmt.Fprintln(w, "    The consumer module is analysed in consumer-mode, so its call graph is not")
	_, _ = fmt.Fprintln(w, "    loaded: a 'reachable' answer means reachable from the closure roots, one hop")
	_, _ = fmt.Fprintln(w, "    short of reachable from a project entrypoint. The final app->dependency edge")
	_, _ = fmt.Fprintln(w, "    is absent from this analysis.")
	_, _ = fmt.Fprintf(w, "    To root reachability at the application, run: kanonarion local %s\n", projectDir)
}

// inspectProjectWalk is the walk the following steps report on.
//
// It is the record the walk above produced, not a fresh "newest walk of this
// project at this scope" lookup: identity reuse serves an existing record when
// the resolution is unchanged and keeps its original started_at, so the walk a
// run produced can be older than another walk of the same target and scope. The
// store lookup remains only for the case where the walk failed before producing
// a record, where reporting on what the store already holds is all that is left.
func inspectProjectWalk(ctx context.Context, ctr *Container, result application.ExecuteWalkResult,
	modulePath string, scope depScope,
) (walkports.WalkSummary, error) {
	if sum := walkSummaryOf(result.Record); sum.ID != "" {
		return sum, nil
	}
	return latestProjectWalkSummary(ctx, ctr.QueryWalks, modulePath, scope)
}

// walkSummaryOf projects the record a walk run returned into the summary shape
// the reporting below reads, so a caller that has the record in hand does not
// re-derive it from a store lookup that could land on a different walk. The zero
// summary means the run produced no record.
func walkSummaryOf(rec domain.WalkRecord) walkports.WalkSummary {
	if rec.ID == "" {
		return walkports.WalkSummary{}
	}
	return walkports.WalkSummary{
		ID:            rec.ID,
		Target:        rec.Target,
		Scope:         rec.Scope,
		Depth:         rec.Depth,
		OverallStatus: rec.OverallStatus,
		NodeCount:     len(rec.Graph.Nodes),
		FailureCount:  countFailures(rec),
		GOOS:          rec.Graph.BuildEnv.GOOS,
		GOARCH:        rec.Graph.BuildEnv.GOARCH,
	}
}

// latestProjectWalkSummary returns the most recent walk rooted at the local main
// module under scope. The zero summary means no such walk has been recorded,
// which is not an error: the caller reports on what the store holds.
func latestProjectWalkSummary(ctx context.Context, q QueryWalksUseCase, modulePath string, scope depScope) (walkports.WalkSummary, error) {
	localCoord, err := coordinate.NewLocalCoordinate(modulePath)
	if err != nil {
		return walkports.WalkSummary{}, fmt.Errorf("project coordinate for %s: %w", modulePath, err)
	}
	walkScope := domain.WalkScope(scope)
	walks, err := q.ListWalks(ctx, walkports.WalkFilter{Target: &localCoord, Scope: &walkScope, Limit: 1})
	if err != nil {
		return walkports.WalkSummary{}, fmt.Errorf("querying project walk: %w", err)
	}
	if len(walks) == 0 {
		return walkports.WalkSummary{}, nil
	}
	return walks[0], nil
}

// readInspectScanRun reads the walk's latest scan run for the --gomod summary.
// scanStatus stays empty when the run cannot be read or none was recorded.
// That is reported, not swallowed: inspectSummaryStatus treats an unknown
// scan outcome as not-clean rather than assuming the best.
func readInspectScanRun(ctx context.Context, ctr *Container, walkID string, stderr io.Writer) (affectedCount int, snapshotVersion string, scanStatus vuldomain.WalkScanStatus) {
	if walkID == "" {
		return 0, "", ""
	}
	runs, rerr := ctr.QueryScanRuns.ListRunsForWalk(ctx, walkID)
	switch {
	case rerr != nil:
		_, _ = fmt.Fprintf(stderr, "==> inspect: reading scan run for walk %s: %v\n", walkID, rerr)
	case len(runs) == 0:
		_, _ = fmt.Fprintf(stderr, "==> inspect: no scan run recorded for walk %s\n", walkID)
	default:
		scanStatus = runs[0].OverallStatus
		// Key the affected count on the findings axis, not the collapsed
		// OverallStatus: a run left Partial by an unscannable module still
		// reports FindingsStatus == Affected, so keying on OverallStatus made
		// the count 0 over real findings. Read the real count from the
		// run's stored counts rather than re-deriving it — a walk with 100
		// affected modules must report 100, not a 0/1 flag.
		if runs[0].FindingsStatus == vuldomain.FindingsAffected {
			affectedCount = runs[0].Counts.Affected
		}
		snapshotVersion = runs[0].Snapshot.Version()
	}
	return affectedCount, snapshotVersion, scanStatus
}
