package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"

	fetchdomain "github.com/eitanity/kanonarion/internal/fetch/domain"
	vuldomain "github.com/eitanity/kanonarion/internal/vuln/domain"
	walkports "github.com/eitanity/kanonarion/internal/walk/ports"
)

type contextFlags struct {
	compact         bool
	full            bool
	sizeOnly        bool
	entryPointsFull bool
	packageFilter   string
	walkID          string
	gomodPath       string
	tool            bool
	project         bool
	stream          bool
	directOnly      bool
	affectedOnly    bool
	modulesFile     string
	symbol          bool // local workspace: enable symbol-level analysis
	reachability    bool // local workspace: build probe binary and check CVE symbol presence
	excludeTests    bool // local workspace: narrow the answer to production-scope dependency users
	// compactSet records whether the caller typed --compact. The flag defaults
	// to true, so its value alone cannot distinguish "asked for compact" from
	// "did not ask"; a path that has to refuse the flag needs the difference.
	compactSet bool
}

// -- output types --

type contextCommands struct {
	Interface       string `json:"interface"`
	CallGraph       string `json:"call_graph"`
	CallGraphNav    string `json:"call_graph_nav"`
	Examples        string `json:"examples"`
	Vulnerabilities string `json:"vulnerabilities"`
	License         string `json:"license"`
	Dependents      string `json:"dependents"`
}

type contextOutput struct {
	Module          contextModuleInfo      `json:"module"`
	Commands        contextCommands        `json:"commands"`
	Verification    contextVerification    `json:"verification"`
	Provenance      contextProvenance      `json:"provenance"`
	Dependencies    contextDependencies    `json:"dependencies"`
	License         contextLicense         `json:"license"`
	Interface       contextInterface       `json:"interface"`
	CallGraph       contextCallGraph       `json:"call_graph"`
	Examples        contextExamples        `json:"examples"`
	Vulnerabilities contextVulnerabilities `json:"vulnerabilities"`
}

// contextForkIndicator is one caveated name-path fork inference.
type contextForkIndicator struct {
	Canonical string `json:"canonical"`
	Statement string `json:"statement"`
}

// contextForkHeuristic carries the cheap-tier name-path fork heuristic result.
// Status is "none" or "path_match" when the heuristic ran; "not_analysed" is
// reserved for surfaces that did not run it, so analysed-no-fork is never
// conflated with absence of analysis.
type contextForkHeuristic struct {
	Status           string                 `json:"status"`
	CatalogueVersion string                 `json:"catalogue_version"`
	ForkIndicators   []contextForkIndicator `json:"fork_indicators,omitempty"`
}

// contextProvenance groups provenance facts about the module's identity.
// Today it holds only the fork heuristic; stronger provenance facts (VCS
// origin, content overlap) extend it additively.
type contextProvenance struct {
	ForkHeuristic contextForkHeuristic `json:"fork_heuristic"`
}

type contextModuleInfo struct {
	Path    string `json:"path"`
	Version string `json:"version"`
}

// Sentinel status values used when a record is absent or unreadable.
const (
	sectionStatusNotFetched = "not_fetched" // verification: module not yet fetched
	sectionStatusNotRun     = "not_run"     // extraction pipeline has not run for this section
	sectionStatusReadError  = "read_error"  // store returned an error when reading the record
	// sectionStatusSuperseded: a record exists for this coordinate, but every
	// stored generation was produced by superseded pipeline logic, so this
	// build serves none of them. Distinct from not_run: the work was done and
	// must be done again, which is a different instruction to the reader.
	sectionStatusSuperseded = "superseded"
)

// Fork-heuristic status strings, mirrored from the domain status names so the
// renderers branch on the same vocabulary the builder emits.
var (
	forkStatusNone      = fetchdomain.ForkProvenanceNone.String()
	forkStatusPathMatch = fetchdomain.ForkProvenancePathMatch.String()
)

type contextVerification struct {
	ExtractedAt string `json:"extracted_at,omitempty"` // ISO-8601; set when record exists
	Status      string `json:"status"`
	GitURL      string `json:"git_url,omitempty"`
	// Retracted is the module author's own withdrawal of this version, read off
	// the fetched record. It is emitted on every section, false included: the
	// record either states a retraction or states there is none, and Status
	// names the sections where no record was read at all.
	Retracted bool   `json:"retracted"`
	Error     string `json:"error,omitempty"` // set when status is read_error
}

type contextDependency struct {
	Path    string `json:"path"`
	Version string `json:"version"`
}

type contextDependencies struct {
	Status string `json:"status"`
	WalkID string `json:"walk_id,omitempty"`
	// Frame is the GOOS/GOARCH the answering walk resolved for, or a token
	// standing for the reason there is none, and FrameBasis is that reason as
	// data: "platform", "not_platform_scoped" for a module-rooted walk (no
	// platform applies), or "unrecorded" (the platform is not known). Both are
	// present whenever a walk answered: GOOS gates which files build, so a
	// dependency list for a project is a list for one platform.
	Frame      string `json:"frame,omitempty"`
	FrameBasis string `json:"frame_basis,omitempty"`
	// Count and Partial are emitted whenever this section is rendered, zero and
	// false included. A module with no direct dependencies is a measurement, and
	// so is a walk that resolved every node; Status carries the cases where no
	// walk answered, so neither needs a second way to say "unmeasured".
	Count        int                 `json:"count"`
	Partial      bool                `json:"partial"`
	Dependencies []contextDependency `json:"dependencies,omitempty"`
	Error        string              `json:"error,omitempty"`
	// PreModulesCaveat is present only when the module itself, or a module in the
	// answering walk, resolved under pre-modules semantics — the case in which an
	// empty dependency list is an absence of resolution rather than a measurement.
	PreModulesCaveat *preModulesCaveatJSON `json:"pre_modules_caveat,omitempty"`
}

type contextCopyrightStatement struct {
	Verbatim string   `json:"verbatim"`
	Holders  []string `json:"holders,omitempty"`
	Years    string   `json:"years,omitempty"`
	Source   string   `json:"source,omitempty"`
}

type contextLicenseObligations struct {
	Status              string `json:"status"` // "known" or "unknown"
	IncludeNotice       bool   `json:"include_notice"`
	IncludeLicenseText  bool   `json:"include_license_text"`
	StateChanges        bool   `json:"state_changes"`
	DiscloseSource      bool   `json:"disclose_source"`
	SameLicense         string `json:"same_license"` // "none"/"weak"/"strong"/"network"
	NetworkUseTrigger   bool   `json:"network_use_trigger"`
	NoTrademarkUse      bool   `json:"no_trademark_use"`
	ExplicitPatentGrant bool   `json:"explicit_patent_grant"`
	CatalogueVersion    string `json:"catalogue_version"`
}

type contextLicense struct {
	ExtractedAt string `json:"extracted_at,omitempty"`
	SPDX        string `json:"spdx,omitempty"`
	Status      string `json:"status"`
	// LowConfidenceSPDX and LowConfidenceCoverage carry a recognisable but
	// sub-threshold licence fragment (e.g. a truncated AGPL-3.0 whose only
	// matching span is the apply-appendix). Set only when the file is
	// Unclassified, so absence-of-classification is surfaced as a caveat
	// rather than rendered as absence-of-licence.
	// LowConfidenceCoverage is a pointer emitted always: unlike the fields
	// beside it there is a genuine third state here, because the fragment search
	// runs only when the root licence could not be classified. Null says no
	// sub-threshold fragment was measured; a number is the coverage of the one
	// that was, and 0 would claim a match covering none of the file.
	LowConfidenceSPDX     string                      `json:"low_confidence_spdx,omitempty"`
	LowConfidenceCoverage *float64                    `json:"low_confidence_coverage"`
	CopyrightStatus       string                      `json:"copyright_status,omitempty"`
	CopyrightStatements   []contextCopyrightStatement `json:"copyright_statements,omitempty"`
	Obligations           *contextLicenseObligations  `json:"obligations,omitempty"`
	Error                 string                      `json:"error,omitempty"`
}

type contextPackage struct {
	ImportPath string   `json:"import_path"`
	Types      []string `json:"types,omitempty"`
	// Methods are the methods declared on those types. A struct's type
	// signature names its fields and nothing else, so without these the
	// section describes a package as having no methods at all — and the
	// symbol count beside it would say so too.
	Methods []string `json:"methods,omitempty"`
	Funcs   []string `json:"funcs,omitempty"`
	Consts  []string `json:"consts,omitempty"`
	Vars    []string `json:"vars,omitempty"`
}

type contextInterface struct {
	ExtractedAt string `json:"extracted_at,omitempty"`
	Status      string `json:"status"`
	// BuildFrame names the build the declarations below were measured in. The
	// section reports one platform's public API, so a reader that cannot see
	// which platform cannot tell an absent symbol from an unbuilt one. Absent
	// only when no record was read at all.
	BuildFrame string           `json:"build_frame,omitempty"`
	Packages   []contextPackage `json:"packages,omitempty"`
	Error      string           `json:"error,omitempty"`
}

type contextCallGraph struct {
	ExtractedAt string `json:"extracted_at,omitempty"`
	Status      string `json:"status"`
	Algorithm   string `json:"algorithm,omitempty"`
	// NodeCount and EdgeCount describe the graph that was extracted, and a graph
	// with no nodes is a real extraction result — Status says whether one ran.
	NodeCount int `json:"node_count"`
	EdgeCount int `json:"edge_count"`
	// EntryPointCount is a pointer emitted always because it answers a narrower
	// question than the counts above: how many exported entry points the ONE
	// package --package named has. Without that flag no single count is derived
	// at all — the breakdown in EntryPointsByPackage is — so null says "this run
	// counted no single package" and 0 says "the package named has none".
	EntryPointCount      *int           `json:"entry_point_count"`
	EntryPointsByPackage map[string]int `json:"entry_points_by_package,omitempty"`
	EntryPoints          []string       `json:"entry_points,omitempty"`
	Error                string         `json:"error,omitempty"`
}

type contextExample struct {
	Name   string `json:"name"`
	Symbol string `json:"symbol,omitempty"`
	Body   string `json:"body"`
	Output string `json:"output,omitempty"`
	Doc    string `json:"doc,omitempty"`
}

type contextExamples struct {
	ExtractedAt string `json:"extracted_at,omitempty"`
	Status      string `json:"status"`
	// Count is emitted at zero: a harvested module with no Example functions is
	// a measured fact about that module, and Status says when nothing harvested.
	Count    int              `json:"count"`
	Examples []contextExample `json:"examples,omitempty"`
	Error    string           `json:"error,omitempty"`
}

type contextCVE struct {
	ID      string   `json:"id"`
	Aliases []string `json:"aliases,omitempty"`
	Summary string   `json:"summary"`
	FixedIn string   `json:"fixed_in,omitempty"`
	// Score is the advisory's CVSS base score, a pointer emitted always. Many
	// advisories publish no severity at all, and 0.0 is a severity — the lowest
	// one — so the two states cannot share an encoding. Null means the advisory
	// carried no score.
	Score *float64 `json:"score"`
	// WithdrawnAt is the retraction timestamp, present only on a withdrawn
	// advisory. Without it this projection carried the retraction no further than
	// the module's status word, so a consumer reading a finding here saw an entry
	// shaped exactly like a live one — with the withdrawal legible only as prose in
	// the upstream summary, which is what the field exists to stop being the signal.
	WithdrawnAt string `json:"withdrawn_at,omitempty"`
	// Reachable is three-valued and emitted always: true, false, or null for a
	// finding no reachability analysis answered. Omitting the null put the
	// unanswered finding and a build that does not derive reachability into the
	// same document; Soundness cannot separate them, because it reads
	// "not stated" for a positive verdict too.
	Reachable *bool `json:"reachable"`
	// Soundness states how thorough the search behind a NEGATIVE reachability
	// answer was, and SoundnessReason names the basis for that rung in the
	// producing analyser's own terms. Both are derived from the served record by
	// vuldomain.NegativeSoundness; neither is stored.
	//
	// Soundness is emitted on every finding and never omitted. On a positive, and
	// on a finding carrying no reachability answer at all, it reads "not stated" —
	// there is no absence to qualify — and that is a different statement from the
	// key being missing, which says the producer does not derive the rung.
	Soundness       vuldomain.ReachabilitySoundness `json:"soundness"`
	SoundnessReason string                          `json:"soundness_reason,omitempty"`
}

type contextVulnerabilities struct {
	ExtractedAt  string   `json:"extracted_at,omitempty"`
	Status       string   `json:"status"`
	WalkStatus   string   `json:"walk_status,omitempty"`   // the walk run's collapsed OverallStatus (compatibility summary)
	WalkCoverage string   `json:"walk_coverage,omitempty"` // coverage axis (Partial/Failed) when the run left modules unanalysed
	WalkAffected []string `json:"walk_affected,omitempty"` // affected walk peers in this module's transitive dep closure
	WalkError    string   `json:"walk_error,omitempty"`    // set when a walk-peer verdict could not be read; the affected-peer set may be incomplete
	// WalkBasisID and WalkBasisFrame name the walk whose scan run answered, and
	// the frame that walk was rooted at, when the answer came from the walk
	// window rather than from a build the caller named. The window's verdict and
	// its walk annotation are facts about that one build, so the build is stated.
	// Empty on a caller-anchored read, which names its build itself.
	WalkBasisID    string `json:"walk_basis_id,omitempty"`
	WalkBasisFrame string `json:"walk_basis_frame,omitempty"`
	// WalkWindowNote states why a verdict carries no run context: the walk the
	// served record was measured in sits outside the recency window this report
	// loaded runs for. The window is a deliberate cost bound, not a claim about
	// the store, and the difference is invisible from the answer — a section
	// silently missing its status word, coverage caveat and affected peers looks
	// exactly like one where the scan had nothing to say. Empty whenever the
	// window covered every walk in the store, so it never reads as boilerplate.
	WalkWindowNote string       `json:"walk_window_note,omitempty"`
	Reason         string       `json:"reason,omitempty"`
	Findings       []contextCVE `json:"findings,omitempty"`
	WalkID         string       `json:"walk_id,omitempty"`
	// Frame is the analysis frame the served record was reached in. A
	// reachability finding means something different in each — isolated answers
	// "is this advisory reachable in the module examined alone", target-rooted
	// answers "is it reachable in the build rooted at that target" — so the
	// section names the question it answered rather than leaving a consumer to
	// assume it was theirs.
	Frame string `json:"frame,omitempty"`
	// Freshness facts: when the verdict was first established, when it was last
	// re-validated, and how old the database snapshot behind it was at that
	// validation. Stated for the consumer to judge; kanonarion renders no
	// verdict on acceptability.
	FirstValidatedAt string `json:"first_validated_at,omitempty"`
	LastValidatedAt  string `json:"last_validated_at,omitempty"`
	SnapshotVersion  string `json:"snapshot_version,omitempty"`
	// PipelineVersion names the vuln-scan pipeline that produced the verdict.
	// It bounds the verdict as much as the snapshot does: a "Clean" from a
	// pipeline whose parse reported no source findings is a different claim
	// from a "Clean" from one that analysed sources.
	PipelineVersion string `json:"pipeline_version,omitempty"`
	// SnapshotAgeDays is how old the advisory snapshot was when the verdict was
	// validated. It is a pointer emitted always: a snapshot with no recorded
	// retrieval time yields no age, and a plain 0 would report that record as
	// validated against a snapshot pulled the same day. Zero is emitted as 0,
	// which is what a snapshot pulled the same day genuinely measures.
	SnapshotRetrievedAt string `json:"snapshot_retrieved_at,omitempty"`
	SnapshotAgeDays     *int   `json:"snapshot_age_days"`
	Error               string `json:"error,omitempty"`
}

// -- command --

func newContextCmd(stdout, stderr io.Writer) *cobra.Command {
	var f contextFlags

	cmd := &cobra.Command{
		Use:   "context [<module>@<version> | <dir>]",
		Short: "Aggregate stored records into AI-ready context (no args: code deps of ./go.mod)",
		Long: `Aggregate all stored records for a module — verification, dependencies,
license, interface, call graph, examples, vulnerabilities — into AI-ready
context.

With no arguments, context defaults to --gomod ./go.mod and emits one context
entry per module in the project's code-scope build list. This is the same module
set a bare 'kanonarion inspect' walks, extracts, and vuln-scans, so the
no-arg pair composes: run 'kanonarion inspect', then 'kanonarion context'.`,
		Example: `  kanonarion context golang.org/x/mod@v0.35.0
  kanonarion context --walk-id <id> --stream
  kanonarion context
  kanonarion context --gomod ./go.mod --json
  kanonarion context . --symbol --exclude-tests`,
		Args: cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			f.compactSet = cmd.Flags().Changed("compact")
			if f.stream && len(args) > 0 {
				return fmt.Errorf("--stream requires --walk-id or --gomod")
			}
			// With no positional module and no --walk-id, default to a go.mod
			// scan; --gomod defaults to./go.mod via resolveGoModPath.
			if f.gomodPath != "" || (len(args) == 0 && f.walkID == "") {
				if len(args) != 0 {
					return fmt.Errorf("--gomod and a module argument are mutually exclusive")
				}
				if f.walkID != "" {
					return fmt.Errorf("--gomod and --walk-id are mutually exclusive")
				}
				resolved, rerr := resolveGoModPath(f.gomodPath)
				if rerr != nil {
					return rerr
				}
				f.gomodPath = resolved
				scope, serr := scopeFromFlags(f.tool, f.project)
				if serr != nil {
					return serr
				}
				return runContextGoMod(cmd.Context(), f, scope, stdout, stderr)
			}
			if f.walkID != "" {
				if len(args) != 0 {
					return fmt.Errorf("--walk-id and a module argument are mutually exclusive")
				}
				return runContextWalk(cmd.Context(), f, stdout, stderr)
			}
			if isLocalPath(args[0]) {
				return runContextLocal(cmd.Context(), args[0], f, stdout, stderr)
			}
			return runContext(cmd.Context(), args[0], f, stdout, stderr)
		},
	}

	cmd.Flags().BoolVar(&f.compact, "compact", true, "strip doc comments from signatures and truncate example bodies (default true)")
	cmd.Flags().BoolVar(&f.full, "full", false, "include full doc comments and complete example bodies (overrides --compact)")
	cmd.Flags().BoolVar(&f.sizeOnly, "size-only", false, "print estimated token count and byte size of the JSON output, then exit")
	cmd.Flags().BoolVar(&f.entryPointsFull, "entry-points-full", false, "include flat entry_points list in addition to entry_points_by_package")
	cmd.Flags().StringVar(&f.packageFilter, "package", "", "restrict interface and call-graph sections to a single import path")
	cmd.Flags().StringVar(&f.walkID, "walk-id", "", "emit context for every module in the walk as NDJSON")
	cmd.Flags().StringVar(&f.gomodPath, "gomod", "", "path to a go.mod file; emit context for the project's code dependencies as NDJSON (default: ./go.mod)")
	cmd.Flags().BoolVar(&f.tool, "tool", false, "scope to the tooling supply chain (the go.mod tool directives' closure)")
	cmd.Flags().BoolVar(&f.project, "project", false, "scope to the complete set: the project's code AND tooling")
	cmd.Flags().BoolVar(&f.stream, "stream", false, "with --walk-id or --gomod: emit NDJSON (one document per module) without --json")
	cmd.Flags().BoolVar(&f.directOnly, "direct-only", false, "with --walk-id: emit context only for direct dependencies of the walk root")
	cmd.Flags().BoolVar(&f.affectedOnly, "affected-only", false, "with --walk-id: emit context only for modules with vulnerability findings")
	cmd.Flags().StringVar(&f.modulesFile, "modules", "", "with --walk-id: emit context only for module coordinates listed in this file (newline-delimited)")
	cmd.Flags().BoolVar(&f.symbol, "symbol", false, "with a local path: enable symbol-level analysis (go/packages type-check, ~2-5s)")
	cmd.Flags().BoolVar(&f.reachability, "reachability", false, "with a local path: probe the binary for CVE-affected symbols (~30s)")
	cmd.Flags().BoolVar(&f.excludeTests, testScopeFlagName, false, "with a local path: omit dependency users declared in _test.go files and external test packages")

	return cmd
}

func runContext(ctx context.Context, arg string, f contextFlags, stdout, stderr io.Writer) error {
	refused := append(contextWalkOnlyFlags(f), contextLocalOnlyFlags(f)...)
	refused = append(refused, contextGoModOnlyFlags(f)...)
	refused = append(refused, contextStreamFlag(f)...)
	if err := refuseInapplicableFlags("context <module>@<version>", refused); err != nil {
		return err
	}

	logger := buildLogger(logLevel, stderr)

	coord, err := parseCoordinate(arg)
	if err != nil {
		return fmt.Errorf("invalid coordinate %q: %w", arg, err)
	}

	dbPath := filepath.Join(storeRoot, "mirror.db")
	if _, err := os.Stat(dbPath); os.IsNotExist(err) {
		return fmt.Errorf("store not found at %s: run a kanonarion command to initialise it", dbPath)
	}

	ctr, cleanup, err := NewContainer(storeRoot, "", "", false, activeConfig, logger)
	if err != nil {
		return fmt.Errorf("initialising store: %w", err)
	}
	defer func() { _ = cleanup() }()

	vulnBatch, err := loadVulnBatchCtx(ctx, ctr.QueryScanRuns, ctr.QueryWalks)
	if err != nil {
		return fmt.Errorf("loading vuln batch context: %w", err)
	}

	compact := f.compact && !f.full
	vulns := buildVulnerabilitiesFromBatch(ctx, coord, ctr.QueryVuln, vulnBatch)
	var cmdWalkID string
	if vulns.Status == sectionStatusNotRun {
		// No scan result found; surface a walk so the agent can run
		// vuln-scan <walk-id> directly.
		//
		// This is the one walk lookup in the command that is not a frame choice
		// and does not run the default selection rule. Nothing is read out of the
		// walk: its id is substituted into a suggested command line, and the
		// suggestion is to go and MEASURE the coordinate, not to report anything
		// about it. Any walk of this target makes that command runnable, so the
		// cheapest one does, and if the reader wants a different frame scanned
		// they name it on the vuln-scan they are being pointed at.
		if walks, err := ctr.QueryWalks.ListWalks(ctx, walkports.WalkFilter{Target: &coord, Limit: 1}); err == nil && len(walks) > 0 {
			cmdWalkID = walks[0].ID
		}
	}
	out := contextOutput{
		Module:          contextModuleInfo{Path: coord.Path(), Version: coord.Version()},
		Verification:    buildVerification(ctx, coord, ctr.QueryFetch),
		Provenance:      buildProvenance(coord),
		Dependencies:    buildDependencies(ctx, coord, ctr.QueryWalks),
		License:         buildLicense(ctx, coord, ctr.QueryLicense),
		Interface:       buildInterface(ctx, coord, ctr.QueryInterface, compact, f.packageFilter),
		CallGraph:       buildCallGraph(ctx, coord, ctr.QueryCallGraph, f.entryPointsFull, f.packageFilter),
		Examples:        buildExamples(ctx, coord, ctr.QueryExamples, compact, f.packageFilter),
		Vulnerabilities: vulns,
		Commands:        buildCommandsWithWalk(coord, cmdWalkID),
	}

	if f.sizeOnly {
		return printDocumentSize(out, jsonOut, stdout)
	}

	if jsonOut {
		raw, err := json.MarshalIndent(out, "", "  ")
		if err != nil {
			return fmt.Errorf("encoding context: %w", err)
		}
		if _, err := fmt.Fprintf(stdout, "%s\n", raw); err != nil {
			return fmt.Errorf("writing context: %w", err)
		}
		return nil
	}

	return printContextText(out, compact, stdout)
}
