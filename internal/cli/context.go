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
	Retracted   bool   `json:"retracted,omitempty"`
	Error       string `json:"error,omitempty"` // set when status is read_error
}

type contextDependency struct {
	Path    string `json:"path"`
	Version string `json:"version"`
}

type contextDependencies struct {
	Status       string              `json:"status"`
	WalkID       string              `json:"walk_id,omitempty"`
	Count        int                 `json:"count,omitempty"`
	Partial      bool                `json:"partial,omitempty"`
	Dependencies []contextDependency `json:"dependencies,omitempty"`
	Error        string              `json:"error,omitempty"`
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
	LowConfidenceSPDX     string                      `json:"low_confidence_spdx,omitempty"`
	LowConfidenceCoverage float64                     `json:"low_confidence_coverage,omitempty"`
	CopyrightStatus       string                      `json:"copyright_status,omitempty"`
	CopyrightStatements   []contextCopyrightStatement `json:"copyright_statements,omitempty"`
	Obligations           *contextLicenseObligations  `json:"obligations,omitempty"`
	Error                 string                      `json:"error,omitempty"`
}

type contextPackage struct {
	ImportPath string   `json:"import_path"`
	Types      []string `json:"types,omitempty"`
	Funcs      []string `json:"funcs,omitempty"`
	Consts     []string `json:"consts,omitempty"`
	Vars       []string `json:"vars,omitempty"`
}

type contextInterface struct {
	ExtractedAt string           `json:"extracted_at,omitempty"`
	Status      string           `json:"status"`
	Packages    []contextPackage `json:"packages,omitempty"`
	Error       string           `json:"error,omitempty"`
}

type contextCallGraph struct {
	ExtractedAt          string         `json:"extracted_at,omitempty"`
	Status               string         `json:"status"`
	Algorithm            string         `json:"algorithm,omitempty"`
	NodeCount            int            `json:"node_count,omitempty"`
	EdgeCount            int            `json:"edge_count,omitempty"`
	EntryPointCount      int            `json:"entry_point_count,omitempty"`
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
	ExtractedAt string           `json:"extracted_at,omitempty"`
	Status      string           `json:"status"`
	Count       int              `json:"count,omitempty"`
	Examples    []contextExample `json:"examples,omitempty"`
	Error       string           `json:"error,omitempty"`
}

type contextCVE struct {
	ID        string   `json:"id"`
	Aliases   []string `json:"aliases,omitempty"`
	Summary   string   `json:"summary"`
	FixedIn   string   `json:"fixed_in,omitempty"`
	Score     float64  `json:"score,omitempty"`
	Reachable *bool    `json:"reachable,omitempty"`
}

type contextVulnerabilities struct {
	ExtractedAt  string       `json:"extracted_at,omitempty"`
	Status       string       `json:"status"`
	WalkStatus   string       `json:"walk_status,omitempty"`
	WalkAffected []string     `json:"walk_affected,omitempty"` // affected walk peers in this module's transitive dep closure
	Reason       string       `json:"reason,omitempty"`
	Findings     []contextCVE `json:"findings,omitempty"`
	WalkID       string       `json:"walk_id,omitempty"`
	// Freshness facts: when the verdict was first established, when it was last
	// re-validated, and how old the database snapshot behind it was at that
	// validation. Stated for the consumer to judge; kanonarion renders no
	// verdict on acceptability.
	FirstValidatedAt    string `json:"first_validated_at,omitempty"`
	LastValidatedAt     string `json:"last_validated_at,omitempty"`
	SnapshotVersion     string `json:"snapshot_version,omitempty"`
	SnapshotRetrievedAt string `json:"snapshot_retrieved_at,omitempty"`
	SnapshotAgeDays     int    `json:"snapshot_age_days,omitempty"`
	Error               string `json:"error,omitempty"`
}

// -- command --

func newContextCmd(stdout, stderr io.Writer) *cobra.Command {
	var f contextFlags

	cmd := &cobra.Command{
		Use:   "context [<module>@<version>]",
		Short: "Aggregate stored records into AI-ready context (no args: direct deps of ./go.mod)",
		Long: `Aggregate all stored records for a module — verification, dependencies,
license, interface, call graph, examples, vulnerabilities — into AI-ready
context.

With no arguments, context defaults to --gomod ./go.mod and emits one
context entry per direct (non-indirect) dependency. This is the same module
set a bare 'kanonarion inspect' walks, extracts, and vuln-scans, so the
no-arg pair composes: run 'kanonarion inspect', then 'kanonarion context'.`,
		Example: `  kanonarion context golang.org/x/mod@v0.35.0
  kanonarion context --walk-id <id> --stream
  kanonarion context
  kanonarion context --gomod ./go.mod --json`,
		Args: cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
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
	cmd.Flags().BoolVar(&f.stream, "stream", false, "emit NDJSON output (implied by --walk-id or --gomod)")
	cmd.Flags().BoolVar(&f.directOnly, "direct-only", false, "with --walk-id: emit context only for direct dependencies of the walk root")
	cmd.Flags().BoolVar(&f.affectedOnly, "affected-only", false, "with --walk-id: emit context only for modules with vulnerability findings")
	cmd.Flags().StringVar(&f.modulesFile, "modules", "", "with --walk-id: emit context only for module coordinates listed in this file (newline-delimited)")
	cmd.Flags().BoolVar(&f.symbol, "symbol", false, "with a local path: enable symbol-level analysis (go/packages type-check, ~2-5s)")
	cmd.Flags().BoolVar(&f.reachability, "reachability", false, "with a local path: probe the binary for CVE-affected symbols (~30s)")

	return cmd
}

func runContext(ctx context.Context, arg string, f contextFlags, stdout, stderr io.Writer) error {
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
		// No scan result found; surface the most recent walk so the agent can
		// run vuln-scan <walk-id> directly.
		if walks, err := ctr.QueryWalks.ListWalks(ctx, walkports.WalkFilter{Target: &coord, Limit: 1}); err == nil && len(walks) > 0 {
			cmdWalkID = walks[0].ID
		}
	}
	out := contextOutput{
		Module:          contextModuleInfo{Path: coord.Path, Version: coord.Version},
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
		return printContextSize(out, jsonOut, stdout)
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
