package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/eitanity/kanonarion/internal/coordinate"

	"github.com/spf13/cobra"

	localimporter "github.com/eitanity/kanonarion/internal/local/adapters/importer/golist"
	localprober "github.com/eitanity/kanonarion/internal/local/adapters/probe/builder"
	localsnapshot "github.com/eitanity/kanonarion/internal/local/adapters/snapshot/walkdir"
	localvulnstore "github.com/eitanity/kanonarion/internal/local/adapters/vulnfindings/store"
	localapp "github.com/eitanity/kanonarion/internal/local/application"
	localdomain "github.com/eitanity/kanonarion/internal/local/domain"
	vuldomain "github.com/eitanity/kanonarion/internal/vuln/domain"
)

const localVulnPipelineVersion = vulnPipelineVersion

// reachabilityMethodNone is the method of a reply that consulted no
// reachability analysis — "not affected" and "withdrawn" are read off the
// advisory set. An empty string would render as a missing value; this says the
// question was not asked.
const reachabilityMethodNone = "none"

// reachability verdicts for the stored-module query mode.
const (
	verdictReachable    = "reachable"
	verdictNotReachable = "not_reachable"
	verdictNotAffected  = "not_affected"
	// verdictWithdrawn is its own verdict, not a flavour of not_affected and
	// certainly not a reachability answer. A retracted advisory is excluded on the
	// strength of its retraction, and answering "not reachable" for one would offer
	// reachability as the mitigation — inviting the reader to conclude the module
	// would be at risk if only something called it, when there is nothing to be at
	// risk from.
	verdictWithdrawn = "withdrawn"
)

// -- output types --

type reachabilityFinding struct {
	CVEID          string   `json:"cve_id"`
	Aliases        []string `json:"aliases,omitempty"`
	Summary        string   `json:"summary"`
	Verdict        string   `json:"verdict"`
	VerdictSource  string   `json:"verdict_source,omitempty"`
	Reason         string   `json:"reason,omitempty"`
	MatchedSymbols []string `json:"matched_symbols,omitempty"`
}

type reachabilityModule struct {
	Path     string                `json:"path"`
	Version  string                `json:"version"`
	Findings []reachabilityFinding `json:"findings"`
}

type reachabilityOutput struct {
	Root       string               `json:"root"`
	ModulePath string               `json:"module_path"`
	VersionID  string               `json:"version_id"`
	ProbeKind  string               `json:"probe_kind"`
	Notice     string               `json:"notice,omitempty"`
	Modules    []reachabilityModule `json:"modules"`
}

func newReachabilityCmd(stdout, stderr io.Writer) *cobra.Command {
	var localPath string
	var vulnID string

	cmd := &cobra.Command{
		Use:   "reachability (<module>@<version> --vuln <id> | --local <dir>)",
		Short: "Report whether a CVE is reachable in a module (stored query) or the local working tree",
		Long: `reachability has two modes.

Stored-module query (read-only): 'reachability <module>@<version> --vuln <id>'
reads the reachability verdict that 'vuln-scan --reachability' previously
computed and persisted for a module, for a single CVE. It never scans or
recomputes; when the data is absent it tells you which command to run.

Local probe: 'reachability --local <dir>' analyses the working tree directly
(a different, live analysis — not a query of stored facts).`,
		Example: `  kanonarion reachability golang.org/x/text@v0.3.7 --vuln GO-2021-0113
  kanonarion reachability golang.org/x/text@v0.3.7 --vuln GO-2021-0113 --json
  kanonarion reachability --local .`,
		Args: cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			coordArg := ""
			if len(args) == 1 {
				coordArg = args[0]
			}

			switch {
			case vulnID != "":
				if coordArg == "" {
					return fmt.Errorf("reachability --vuln requires a <module>@<version> argument")
				}
				if localPath != "" {
					return fmt.Errorf("--vuln and --local are mutually exclusive: --vuln queries a stored module, --local analyses the working tree")
				}
				logger := buildLogger(logLevel, stderr)
				ctr, cleanup, err := NewContainer(storeRoot, "", "", false, activeConfig, logger)
				if err != nil {
					return fmt.Errorf("initialising store: %w", err)
				}
				defer func() { _ = cleanup() }()
				return runVulnReachability(cmd.Context(), coordArg, vulnID, jsonOut, ctr.QueryVuln, stdout)
			case localPath != "":
				if coordArg != "" {
					return fmt.Errorf("reachability --local does not take a module argument; use '<module>@<version> --vuln <id>' to query a stored module")
				}
				return runLocalReachability(cmd.Context(), localPath, stdout, stderr)
			default:
				return fmt.Errorf("specify a target: '<module>@<version> --vuln <id>' to query a scanned module, or '--local <dir>' for the working tree")
			}
		},
	}

	cmd.Flags().StringVar(&localPath, "local", "", "path to the local Go workspace to probe")
	cmd.Flags().StringVar(&vulnID, "vuln", "", "vulnerability ID (e.g. GO-2024-1234, CVE-..., GHSA-...) to query; requires a <module>@<version> argument")

	return cmd
}

// runVulnReachability answers "is <vulnID> reachable in <arg>?" by reading the
// reachability verdict persisted by a prior 'vuln-scan --reachability'. It is a
// read-only query: it never scans or recomputes. Absent or undetermined data is
// surfaced as a non-zero, actionable diagnostic (never a false "not reachable"),
// distinguishing "not analysed" from "analysed, genuinely not affected/reachable".
func runVulnReachability(ctx context.Context, arg, vulnID string, jsonOut bool, uc QueryVulnUseCase, stdout io.Writer) error {
	coord, err := parseCoordinate(arg)
	if err != nil {
		return fmt.Errorf("invalid coordinate %q: %w", arg, err)
	}

	rec, found, err := uc.GetLatestRecord(ctx, coord, localVulnPipelineVersion)
	if err != nil {
		return fmt.Errorf("getting vulnerability record: %w", err)
	}

	res, verr := vulnReachabilityVerdict(coord, rec, found, vulnID)
	if verr != nil {
		return verr
	}

	if jsonOut {
		enc := json.NewEncoder(stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(res); err != nil {
			return fmt.Errorf("encoding reachability result: %w", err)
		}
		return nil
	}

	printVulnReachability(stdout, res)
	return nil
}

// vulnReachabilityQuery is the curated, snake_case result of a stored-module
// reachability query for a single CVE. Method records which analysis produced
// the verdict so a future probe-based method is reported, not silently mixed in.
type vulnReachabilityQuery struct {
	Module     string   `json:"module"`
	Version    string   `json:"version"`
	VulnID     string   `json:"vuln_id"`
	Aliases    []string `json:"aliases,omitempty"`
	Summary    string   `json:"summary,omitempty"`
	Verdict    string   `json:"verdict"`
	Confidence string   `json:"confidence,omitempty"`
	// Method is the analyser that produced the stored answer, read off the
	// answer itself. It used to be the constant "call-graph" on every reply,
	// which mislabelled every govulncheck-derived answer in the store — most of
	// them — as one this tool had computed.
	Method string `json:"method"`
	// Fidelity and Rooting complete the derivation: how well the analyser could
	// see, and what the analysis was rooted at. Without the root a route reads
	// as a property of the module, and it is a property of one build.
	Fidelity string `json:"fidelity,omitempty"`
	Rooting  string `json:"rooting,omitempty"`
	// Routes are the paths that reach the vulnerable symbol, entry point first,
	// each hop naming its module and version where the analyser knew them.
	Routes []reachabilityRouteOutput `json:"routes,omitempty"`
	// WithdrawnAt is set only on the withdrawn verdict, and carries the retraction
	// timestamp so the answer states its reason rather than asserting a bare
	// negative the reader has to take on trust.
	WithdrawnAt string `json:"withdrawn_at,omitempty"`
	ScannedAt   string `json:"scanned_at,omitempty"`
}

// reachabilityRouteOutput is one route in the curated JSON shape. Versioned
// says whether every hop named its module version: a route from the call-graph
// search never does, and a reader must not take an unversioned route for one
// they can check against their own build.
type reachabilityRouteOutput struct {
	Versioned bool                      `json:"versioned"`
	Frames    []reachabilityFrameOutput `json:"frames"`
}

// reachabilityFrameOutput is one hop.
type reachabilityFrameOutput struct {
	Module   string `json:"module,omitempty"`
	Version  string `json:"version,omitempty"`
	Package  string `json:"package,omitempty"`
	Receiver string `json:"receiver,omitempty"`
	Symbol   string `json:"symbol,omitempty"`
}

// routesToOutput renders stored routes for the curated JSON shape.
func routesToOutput(routes []vuldomain.ReachabilityRoute) []reachabilityRouteOutput {
	if len(routes) == 0 {
		return nil
	}
	out := make([]reachabilityRouteOutput, 0, len(routes))
	for _, r := range routes {
		frames := make([]reachabilityFrameOutput, 0, len(r))
		for _, f := range r {
			frames = append(frames, reachabilityFrameOutput{
				Module: f.ModulePath, Version: f.ModuleVersion,
				Package: f.Package, Receiver: f.Receiver, Symbol: f.Symbol,
			})
		}
		out = append(out, reachabilityRouteOutput{Versioned: r.IsVersioned(), Frames: frames})
	}
	return out
}

// vulnReachabilityVerdict is the pure classifier (no I/O) so the intent-aware
// distinctions are unit-testable from constructed records. It returns either a
// confident result (reachable / not_reachable / not_affected) for exit 0, or a
// directing error for the cases where the answer is genuinely unknown.
func vulnReachabilityVerdict(coord coordinate.ModuleCoordinate, rec vuldomain.VulnerabilityRecord, found bool, vulnID string) (vulnReachabilityQuery, error) {
	if !found {
		return vulnReachabilityQuery{}, fmt.Errorf(
			"no vulnerability record for %s: the module has not been vuln-scanned. Run:\n  kanonarion vuln-scan %s --reachability",
			coord, coord)
	}

	// Whether reachability could have been computed is a coverage question, so it
	// is asked of the coverage axis rather than the collapsed word. A metadata-only
	// record that matched an advisory summarises as Affected, so this switch missed
	// it and the answer fell through to the finding lookup below, which reported
	// "the module was scanned without --reachability" — naming a flag the operator
	// did pass, for a module whose source could never be analysed at all.
	coverage, _ := vuldomain.RecordAxes(rec)
	switch coverage {
	case vuldomain.CoverageFailedScan:
		detail := ""
		if rec.ErrorDetail != "" {
			detail = ": " + rec.ErrorDetail
		}
		return vulnReachabilityQuery{}, fmt.Errorf(
			"%s could not be scanned (ScanFailed)%s; reachability is unknown. Re-run:\n  kanonarion vuln-scan %s --reachability",
			coord, detail, coord)
	case vuldomain.CoverageUnscannable:
		detail := ""
		if rec.UnscannableReason != "" {
			detail = ": " + rec.UnscannableReason
		}
		return vulnReachabilityQuery{}, fmt.Errorf(
			"%s is unscannable%s; reachability cannot be determined. See: kanonarion vuln-show %s",
			coord, detail, coord)
	case vuldomain.CoverageAnalysed:
		// Analysed: the findings below are an answer about a module that was read.
	}

	// The module was analysed, so its findings answer the question.
	f, ok := findFindingByID(rec.Findings, vulnID)
	if !ok {
		// Genuine zero: the scan ran and this CVE is not among its findings.
		return vulnReachabilityQuery{
			Module:  coord.Path(),
			Version: coord.Version(),
			VulnID:  vulnID,
			Verdict: verdictNotAffected,
			// No Method: this reply is a statement about the advisory set, not the
			// output of a reachability analyser. Naming one would attribute an
			// answer to an instrument that was never consulted.
			Method:    reachabilityMethodNone,
			ScannedAt: rec.ScannedAt.UTC().Format(time.RFC3339),
		}, nil
	}

	// The retraction is answered before reachability is consulted, because it makes
	// the reachability question moot: whether anything calls the symbol does not
	// matter for an advisory that no longer stands, and the two directing errors
	// below would otherwise send the operator to compute a call graph for it.
	if f.IsWithdrawn() {
		return vulnReachabilityQuery{
			Module:  coord.Path(),
			Version: coord.Version(),
			VulnID:  f.ID,
			Aliases: f.Aliases,
			Summary: f.Summary,
			Verdict: verdictWithdrawn,
			// No Method, for the reason given on the not-affected reply above: a
			// retraction is read off the advisory, not computed.
			Method:      reachabilityMethodNone,
			WithdrawnAt: f.WithdrawnAt.UTC().Format(time.RFC3339),
			ScannedAt:   rec.ScannedAt.UTC().Format(time.RFC3339),
		}, nil
	}

	if f.Reachable == nil {
		return vulnReachabilityQuery{}, fmt.Errorf(
			"reachability was not computed for %s in %s (the module was scanned without --reachability). Run:\n  kanonarion callgraph %s\n  kanonarion vuln-scan %s --reachability",
			f.ID, coord, coord, coord)
	}

	if f.Reachable.Confidence == vuldomain.ConfidenceUnknown {
		return vulnReachabilityQuery{}, fmt.Errorf(
			"reachability for %s in %s is undetermined: the call graph was unavailable during the scan. Run:\n  kanonarion callgraph %s\n  kanonarion vuln-scan %s --reachability",
			f.ID, coord, coord, coord)
	}

	verdict := verdictNotReachable
	if f.Reachable.IsReachable {
		verdict = verdictReachable
	}
	return vulnReachabilityQuery{
		Module:     coord.Path(),
		Version:    coord.Version(),
		VulnID:     f.ID,
		Aliases:    f.Aliases,
		Summary:    f.Summary,
		Verdict:    verdict,
		Confidence: string(f.Reachable.Confidence),
		Method:     f.Reachable.DerivedBy.Analyser.String(),
		Fidelity:   f.Reachable.DerivedBy.Fidelity,
		Rooting:    f.Reachable.DerivedBy.Rooting.String(),
		Routes:     routesToOutput(f.Reachable.Routes),
		ScannedAt:  rec.ScannedAt.UTC().Format(time.RFC3339),
	}, nil
}

// findFindingByID matches a vulnerability ID against each finding's primary ID
// and its aliases, case-insensitively (GO-, CVE-, GHSA- IDs are referenced
// interchangeably).
func findFindingByID(findings []vuldomain.VulnerabilityFinding, vulnID string) (vuldomain.VulnerabilityFinding, bool) {
	for _, f := range findings {
		if strings.EqualFold(f.ID, vulnID) {
			return f, true
		}
		for _, a := range f.Aliases {
			if strings.EqualFold(a, vulnID) {
				return f, true
			}
		}
	}
	return vuldomain.VulnerabilityFinding{}, false
}

// derivationLine renders the instrument, how well it could see and what it was
// rooted at, for the one-line summary.
func derivationLine(res vulnReachabilityQuery) string {
	parts := []string{"by: " + res.Method}
	if res.Fidelity != "" {
		parts = append(parts, "fidelity: "+res.Fidelity)
	}
	if res.Rooting != "" {
		parts = append(parts, "rooted at: "+res.Rooting)
	}
	return strings.Join(parts, ", ")
}

// printRoute prints the first stored route, hop by hop, and says plainly when
// the hops carry no versions — an unversioned route cannot be checked against
// another build, and a reader who assumes it can will draw the wrong conclusion
// about their own.
func printRoute(stdout io.Writer, res vulnReachabilityQuery) {
	if len(res.Routes) == 0 {
		return
	}
	r := res.Routes[0]
	label := "  route (entry point first):"
	if !r.Versioned {
		label = "  route (entry point first; hops carry no module version, so it cannot be checked against another build):"
	}
	_, _ = fmt.Fprintln(stdout, label)
	for _, f := range r.Frames {
		_, _ = fmt.Fprintf(stdout, "    %s\n", frameLine(f))
	}
	if len(res.Routes) > 1 {
		_, _ = fmt.Fprintf(stdout, "    (%d further route(s) recorded)\n", len(res.Routes)-1)
	}
}

// frameLine renders one hop, omitting the parts the analyser could not supply.
func frameLine(f reachabilityFrameOutput) string {
	var b strings.Builder
	if f.Module != "" {
		b.WriteString(f.Module)
		if f.Version != "" {
			b.WriteString("@")
			b.WriteString(f.Version)
		}
		b.WriteString(" ")
	}
	if f.Package != "" && f.Package != f.Module {
		b.WriteString(f.Package)
		b.WriteString(".")
	}
	if f.Receiver != "" {
		b.WriteString("(")
		b.WriteString(f.Receiver)
		b.WriteString(").")
	}
	b.WriteString(f.Symbol)
	return strings.TrimSpace(b.String())
}

func printVulnReachability(stdout io.Writer, res vulnReachabilityQuery) {
	coord := res.Module + "@" + res.Version
	switch res.Verdict {
	case verdictReachable:
		_, _ = fmt.Fprintf(stdout, "%s is REACHABLE in %s [confidence: %s, %s]\n", res.VulnID, coord, res.Confidence, derivationLine(res))
		printRoute(stdout, res)
	case verdictNotReachable:
		// The derivation is printed on the negative too. "Not reachable" from a
		// metadata-only graph and from a built one are different claims, and the
		// negative is the one an operator acts on by NOT upgrading.
		_, _ = fmt.Fprintf(stdout, "%s affects %s but is NOT reachable [confidence: %s, %s]\n", res.VulnID, coord, res.Confidence, derivationLine(res))
	case verdictNotAffected:
		_, _ = fmt.Fprintf(stdout, "%s is not affected by %s (scanned %s)\n", coord, res.VulnID, res.ScannedAt)
	case verdictWithdrawn:
		_, _ = fmt.Fprintf(stdout, "%s was WITHDRAWN upstream %s — %s is not affected by it (scanned %s)\n",
			res.VulnID, res.WithdrawnAt, coord, res.ScannedAt)
	}
}

func runLocalReachability(ctx context.Context, dir string, stdout, stderr io.Writer) error {
	abs, err := filepath.Abs(dir)
	if err != nil {
		return fmt.Errorf("resolving path %q: %w", dir, err)
	}
	out, err := runLocalReachabilityInner(ctx, abs, stderr)
	if err != nil {
		return err
	}
	raw, err := json.MarshalIndent(out, "", "  ")
	if err != nil {
		return fmt.Errorf("encoding reachability result: %w", err)
	}
	if _, err := fmt.Fprintf(stdout, "%s\n", raw); err != nil {
		return fmt.Errorf("writing reachability result: %w", err)
	}
	return nil
}

// runLocalReachabilityInner opens the store and runs the reachability use case,
// returning the serialisable output. Used by both the standalone reachability
// command and the --reachability flag on context.
func runLocalReachabilityInner(ctx context.Context, abs string, stderr io.Writer) (reachabilityOutput, error) {
	dbPath := filepath.Join(storeRoot, "mirror.db")
	if _, err := os.Stat(dbPath); os.IsNotExist(err) {
		return reachabilityOutput{}, fmt.Errorf("store not found at %s: run a kanonarion command to initialise it", dbPath)
	}

	logger := buildLogger(logLevel, stderr)
	ctr, cleanup, err := NewContainer(storeRoot, "", "", false, activeConfig, logger)
	if err != nil {
		return reachabilityOutput{}, fmt.Errorf("initialising store: %w", err)
	}
	defer func() { _ = cleanup() }()

	vulnLoader := localvulnstore.New(ctr.VulnStore, localVulnPipelineVersion)
	uc := localapp.NewLocalReachabilityUseCase(
		localsnapshot.Builder{},
		localimporter.New(""),
		vulnLoader,
		localprober.New(""),
	)

	result, err := uc.Execute(ctx, abs)
	if err != nil {
		return reachabilityOutput{}, fmt.Errorf("local reachability analysis: %w", err)
	}

	return reachabilityResultToOutput(result), nil
}

func reachabilityResultToOutput(r localdomain.LocalReachabilityResult) reachabilityOutput {
	mods := make([]reachabilityModule, 0, len(r.Modules))
	for _, m := range r.Modules {
		findings := make([]reachabilityFinding, 0, len(m.Findings))
		for _, f := range m.Findings {
			findings = append(findings, reachabilityFinding{
				CVEID:          f.CVEID,
				Aliases:        f.Aliases,
				Summary:        f.Summary,
				Verdict:        string(f.Verdict),
				VerdictSource:  string(f.VerdictSource),
				Reason:         f.Reason,
				MatchedSymbols: f.MatchedSymbols,
			})
		}
		mods = append(mods, reachabilityModule{
			Path:     m.Path,
			Version:  m.Version,
			Findings: findings,
		})
	}
	return reachabilityOutput{
		Root:       r.Root,
		ModulePath: r.ModulePath,
		VersionID:  r.VersionID,
		ProbeKind:  r.ProbeKind,
		Notice:     r.Notice,
		Modules:    mods,
	}
}
