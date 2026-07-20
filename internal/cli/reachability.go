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

// reachabilityMethodCallGraph names the analysis that produced a persisted
// reachability verdict. Today the only producer is govulncheck source-mode
// call-graph analysis; the field is reported (and reserved in --json) so a
// future symbol-table probe method can be distinguished without a breaking
// change to the output shape.
const reachabilityMethodCallGraph = "call-graph"

// reachability verdicts for the stored-module query mode.
const (
	verdictReachable    = "reachable"
	verdictNotReachable = "not_reachable"
	verdictNotAffected  = "not_affected"
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
	Module       string     `json:"module"`
	Version      string     `json:"version"`
	VulnID       string     `json:"vuln_id"`
	Aliases      []string   `json:"aliases,omitempty"`
	Summary      string     `json:"summary,omitempty"`
	Verdict      string     `json:"verdict"`
	Confidence   string     `json:"confidence,omitempty"`
	Method       string     `json:"method"`
	ExamplePaths [][]string `json:"example_paths,omitempty"`
	ScannedAt    string     `json:"scanned_at,omitempty"`
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

	switch rec.OverallStatus {
	case vuldomain.StatusScanFailed:
		detail := ""
		if rec.ErrorDetail != "" {
			detail = ": " + rec.ErrorDetail
		}
		return vulnReachabilityQuery{}, fmt.Errorf(
			"%s could not be scanned (ScanFailed)%s; reachability is unknown. Re-run:\n  kanonarion vuln-scan %s --reachability",
			coord, detail, coord)
	case vuldomain.StatusUnscannable:
		detail := ""
		if rec.UnscannableReason != "" {
			detail = ": " + rec.UnscannableReason
		}
		return vulnReachabilityQuery{}, fmt.Errorf(
			"%s is unscannable%s; reachability cannot be determined. See: kanonarion vuln-show %s",
			coord, detail, coord)
	}

	// The module was scanned successfully (Clean or Affected).
	f, ok := findFindingByID(rec.Findings, vulnID)
	if !ok {
		// Genuine zero: the scan ran and this CVE is not among its findings.
		return vulnReachabilityQuery{
			Module:    coord.Path,
			Version:   coord.Version,
			VulnID:    vulnID,
			Verdict:   verdictNotAffected,
			Method:    reachabilityMethodCallGraph,
			ScannedAt: rec.ScannedAt.UTC().Format(time.RFC3339),
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
		Module:       coord.Path,
		Version:      coord.Version,
		VulnID:       f.ID,
		Aliases:      f.Aliases,
		Summary:      f.Summary,
		Verdict:      verdict,
		Confidence:   string(f.Reachable.Confidence),
		Method:       reachabilityMethodCallGraph,
		ExamplePaths: f.Reachable.ExamplePaths,
		ScannedAt:    rec.ScannedAt.UTC().Format(time.RFC3339),
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

func printVulnReachability(stdout io.Writer, res vulnReachabilityQuery) {
	coord := res.Module + "@" + res.Version
	switch res.Verdict {
	case verdictReachable:
		_, _ = fmt.Fprintf(stdout, "%s is REACHABLE in %s [confidence: %s, method: %s]\n", res.VulnID, coord, res.Confidence, res.Method)
		if len(res.ExamplePaths) > 0 {
			_, _ = fmt.Fprintln(stdout, "  example path:")
			for _, step := range res.ExamplePaths[0] {
				_, _ = fmt.Fprintf(stdout, "    %s\n", step)
			}
		}
	case verdictNotReachable:
		_, _ = fmt.Fprintf(stdout, "%s affects %s but is NOT reachable [confidence: %s, method: %s]\n", res.VulnID, coord, res.Confidence, res.Method)
	case verdictNotAffected:
		_, _ = fmt.Fprintf(stdout, "%s is not affected by %s (scanned %s)\n", coord, res.VulnID, res.ScannedAt)
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
