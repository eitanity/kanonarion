package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"text/tabwriter"

	fipsdomain "github.com/eitanity/kanonarion/internal/fips/domain"
	"github.com/spf13/cobra"
)

// fipsFindingResult is the machine-readable shape of one classified FIPS
// finding. Every field has a single, stable meaning so an agentic consumer
// can reason about whether the finding is a deviation, compliant, or sits
// in the cgo gap (unknown).
type fipsFindingResult struct {
	Kind           string `json:"kind"`
	Package        string `json:"package,omitempty"`
	Module         string `json:"module,omitempty"`
	Source         string `json:"source,omitempty"`
	Line           int    `json:"line,omitempty"`
	Toolchain      string `json:"toolchain,omitempty"`
	ToolchainRaw   string `json:"toolchain_raw,omitempty"`
	Category       string `json:"category"`
	PolicyOutcome  string `json:"policy_outcome"`
	PolicyBlocking bool   `json:"policy_blocking"`
}

// fipsSection is the top-level `fips` JSON section described by
// toolchain_fips_capable, toolchain_variant, fips_mode_statically_enabled,
// non_fips_algorithm_usage[], cgo_crypto_dependencies[], compliance_assessment
// (with the eligibility-vs-validation caveat in the text). Deterministic:
// findings are domain-sorted and no wall-clock field is emitted, so identical
// inputs yield identical bytes.
type fipsSection struct {
	SchemaVersion             string              `json:"schema_version"`
	Ecosystem                 string              `json:"ecosystem"`
	PipelineVersion           string              `json:"pipeline_version"`
	CatalogueVersion          string              `json:"catalogue_version"`
	Project                   string              `json:"project"`
	ToolchainFIPSCapable      bool                `json:"toolchain_fips_capable"`
	ToolchainVariant          string              `json:"toolchain_variant,omitempty"`
	ToolchainRaw              string              `json:"toolchain_raw,omitempty"`
	FIPSModeStaticallyEnabled bool                `json:"fips_mode_statically_enabled"`
	ComplianceAssessment      string              `json:"compliance_assessment"`
	Caveat                    string              `json:"caveat"`
	ContentHash               string              `json:"content_hash"`
	NonFIPSAlgorithmUsage     []fipsFindingResult `json:"non_fips_algorithm_usage"`
	CgoCryptoDependencies     []fipsFindingResult `json:"cgo_crypto_dependencies"`
	DirectCryptoRandUsage     []fipsFindingResult `json:"direct_crypto_rand_usage"`
	Findings                  []fipsFindingResult `json:"findings"`
}

// toFIPSSection projects a domain record into the JSON section. Shared by
// the `fips` command and any future aggregator. Per-kind buckets are
// surfaced alongside the flat finding list so agents can read the
// dimension they need without filtering, while the full ordered set
// remains available for diffing.
func toFIPSSection(rec fipsdomain.Record) fipsSection {
	out := fipsSection{
		SchemaVersion:             rec.SchemaVersion,
		Ecosystem:                 rec.Ecosystem,
		PipelineVersion:           rec.PipelineVersion,
		CatalogueVersion:          rec.CatalogueVersion,
		Project:                   rec.ProjectModulePath,
		ToolchainFIPSCapable:      rec.ToolchainCapable,
		ToolchainVariant:          rec.ToolchainVariant,
		ToolchainRaw:              rec.ToolchainRaw,
		FIPSModeStaticallyEnabled: rec.FIPSModeStaticallyEnabled,
		ComplianceAssessment:      rec.ComplianceAssessment,
		Caveat:                    rec.Caveat,
		ContentHash:               rec.ContentHash,
		// Empty (non-nil) slices serialise as [] not null
		// consumers can iterate uniformly regardless of fixture state.
		NonFIPSAlgorithmUsage: []fipsFindingResult{},
		CgoCryptoDependencies: []fipsFindingResult{},
		DirectCryptoRandUsage: []fipsFindingResult{},
		Findings:              make([]fipsFindingResult, 0, len(rec.Findings)),
	}
	for _, f := range rec.Findings {
		r := fipsFindingResult{
			Kind: string(f.Kind), Package: f.Package, Module: f.Module,
			Source: f.Source, Line: f.Line, Toolchain: f.Toolchain,
			ToolchainRaw:  f.ToolchainRaw,
			Category:      string(f.Category),
			PolicyOutcome: f.PolicyOutcome, PolicyBlocking: f.PolicyBlocking,
		}
		out.Findings = append(out.Findings, r)
		switch f.Kind {
		case fipsdomain.FindingAlgorithm:
			out.NonFIPSAlgorithmUsage = append(out.NonFIPSAlgorithmUsage, r)
		case fipsdomain.FindingCgoCrypto:
			out.CgoCryptoDependencies = append(out.CgoCryptoDependencies, r)
		case fipsdomain.FindingDirectRandom:
			out.DirectCryptoRandUsage = append(out.DirectCryptoRandUsage, r)
		}
	}
	return out
}

func newFIPSCmd(stdout, stderr io.Writer) *cobra.Command {
	var gomodPath string
	cmd := &cobra.Command{
		Use:   "fips",
		Short: "Assess FIPS toolchain eligibility and non-FIPS algorithm usage",
		Long: `fips reports the FIPS *eligibility* of the project. A toolchain is
FIPS-capable from either of two sources: an out-of-tree distribution marker
in buildinfo.txt / go.mod that matches the catalogue of FIPS-capable Go
variants (BoringCrypto, Microsoft, Red Hat, AWS), or the standard toolchain's
native Go Cryptographic Module (go 1.24+ with the fips140 directive enabled).
The closure is also scanned for non-FIPS algorithm packages (crypto/md5,
crypto/rc4, …) or cgo crypto dependencies.

When the toolchain is not capable the assessment names the reason rather than
reporting a flat negative: a toolchain too old for native FIPS is "not
eligible", while a go 1.24+ toolchain that ships native FIPS but has the
fips140 directive unset is "not enabled" and points at the remediation.

This is eligibility assessment, NOT formal CMVP / FIPS 140-3 validation —
the output carries that caveat explicitly. A cgo crypto dependency is
flagged as "unknown" rather than compliant: the known cgo gap means we
cannot assert validation from source alone.

The default policy is opt-in: with fips_required: false in policy.yaml the
findings are surfaced but never gate. With fips_required: true a
non-FIPS-capable toolchain, a non-FIPS algorithm import, or a cgo crypto
dependency exits non-zero so CI can gate.`,
		Example: `  kanonarion fips
  kanonarion fips --gomod ./go.mod --json`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runFIPS(cmd.Context(), gomodPath, stdout, stderr)
		},
	}
	cmd.Flags().StringVar(&gomodPath, "gomod", "", "path to go.mod file (default: ./go.mod)")
	return cmd
}

func runFIPS(ctx context.Context, gomodFlag string, stdout, stderr io.Writer) error {
	gomodPath, err := resolveGoModPath(gomodFlag)
	if err != nil {
		return err
	}
	logger := buildLogger(logLevel, stderr)
	ctr, cleanup, err := NewContainer(storeRoot, "", "", false, activeConfig, logger)
	if err != nil {
		return fmt.Errorf("initialising store: %w", err)
	}
	defer func() { _ = cleanup() }()

	return fipsWith(ctx, ctr, gomodPath, stdout)
}

// fipsWith holds the fips logic over an injected Container: it runs the
// assessment, renders JSON or text, and returns fipsBlockingErr in *both*
// modes so a policy violation gates the build regardless of output format.
// Split from runFIPS so that exit contract is testable without a live store.
func fipsWith(ctx context.Context, ctr *Container, gomodPath string, stdout io.Writer) error {
	rec, err := ctr.ExtractFIPS.Extract(ctx, gomodPath, activeConfig.FIPSPolicy)
	if err != nil {
		return fmt.Errorf("scanning fips facts: %w", err)
	}
	section := toFIPSSection(rec)

	if jsonOut {
		enc := json.NewEncoder(stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(section); err != nil {
			return fmt.Errorf("encoding fips: %w", err)
		}
		return fipsBlockingErr(section)
	}
	if err := printFIPSTable(stdout, section); err != nil {
		return err
	}
	return fipsBlockingErr(section)
}

func printFIPSTable(stdout io.Writer, s fipsSection) error {
	capable := "no"
	if s.ToolchainFIPSCapable {
		capable = "yes"
	}
	toolchain := s.ToolchainRaw
	if s.ToolchainVariant != "" {
		toolchain = fmt.Sprintf("%s (%s)", toolchain, s.ToolchainVariant)
	}
	if _, err := fmt.Fprintf(stdout, "Project:    %s\nToolchain:  %s — capable=%s\nAssessment: %s\nCaveat:     %s\n\n",
		s.Project, toolchain, capable, s.ComplianceAssessment, s.Caveat); err != nil {
		return fmt.Errorf("writing output: %w", err)
	}
	if len(s.Findings) == 0 {
		if _, err := fmt.Fprintln(stdout, "no FIPS findings"); err != nil {
			return fmt.Errorf("writing output: %w", err)
		}
		return nil
	}
	tw := tabwriter.NewWriter(stdout, 0, 2, 2, ' ', 0)
	if _, err := fmt.Fprintln(tw, "KIND\tPACKAGE\tMODULE\tSOURCE:LINE\tCATEGORY\tPOLICY"); err != nil {
		return fmt.Errorf("writing output: %w", err)
	}
	for _, f := range s.Findings {
		loc := f.Source
		if f.Line > 0 {
			loc = fmt.Sprintf("%s:%d", f.Source, f.Line)
		}
		if _, err := fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\n",
			f.Kind, f.Package, f.Module, loc, f.Category, f.PolicyOutcome); err != nil {
			return fmt.Errorf("writing output: %w", err)
		}
	}
	if err := tw.Flush(); err != nil {
		return fmt.Errorf("flushing output: %w", err)
	}
	return nil
}

// fipsBlockingErr returns a non-zero ExitConfig error when any finding is
// policy-blocking — typically a non-FIPS algorithm import under
// fips_required, or a toolchain not on the catalogue. Surfacing the
// finding list keeps the error actionable rather than just "policy
// failed".
func fipsBlockingErr(s fipsSection) error {
	var blocked []string
	for _, f := range s.Findings {
		if !f.PolicyBlocking {
			continue
		}
		switch f.Kind {
		case string(fipsdomain.FindingToolchain):
			blocked = append(blocked, fmt.Sprintf("toolchain not FIPS-capable (%q)", f.ToolchainRaw))
		case string(fipsdomain.FindingAlgorithm):
			blocked = append(blocked, fmt.Sprintf("%s in %s", f.Package, f.Module))
		case string(fipsdomain.FindingCgoCrypto):
			blocked = append(blocked, fmt.Sprintf("cgo crypto dep %s", f.Module))
		default:
			blocked = append(blocked, fmt.Sprintf("%s/%s", f.Kind, f.Module))
		}
	}
	if len(blocked) == 0 {
		return nil
	}
	return &exitError{code: ExitConfig, msg: fmt.Sprintf(
		"fips policy: %d finding(s) violate policy: %v", len(blocked), blocked)}
}
