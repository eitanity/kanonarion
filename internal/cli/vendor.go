package cli

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"text/tabwriter"

	vendomain "github.com/eitanity/kanonarion/internal/vendortree/domain"
	vendports "github.com/eitanity/kanonarion/internal/vendortree/ports"
	"github.com/spf13/cobra"
)

// vendorFinding is the machine-readable shape of one reconciliation finding.
type vendorFinding struct {
	Kind           string `json:"kind"`
	Module         string `json:"module"`
	Version        string `json:"version,omitempty"`
	File           string `json:"file,omitempty"`
	Detail         string `json:"detail"`
	Expected       string `json:"expected,omitempty"`
	Actual         string `json:"actual,omitempty"`
	PolicyOutcome  string `json:"policy_outcome"`
	PolicyBlocking bool   `json:"policy_blocking"`
}

// vendorModule is the machine-readable shape of one reconciled module.
type vendorModule struct {
	Path     string `json:"path"`
	Version  string `json:"version"`
	Explicit bool   `json:"explicit"`
	Present  bool   `json:"present"`
	Dir      string `json:"dir"`
	// Packages is how many packages vendor/modules.txt lists under this
	// module. Zero means no package of the build imports it, which is why
	// `go mod vendor` wrote no directory for it.
	Packages int `json:"packages"`
	// ExpectedHash is the go.sum h1 the comparison oracle — the module zip
	// kanonarion holds — was verified against. There is no counterpart hash
	// of the vendored tree: `go mod vendor` prunes the tree, so a whole-tree
	// hash could never equal this value and reporting the pair asserted a
	// mismatch that was an artefact of the measurement.
	ExpectedHash string `json:"expected_hash,omitempty"`
}

// vendorUncoveredModule is one module of the vendored tree the report does not
// describe, with the reason it does not.
type vendorUncoveredModule struct {
	Path    string `json:"path"`
	Version string `json:"version,omitempty"`
	Reason  string `json:"reason"`
	// PackageLines is how many packages vendor/modules.txt lists under the
	// module — what `go mod vendor` wrote across all build constraints, not a
	// count of what any one build compiles.
	PackageLines int `json:"package_lines"`
}

// vendorScope is the machine-readable scope statement. No field carries
// omitempty: a CI gate must be able to assert `.covered == .tree_modules`, and
// a zero that is absent cannot be asserted on.
type vendorScope struct {
	TreeModules int                     `json:"tree_modules"`
	Covered     int                     `json:"covered"`
	Uncovered   []vendorUncoveredModule `json:"uncovered"`
}

// vendorSection is the deterministic top-level `vendor` JSON section: modules
// and findings are domain-sorted and no wall-clock field is emitted, so
// identical inputs yield identical bytes.
type vendorSection struct {
	SchemaVersion   string          `json:"schema_version"`
	Ecosystem       string          `json:"ecosystem"`
	PipelineVersion string          `json:"pipeline_version"`
	Project         string          `json:"project"`
	VendorDir       string          `json:"vendor_dir"`
	VendorOnly      bool            `json:"vendor_only"`
	OverallStatus   string          `json:"overall_status"`
	ContentHash     string          `json:"content_hash"`
	Modules         []vendorModule  `json:"modules"`
	Findings        []vendorFinding `json:"findings"`
	// Scope states how much of the vendored tree this section describes and
	// names every module it does not, so a correct narrowing reads as one.
	Scope vendorScope `json:"scope"`
}

// vendorStatusNotVendored is the overall status for a project with no vendor
// tree. It is deliberately distinct from the domain's "clean" and "findings":
// those both mean reconciliation ran, and reporting an absent vendor tree as
// clean would present a gap as a verified result.
const vendorStatusNotVendored = "not_vendored"

// notVendoredSection is the section emitted when the project has no
// vendor/modules.txt. Modules and Findings are empty arrays rather than nil so
// the document a caller parses has the same shape as a populated one, and
// neither collection decodes as null. Project is left empty because the scan
// never established the module path — stating a value here would be inventing
// one.
func notVendoredSection(vendorOnly bool) vendorSection {
	return vendorSection{
		SchemaVersion:   vendomain.VendorSchemaVersion,
		Ecosystem:       vendomain.EcosystemGo,
		PipelineVersion: vendomain.PipelineVersion,
		VendorOnly:      vendorOnly,
		OverallStatus:   vendorStatusNotVendored,
		Modules:         []vendorModule{},
		Findings:        []vendorFinding{},
		// There is no vendored tree, so there is nothing to state scope over.
		Scope: vendorScope{Uncovered: []vendorUncoveredModule{}},
	}
}

// toVendorScope projects the domain scope statement into its JSON shape.
// Uncovered is an empty array rather than nil so full coverage decodes as a
// list with nothing in it, not as null.
func toVendorScope(s vendomain.VendorScope) vendorScope {
	out := vendorScope{
		TreeModules: s.TreeModules,
		Covered:     s.Covered,
		Uncovered:   make([]vendorUncoveredModule, 0, len(s.Uncovered)),
	}
	for _, u := range s.Uncovered {
		out.Uncovered = append(out.Uncovered, vendorUncoveredModule{
			Path: u.Path, Version: u.Version, Reason: u.Reason,
			PackageLines: u.PackageLines,
		})
	}
	return out
}

// toVendorSection projects a domain record into the JSON section. Shared by
// the `vendor` command and the `inspect` aggregate.
func toVendorSection(rec vendomain.Record) vendorSection {
	out := vendorSection{
		SchemaVersion:   rec.SchemaVersion,
		Ecosystem:       rec.Ecosystem,
		PipelineVersion: rec.PipelineVersion,
		Project:         rec.ProjectModulePath,
		VendorDir:       rec.VendorDir,
		VendorOnly:      rec.VendorOnly,
		OverallStatus:   rec.OverallStatus,
		ContentHash:     rec.ContentHash,
		Modules:         make([]vendorModule, 0, len(rec.Modules)),
		Findings:        make([]vendorFinding, 0, len(rec.Findings)),
		Scope:           toVendorScope(rec.Scope),
	}
	for _, m := range rec.Modules {
		out.Modules = append(out.Modules, vendorModule{
			Path: m.Path, Version: m.Version, Explicit: m.Explicit,
			Present: m.Present, Dir: m.Dir, Packages: m.PackageCount,
			ExpectedHash: m.ExpectedHash,
		})
	}
	for _, f := range rec.Findings {
		out.Findings = append(out.Findings, vendorFinding{
			Kind: string(f.Kind), Module: f.Module, Version: f.Version,
			File:   f.File,
			Detail: f.Detail, Expected: f.Expected, Actual: f.Actual,
			PolicyOutcome: f.PolicyOutcome, PolicyBlocking: f.PolicyBlocking,
		})
	}
	return out
}

func newVendorCmd(stdout, stderr io.Writer) *cobra.Command {
	var gomodPath string
	var vendorOnly bool
	cmd := &cobra.Command{
		Use:   "vendor",
		Short: "Analyse a vendored project and detect vendor/ drift & inconsistency",
		Long: `vendor treats a vendored project (vendor/ + vendor/modules.txt) as a
first-class input: it resolves the closure from modules.txt instead of
re-fetching from the proxy, checks every file under vendor/ against the same
file in the module zip go.sum verifies, and reconciles vendor/modules.txt
against the filesystem and the go.mod require set.

A vendored tree is pruned to the packages the build imports, so files the
module publishes and vendor/ omits are expected and are not reported. A file
vendor/ holds that the published module does not, or holds with different
bytes, is drift.

Findings: drift (a vendored file ≠ the published module), missing/extra modules between
modules.txt and vendor/, modules.txt-vs-go.mod version mismatch, and
unverified modules with no go.sum entry (surfaced, never assumed clean).
The default policy flags drift and inconsistency (warn), so this
command exits non-zero when a finding's policy outcome is "warn".

Exit codes:
  0  no finding resolves to a blocking policy outcome
  5  the governance gate fired: drift or inconsistency violates policy
  20 bad invocation, no vendor/ tree, or a policy file that could not be read

--vendor-only asserts the airgapped contract: the scan completes with no
proxy contact, resolving the closure entirely from modules.txt.`,
		Example: `  kanonarion vendor
  kanonarion vendor --gomod ./go.mod --vendor-only --json`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runVendor(cmd.Context(), gomodPath, vendorOnly, stdout, stderr)
		},
	}
	cmd.Flags().StringVar(&gomodPath, "gomod", "", "path to go.mod file (default: ./go.mod)")
	cmd.Flags().BoolVar(&vendorOnly, "vendor-only", false, "airgapped scan: no proxy contact (also set via vendor_policy.vendor_only)")
	return cmd
}

func runVendor(ctx context.Context, gomodFlag string, vendorOnly bool, stdout, stderr io.Writer) error {
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

	// The flag OR the configured posture enables vendor-only mode.
	vendorOnly = vendorOnly || activeConfig.VendorPolicy.VendorOnly

	rec, err := ctr.ExtractVendor.Extract(ctx, gomodPath, vendorOnly, activeConfig.VendorPolicy)
	if err != nil {
		if errors.Is(err, vendports.ErrNotVendored) {
			// An unvendored project is its own answer, and it is answered on
			// the caller's own channel: a section under --json, prose only on
			// the text path. The status is not "clean" — clean asserts that
			// reconciliation ran and found nothing, which would present an
			// absent vendor tree as a verified one.
			if jsonOut {
				enc := json.NewEncoder(stdout)
				enc.SetIndent("", "  ")
				if encErr := enc.Encode(notVendoredSection(vendorOnly)); encErr != nil {
					return fmt.Errorf("encoding vendor: %w", encErr)
				}
				return nil
			}
			_, _ = fmt.Fprintf(stdout, "project is not vendored (no vendor/modules.txt); nothing to reconcile\n")
			return nil
		}
		return fmt.Errorf("scanning vendored project: %w", err)
	}
	section := toVendorSection(rec)

	if jsonOut {
		enc := json.NewEncoder(stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(section); err != nil {
			return fmt.Errorf("encoding vendor: %w", err)
		}
		return vendorBlockingErr(section)
	}
	if err := printVendorTable(stdout, section); err != nil {
		return err
	}
	return vendorBlockingErr(section)
}

func printVendorTable(stdout io.Writer, s vendorSection) error {
	if _, err := fmt.Fprintf(stdout, "project: %s  vendor: %s  status: %s  vendor-only: %t\n",
		s.Project, s.VendorDir, s.OverallStatus, s.VendorOnly); err != nil {
		return fmt.Errorf("writing output: %w", err)
	}
	if err := printVendorScope(stdout, s.Scope); err != nil {
		return err
	}
	if len(s.Findings) == 0 {
		if _, err := fmt.Fprintf(stdout, "no vendor findings (%d modules reconciled)\n", len(s.Modules)); err != nil {
			return fmt.Errorf("writing output: %w", err)
		}
		return nil
	}
	tw := tabwriter.NewWriter(stdout, 0, 2, 2, ' ', 0)
	// FILE carries the drift axis, which is decided per file: naming the module
	// alone would leave a reader unable to see which file to look at.
	if _, err := fmt.Fprintln(tw, "KIND\tMODULE\tVERSION\tFILE\tEXPECTED\tACTUAL\tPOLICY"); err != nil {
		return fmt.Errorf("writing output: %w", err)
	}
	for _, f := range s.Findings {
		if _, err := fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\t%s\n",
			f.Kind, f.Module, f.Version, f.File, f.Expected, f.Actual, f.PolicyOutcome); err != nil {
			return fmt.Errorf("writing output: %w", err)
		}
	}
	if err := tw.Flush(); err != nil {
		return fmt.Errorf("flushing output: %w", err)
	}
	return nil
}

// printVendorScope writes the scope statement: how much of the vendored tree
// this report describes, and every module it does not with the reason. Full
// coverage is stated rather than left to silence — a reader cannot tell a
// complete report from a narrowed one that says nothing.
func printVendorScope(stdout io.Writer, s vendorScope) error {
	if s.TreeModules == 0 {
		return nil
	}
	if _, err := fmt.Fprintf(stdout, "scope: %d of %d vendored modules described\n",
		s.Covered, s.TreeModules); err != nil {
		return fmt.Errorf("writing output: %w", err)
	}
	if len(s.Uncovered) == 0 {
		if _, err := fmt.Fprintln(stdout, "  the report covers the whole vendored tree"); err != nil {
			return fmt.Errorf("writing output: %w", err)
		}
		return nil
	}
	for _, u := range s.Uncovered {
		if _, err := fmt.Fprintf(stdout, "  not described: %s %s — %s\n", u.Path, u.Version, u.Reason); err != nil {
			return fmt.Errorf("writing output: %w", err)
		}
	}
	return nil
}

// vendorBlockingErr returns an ExitPolicy error when any finding
// resolves to a blocking ("warn") policy outcome — drift or an inconsistency
// under the default policy — making the command a CI gate.
func vendorBlockingErr(s vendorSection) error {
	var blocked []string
	for _, f := range s.Findings {
		if f.PolicyBlocking {
			subject := f.Module
			if f.File != "" {
				subject = f.Module + "/" + f.File
			}
			blocked = append(blocked, fmt.Sprintf("%s %s", f.Kind, subject))
		}
	}
	if len(blocked) == 0 {
		return nil
	}
	return &exitError{code: ExitPolicy, msg: fmt.Sprintf(
		"vendor policy: %d finding(s) violate policy: %v", len(blocked), blocked)}
}
