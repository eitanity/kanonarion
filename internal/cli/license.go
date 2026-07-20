package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/eitanity/kanonarion/internal/coordinate"

	licapp "github.com/eitanity/kanonarion/internal/license/application"
	"github.com/eitanity/kanonarion/internal/license/domain"
	"github.com/eitanity/kanonarion/internal/license/ports"
	walkports "github.com/eitanity/kanonarion/internal/walk/ports"
	"github.com/spf13/cobra"
)

type licenseFlags struct {
	force     bool
	recursive bool
	all       bool
	perFile   bool
}

// -- license extract command --

func newLicenseCmd(stdout, stderr io.Writer) *cobra.Command {
	var f licenseFlags

	cmd := &cobra.Command{
		Use:   "license <module>@<version>",
		Short: "Extract and persist license information for a Go module",
		Example: `  kanonarion license github.com/spf13/cobra@v1.8.1
  kanonarion license github.com/spf13/cobra@v1.8.1 --json
  kanonarion license github.com/spf13/cobra@v1.8.1 --force`,
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) == 0 {
				return usageErr(cmd)
			}
			if len(args) > 1 {
				return fmt.Errorf("accepts 1 arg, received %d", len(args))
			}
			return runLicenseExtract(cmd.Context(), args[0], f, stdout, stderr)
		},
	}

	cmd.Flags().BoolVar(&f.force, "force", false, "re-extract even if cached")
	cmd.Flags().BoolVar(&f.recursive, "recursive", false, "report licenses for dependencies recursively")
	cmd.Flags().BoolVar(&f.all, "all", false, "show all dependencies and their licenses")
	cmd.Flags().BoolVar(&f.perFile, "per-file", false, "scan root-level .go files for SPDX headers when no license file is found")

	return cmd
}

func runLicenseExtract(ctx context.Context, arg string, f licenseFlags, stdout, stderr io.Writer) error {
	logger := buildLogger(logLevel, stderr)

	coord, err := parseCoordinate(arg)
	if err != nil {
		return fmt.Errorf("invalid coordinate %q: %w", arg, err)
	}

	ctr, cleanup, err := NewContainer(storeRoot, "", "", false, activeConfig, logger)
	if err != nil {
		return fmt.Errorf("initialising store: %w", err)
	}
	defer func() { _ = cleanup() }()

	result, err := ctr.ExtractLicense.Execute(ctx, licapp.ExtractRequest{
		Coordinate: coord,
		Force:      f.force,
		PerFile:    f.perFile,
	})
	if err != nil {
		return fmt.Errorf("extracting license: %w", err)
	}

	if err := printLicenseRecord(result.Record, result.FromCache, jsonOut, stdout); err != nil {
		return err
	}

	if (f.recursive || f.all) && !jsonOut {
		if err := printLicenseRecursive(ctx, coord, ctr.QueryWalks, ctr.ExtractLicense, ctr.QueryLicense, f, stdout); err != nil {
			return fmt.Errorf("recursive license report: %w", err)
		}
	}

	return nil
}

func printLicenseRecursive(
	ctx context.Context,
	target coordinate.ModuleCoordinate,
	walksUC QueryWalksUseCase,
	extractUC ExtractLicenseUseCase,
	queryUC QueryLicenseUseCase,
	f licenseFlags,
	stdout io.Writer,
) error {
	summaries, err := walksUC.ListWalks(ctx, walkports.WalkFilter{Target: &target, Limit: 1})
	if err != nil {
		return fmt.Errorf("listing walks: %w", err)
	}
	if len(summaries) == 0 {
		return fmt.Errorf("no walk record found for %s — run 'kanonarion walk' first", target)
	}

	extractFn := func(ctx context.Context, coord coordinate.ModuleCoordinate) (domain.LicenseRecord, error) {
		res, err := extractUC.Execute(ctx, licapp.ExtractRequest{Coordinate: coord, Force: f.force})
		if err != nil {
			return domain.LicenseRecord{}, fmt.Errorf("extracting license for %s: %w", coord, err)
		}
		return res.Record, nil
	}

	depResults, err := queryUC.ResolveForWalk(ctx, summaries[0].ID, target, extractFn)
	if err != nil {
		return fmt.Errorf("resolving walk licenses: %w", err)
	}
	if len(depResults) == 0 {
		return nil
	}

	primaryLic := "Unknown"
	if primaryRec, found, err := queryUC.GetLicenseRecord(ctx, target, licapp.PipelineVersion); err == nil && found {
		if primaryRec.PrimarySPDX != "" {
			primaryLic = primaryRec.PrimarySPDX
		} else {
			primaryLic = "None"
		}
	}

	if f.all {
		if _, err := fmt.Fprintf(stdout, "\nDependency Licenses:\n"); err != nil {
			return fmt.Errorf("writing header: %w", err)
		}
		for _, d := range depResults {
			status := d.PrimarySPDX
			if d.Err != nil {
				status = fmt.Sprintf("Error: %v", d.Err)
			}
			if _, err := fmt.Fprintf(stdout, "  %-50s: %s\n", d.Coordinate, status); err != nil {
				return fmt.Errorf("writing dep: %w", err)
			}
		}
		return nil
	}

	// Summarize.
	licenseCounts := make(map[string]int)
	for _, d := range depResults {
		lic := d.PrimarySPDX
		if d.Err != nil {
			lic = "Unknown"
		}
		licenseCounts[lic]++
	}

	different := false
	for lic := range licenseCounts {
		if lic != primaryLic {
			different = true
			break
		}
	}

	if !different {
		if _, err := fmt.Fprintf(stdout, "  All %d dependencies use the same license (%s).\n", len(depResults), primaryLic); err != nil {
			return fmt.Errorf("writing summary: %w", err)
		}
		return nil
	}

	if _, err := fmt.Fprintf(stdout, "\nDependency License Summary:\n"); err != nil {
		return fmt.Errorf("writing header: %w", err)
	}
	licenses := make([]string, 0, len(licenseCounts))
	for l := range licenseCounts {
		licenses = append(licenses, l)
	}
	sort.Strings(licenses)
	for _, l := range licenses {
		if _, err := fmt.Fprintf(stdout, "  %s: %d modules\n", l, licenseCounts[l]); err != nil {
			return fmt.Errorf("writing summary line: %w", err)
		}
	}
	return nil
}

func printLicenseRecord(r domain.LicenseRecord, fromCache bool, jsonOut bool, stdout io.Writer) error {
	if jsonOut {
		type licenseRecordWithObligations struct {
			domain.LicenseRecord
			Obligations domain.Obligations `json:"obligations"`
		}
		out := licenseRecordWithObligations{
			LicenseRecord: r,
			Obligations:   domain.LookupObligations(r.PrimarySPDX),
		}
		enc := json.NewEncoder(stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(out); err != nil {
			return fmt.Errorf("encoding JSON: %w", err)
		}
		return nil
	}

	cached := ""
	if fromCache {
		cached = " (cached)"
	}
	displayLicense := r.PrimarySPDX
	if r.Expression != "" {
		displayLicense = r.Expression
	}
	if _, err := fmt.Fprintf(stdout, "%s@%s: %s — %s%s\n",
		r.Coordinate.Path, r.Coordinate.Version,
		r.OverallStatus.String(), displayLicense,
		cached,
	); err != nil {
		return fmt.Errorf("writing output: %w", err)
	}
	if r.FailureDetail != "" {
		if _, err := fmt.Fprintf(stdout, "  failure: %s\n", r.FailureDetail); err != nil {
			return fmt.Errorf("writing failure detail: %w", err)
		}
	}
	for _, f := range r.LicenseFiles {
		vendored := ""
		if f.IsVendored {
			vendored = " [vendored]"
		}
		if _, err := fmt.Fprintf(stdout, "  %s: %s (%.0f%%)%s\n",
			f.Path, f.SPDX, f.Confidence*100, vendored,
		); err != nil {
			return fmt.Errorf("writing file entry: %w", err)
		}
	}
	if err := printPackageLicensesSection(r, stdout); err != nil {
		return err
	}
	if err := printCopyrightSection(r, stdout); err != nil {
		return err
	}
	if err := printProvenanceSection(r, stdout); err != nil {
		return err
	}
	return printObligationsSection(r.PrimarySPDX, stdout)
}

func printPackageLicensesSection(r domain.LicenseRecord, stdout io.Writer) error {
	if len(r.PackageLicenses) == 0 {
		return nil
	}
	if _, err := fmt.Fprintf(stdout, "  per-package licenses (%d sub-packages):\n", len(r.PackageLicenses)); err != nil {
		return fmt.Errorf("writing per-package header: %w", err)
	}
	for _, pl := range r.PackageLicenses {
		spdx := pl.SPDX
		if spdx == "" {
			spdx = "unclassified"
		}
		if _, err := fmt.Fprintf(stdout, "    %-40s %s (%.0f%%)\n",
			pl.PackagePath, spdx, pl.Confidence*100,
		); err != nil {
			return fmt.Errorf("writing per-package entry: %w", err)
		}
	}
	return nil
}

func printObligationsSection(spdxID string, stdout io.Writer) error {
	if spdxID == "" {
		return nil
	}
	ob := domain.LookupObligations(spdxID)
	if ob.Status == domain.ObligationStatusUnknown {
		if _, err := fmt.Fprintf(stdout, "  obligations: unknown (%s not in catalogue v%s)\n",
			spdxID, domain.ObligationCatalogueVersion); err != nil {
			return fmt.Errorf("writing obligations: %w", err)
		}
		return nil
	}
	if _, err := fmt.Fprintf(stdout, "  obligations (%s, catalogue v%s):\n",
		spdxID, domain.ObligationCatalogueVersion); err != nil {
		return fmt.Errorf("writing obligations header: %w", err)
	}
	rows := []struct {
		label string
		value string
	}{
		{"include-notice", boolStr(ob.IncludeNotice)},
		{"include-license-text", boolStr(ob.IncludeLicenseText)},
		{"state-changes", boolStr(ob.StateChanges)},
		{"disclose-source", boolStr(ob.DiscloseSource)},
		{"same-license", ob.SameLicense.String()},
		{"network-use-trigger", boolStr(ob.NetworkUseTrigger)},
		{"no-trademark-use", boolStr(ob.NoTrademarkUse)},
		{"explicit-patent-grant", boolStr(ob.ExplicitPatentGrant)},
	}
	for _, row := range rows {
		if _, err := fmt.Fprintf(stdout, "    %-22s %s\n", row.label+":", row.value); err != nil {
			return fmt.Errorf("writing obligations row: %w", err)
		}
	}
	return nil
}

func boolStr(v bool) string {
	if v {
		return "true"
	}
	return "false"
}

func printCopyrightSection(r domain.LicenseRecord, stdout io.Writer) error {
	switch r.CopyrightStatus {
	case domain.CopyrightStatusNotAnalysed:
		if _, err := fmt.Fprintln(stdout, "  copyright: not analysed"); err != nil {
			return fmt.Errorf("writing copyright status: %w", err)
		}
	case domain.CopyrightStatusNoneFound:
		if _, err := fmt.Fprintln(stdout, "  copyright: none found"); err != nil {
			return fmt.Errorf("writing copyright status: %w", err)
		}
	case domain.CopyrightStatusExtractionFailed:
		if _, err := fmt.Fprintln(stdout, "  copyright: extraction failed"); err != nil {
			return fmt.Errorf("writing copyright status: %w", err)
		}
	case domain.CopyrightStatusFound:
		seen := make(map[string]struct{})
		var stmts []domain.CopyrightStatement
		for _, f := range r.LicenseFiles {
			for _, s := range f.CopyrightStatements {
				if _, dup := seen[s.Verbatim]; dup {
					continue
				}
				seen[s.Verbatim] = struct{}{}
				stmts = append(stmts, s)
			}
		}
		if _, err := fmt.Fprintf(stdout, "  copyright (%d statements):\n", len(stmts)); err != nil {
			return fmt.Errorf("writing copyright header: %w", err)
		}
		for _, s := range stmts {
			if _, err := fmt.Fprintf(stdout, "    %s  [%s]\n", s.Verbatim, s.Source); err != nil {
				return fmt.Errorf("writing copyright statement: %w", err)
			}
		}
	}
	return nil
}

// provenanceSignalLabel maps a contribution-licensing provenance signal to a
// reader-facing label for the text view. Falls back to the machine token.
func provenanceSignalLabel(s domain.ProvenanceSignal) string {
	switch s {
	case domain.ProvenanceSignalInboundOutbound:
		return "inbound=outbound"
	case domain.ProvenanceSignalCLARequired:
		return "CLA required"
	case domain.ProvenanceSignalDCORequired:
		return "DCO required"
	case domain.ProvenanceSignalAuthorsFile:
		return "AUTHORS"
	case domain.ProvenanceSignalContributorsFile:
		return "CONTRIBUTORS"
	case domain.ProvenanceSignalPatentsFile:
		return "PATENTS"
	default:
		return s.String()
	}
}

// printProvenanceSection renders the contribution-licensing chain-of-title as
// the facts found in the module zip, not as a compressed confidence verdict:
// the chain of title is evidence the reader weighs, never a judgement we make.
// The confidence enum's zero value still gates analysed from not-analysed so
// absence is surfaced, never assumed clean.
func printProvenanceSection(r domain.LicenseRecord, stdout io.Writer) error {
	p := r.Provenance
	if p.Confidence == domain.ChainOfTitleNotAnalysed {
		if _, err := fmt.Fprintln(stdout, "  provenance: not analysed"); err != nil {
			return fmt.Errorf("writing provenance status: %w", err)
		}
		return nil
	}

	// Signals are pre-sorted by signal value, so contribution statements and
	// attribution files emit in a deterministic order.
	var statements, attribution []string
	for _, sig := range p.Signals {
		switch sig {
		case domain.ProvenanceSignalInboundOutbound,
			domain.ProvenanceSignalCLARequired,
			domain.ProvenanceSignalDCORequired:
			statements = append(statements, provenanceSignalLabel(sig))
		case domain.ProvenanceSignalAuthorsFile,
			domain.ProvenanceSignalContributorsFile,
			domain.ProvenanceSignalPatentsFile:
			attribution = append(attribution, provenanceSignalLabel(sig))
		}
	}

	if _, err := fmt.Fprintln(stdout, "  provenance:"); err != nil {
		return fmt.Errorf("writing provenance header: %w", err)
	}
	stmt := "none found"
	if len(statements) > 0 {
		stmt = strings.Join(statements, ", ")
	}
	if _, err := fmt.Fprintf(stdout, "    contribution-licensing statement: %s\n", stmt); err != nil {
		return fmt.Errorf("writing contribution-licensing statement: %w", err)
	}
	if len(attribution) > 0 {
		if _, err := fmt.Fprintf(stdout, "    attribution files: %s\n", strings.Join(attribution, ", ")); err != nil {
			return fmt.Errorf("writing attribution files: %w", err)
		}
	}
	return nil
}

// -- license-list command --

func newLicenseListCmd(stdout, stderr io.Writer) *cobra.Command {
	var spdx string
	var copyright string
	var limit int

	cmd := &cobra.Command{
		Use:   "license-list",
		Short: "List extracted license records",
		RunE: func(cmd *cobra.Command, _ []string) error {
			logger := buildLogger(logLevel, stderr)
			ctr, cleanup, err := NewContainer(storeRoot, "", "", false, activeConfig, logger)
			if err != nil {
				return fmt.Errorf("initialising store: %w", err)
			}
			defer func() { _ = cleanup() }()
			ovSet, err := ctr.LicenseOverrides.LoadOverrides(cmd.Context())
			if err != nil {
				return fmt.Errorf("loading license overrides: %w", err)
			}
			return runLicenseList(cmd.Context(), spdx, copyright, limit, ctr.QueryLicense, ovSet, stdout)
		},
	}

	cmd.Flags().StringVar(&spdx, "spdx", "", "filter by SPDX identifier (e.g. MIT)")
	cmd.Flags().StringVar(&copyright, "copyright", "", "filter by copyright holder substring (case-insensitive; loads full records)")
	cmd.Flags().IntVar(&limit, "limit", 50, "maximum number of records to return (0 = unlimited)")

	return cmd
}

func runLicenseList(ctx context.Context, spdx, copyright string, limit int, uc QueryLicenseUseCase, overrides domain.LicenseOverrideSet, stdout io.Writer) error {
	// When copyright filtering is active, fetch without a limit so we can
	// post-filter by full record; re-apply the caller's limit afterwards.
	fetchLimit := limit
	if copyright != "" {
		fetchLimit = 0
	}
	filter := ports.LicenseFilter{SPDX: spdx, Limit: fetchLimit}
	sums, err := uc.ListLicenseRecords(ctx, filter)
	if err != nil {
		return fmt.Errorf("listing license records: %w", err)
	}

	if copyright != "" {
		var matched []ports.LicenseSummary
		for _, s := range sums {
			coord := coordinate.ModuleCoordinate{Path: s.ModulePath, Version: s.ModuleVersion}
			rec, found, rerr := uc.GetLicenseRecord(ctx, coord, s.PipelineVersion)
			if rerr != nil || !found {
				continue
			}
			if domain.MatchesCopyrightHolder(rec.LicenseFiles, copyright) {
				matched = append(matched, s)
			}
		}
		sums = matched
		if limit > 0 && len(sums) > limit {
			sums = sums[:limit]
		}
	}
	if jsonOut {
		type entry struct {
			Module     string `json:"module"`
			Version    string `json:"version"`
			Status     string `json:"status"`
			License    string `json:"license"`
			Expression string `json:"expression,omitempty"`
			Source     string `json:"source"`
		}
		out := make([]entry, 0, len(sums))
		for _, s := range sums {
			license := s.PrimarySPDX
			expr := s.Expression
			source := "scanner"
			if ov, ok := overrides.Resolve(coordinate.ModuleCoordinate{Path: s.ModulePath, Version: s.ModuleVersion}); ok {
				license = ov.SPDX
				expr = ""
				source = "override"
			}
			out = append(out, entry{s.ModulePath, s.ModuleVersion, s.OverallStatus.String(), license, expr, source})
		}
		enc := json.NewEncoder(stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(out); err != nil {
			return fmt.Errorf("encoding JSON: %w", err)
		}
		return nil
	}
	if len(sums) == 0 {
		if _, err := fmt.Fprintln(stdout, "no license records found"); err != nil {
			return fmt.Errorf("writing output: %w", err)
		}
		return nil
	}
	for _, s := range sums {
		license := s.PrimarySPDX
		if s.Expression != "" {
			license = s.Expression
		}
		source := "scanner"
		if ov, ok := overrides.Resolve(coordinate.ModuleCoordinate{Path: s.ModulePath, Version: s.ModuleVersion}); ok {
			license = ov.SPDX
			source = "override"
		}
		if _, err := fmt.Fprintf(stdout, "%-50s %-12s %-20s %s\n",
			s.ModulePath+"@"+s.ModuleVersion,
			s.OverallStatus.String(),
			license,
			source,
		); err != nil {
			return fmt.Errorf("writing output: %w", err)
		}
	}
	return nil
}
