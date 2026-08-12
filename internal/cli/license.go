package cli

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sort"
	"strings"
	"time"

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
	history   bool
	// walkID pins the walk --recursive reports the closure of. Empty leaves the
	// choice to the default rule, which states the walk it picked.
	walkID string
}

// -- license extract command --

func newLicenseCmd(stdout, stderr io.Writer) *cobra.Command {
	var f licenseFlags

	cmd := &cobra.Command{
		Use: "license <module>@<version>",
		// The docs and the store speak British English; accept both spellings so
		// neither the documented form nor the SPDX-conventional one is wrong.
		Aliases: []string{"licence"},
		Short:   "Extract and persist license information for a Go module",
		Example: `  kanonarion license github.com/spf13/cobra@v1.8.1
  kanonarion license github.com/spf13/cobra@v1.8.1 --json
  kanonarion license github.com/spf13/cobra@v1.8.1 --force
  kanonarion license example.com/project@local --recursive --walk-id 01KZ42BGN0T95D932JMC1GXX3C`,
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
	cmd.Flags().BoolVar(&f.history, "history", false, "show every stored generation for the module instead of extracting")
	cmd.Flags().StringVar(&f.walkID, "walk-id", "", "with --recursive: report the closure of this walk instead of the one the default rule picks")

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

	if f.history {
		return runLicenseHistory(ctx, coord, ctr.QueryLicense, stdout)
	}

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
		if err := printLicenseRecursive(ctx, coord, ctr.QueryWalks, ctr.ExtractLicense, ctr.QueryLicense, f, stdout, stderr); err != nil {
			return fmt.Errorf("recursive license report: %w", err)
		}
	}

	return nil
}

// runLicenseHistory prints every generation the ledger holds for a coordinate,
// oldest first, and marks the one composition serves.
//
// The served record is marked rather than printed alone, because the point of
// the ledger is that the two are different things: what is believed now, and
// what was believed before and on the strength of which bytes.
func runLicenseHistory(ctx context.Context, coord coordinate.ModuleCoordinate, uc QueryLicenseUseCase, stdout io.Writer) error {
	recs, err := uc.LicenseHistory(ctx, coord, licapp.PipelineVersion)
	if err != nil {
		return fmt.Errorf("reading license history: %w", err)
	}
	if len(recs) == 0 {
		if _, werr := fmt.Fprintf(stdout, "no license records for %s\n", coord); werr != nil {
			return fmt.Errorf("writing output: %w", werr)
		}
		return nil
	}

	// A conflict is reported, not hidden: the history view is precisely where an
	// operator goes to see why the composed read refused to pick.
	servedHash := ""
	served, found, gerr := uc.GetLicenseRecord(ctx, coord, licapp.PipelineVersion)
	switch {
	case gerr != nil:
		if _, werr := fmt.Fprintf(stdout, "composed answer: unavailable — %v\n\n", gerr); werr != nil {
			return fmt.Errorf("writing output: %w", werr)
		}
	case found:
		servedHash = served.ContentHash
	}

	if _, werr := fmt.Fprintf(stdout, "%d generation(s) for %s at pipeline %s:\n",
		len(recs), coord, licapp.PipelineVersion); werr != nil {
		return fmt.Errorf("writing output: %w", werr)
	}
	for _, r := range recs {
		marker := " "
		if r.ContentHash != "" && r.ContentHash == servedHash {
			marker = "*"
		}
		artefact := r.ArtefactIdentity
		if artefact == "" {
			artefact = "(no artefact recorded)"
		}
		spdx := r.PrimarySPDX
		if spdx == "" {
			spdx = "-"
		}
		if _, werr := fmt.Fprintf(stdout, "%s %s  %-20s conf=%.2f  %s\n    artefact: %s\n    record:   %s\n",
			marker, r.ExtractedAt.UTC().Format(time.RFC3339), spdx, r.PrimaryConfidence,
			r.OverallStatus.String(), artefact, r.ContentHash); werr != nil {
			return fmt.Errorf("writing output: %w", werr)
		}
	}
	if _, werr := fmt.Fprintln(stdout, "\n* served by the composed read (highest confidence, then most recent)"); werr != nil {
		return fmt.Errorf("writing output: %w", werr)
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
	stdout, stderr io.Writer,
) error {
	// Which walk's closure is being listed. --recursive reports a build's
	// dependency set, and a store holding several walks of one project holds
	// several different ones; the caller either names the walk or is told which
	// was named for them.
	var choice walkChoice
	if f.walkID != "" {
		rec, perr := resolvePinnedWalk(ctx, walksUC, f.walkID, target)
		if perr != nil {
			return perr
		}
		choice = pinnedWalkChoice(rec)
	} else {
		summaries, lerr := walksUC.ListWalks(ctx, walkports.WalkFilter{Target: &target})
		if lerr != nil {
			return fmt.Errorf("listing walks: %w", lerr)
		}
		if len(summaries) == 0 {
			return walkTargetMiss(ctx, walksUC, target, stderr)
		}
		choice = chooseWalk(ctx, walksUC, summaries, "")
	}

	extractFn := func(ctx context.Context, coord coordinate.ModuleCoordinate) (domain.LicenseRecord, error) {
		res, err := extractUC.Execute(ctx, licapp.ExtractRequest{Coordinate: coord, Force: f.force})
		if err != nil {
			return domain.LicenseRecord{}, fmt.Errorf("extracting license for %s: %w", coord, err)
		}
		return res.Record, nil
	}

	depResults, err := queryUC.ResolveForWalk(ctx, choice.summary.ID, target, extractFn)
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

	// Which walk answered, and in which frame. A closure listed here is the
	// closure of one platform's build — GOOS gates which files, and so which
	// modules, that build selects — and the choice between the store's walks of
	// this target is stated on the line below when there was a choice to make.
	if _, err := fmt.Fprintf(stdout, "\nAnswered from walk %s (frame %s)\n", choice.summary.ID, choice.summary.BuildFrame()); err != nil {
		return fmt.Errorf("writing walk frame: %w", err)
	}
	if note := choice.statement(); note != "" {
		if _, err := fmt.Fprint(stdout, note); err != nil {
			return fmt.Errorf("writing walk selection notice: %w", err)
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
			// ElectiveObligations carries per-arm obligations when the
			// expression is a disjunction (a dual licence): the obligations in
			// force are those of the arm the consumer elects, an operator
			// decision recorded via license_overrides — never resolved here.
			ElectiveObligations map[string]domain.Obligations `json:"elective_obligations,omitempty"`
		}
		out := licenseRecordWithObligations{
			LicenseRecord: r,
			Obligations:   domain.LookupObligations(r.PrimarySPDX),
		}
		if arms := domain.DisjunctionArms(r.Expression); len(arms) >= 2 {
			out.ElectiveObligations = make(map[string]domain.Obligations, len(arms))
			for _, arm := range arms {
				out.ElectiveObligations[arm] = domain.LookupObligations(arm)
			}
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
		r.Coordinate.Path(), r.Coordinate.Version(),
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
	// A dual licence (disjunctive expression) has no single obligation set:
	// the obligations in force are those of the elected arm, so each arm is
	// rendered per election rather than asserting the primary's obligations —
	// which would claim, e.g., GPL disclose-source of a consumer electing the
	// Apache arm.
	if arms := domain.DisjunctionArms(r.Expression); len(arms) >= 2 {
		return printElectiveObligationsSection(arms, stdout)
	}
	return printObligationsSection(r.PrimarySPDX, stdout)
}

// printElectiveObligationsSection renders per-arm obligations for a
// dual-licensed module and names the election as an operator decision.
func printElectiveObligationsSection(arms []string, stdout io.Writer) error {
	if _, err := fmt.Fprintln(stdout, "  dual licence: obligations depend on the elected arm — the election is an"); err != nil {
		return fmt.Errorf("writing elective obligations header: %w", err)
	}
	if _, err := fmt.Fprintln(stdout, "  operator decision, recorded as a license_overrides entry for this module"); err != nil {
		return fmt.Errorf("writing elective obligations header: %w", err)
	}
	for _, arm := range arms {
		ob := domain.LookupObligations(arm)
		if ob.Status == domain.ObligationStatusUnknown {
			if _, err := fmt.Fprintf(stdout, "  obligations if %s is elected: unknown (%s not in catalogue v%s)\n",
				arm, arm, domain.ObligationCatalogueVersion); err != nil {
				return fmt.Errorf("writing obligations: %w", err)
			}
			continue
		}
		if _, err := fmt.Fprintf(stdout, "  obligations if %s is elected (catalogue v%s):\n",
			arm, domain.ObligationCatalogueVersion); err != nil {
			return fmt.Errorf("writing obligations header: %w", err)
		}
		if err := printObligationRows(ob, stdout); err != nil {
			return err
		}
	}
	return nil
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
	return printObligationRows(ob, stdout)
}

// printObligationRows renders the labelled obligation rows shared by the
// single-licence and per-election obligation sections.
func printObligationRows(ob domain.Obligations, stdout io.Writer) error {
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
	var limit, offset int

	cmd := &cobra.Command{
		Use:     "license-list",
		Aliases: []string{"licence-list"},
		Short:   "List extracted license records",
		// The command filters by flag only. Without this a stray positional was
		// accepted and silently ignored, so `license-list <module>` printed the
		// whole store and read as "this module holds every one of these".
		Args: cobra.NoArgs,
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
			return runLicenseList(cmd.Context(), spdx, copyright, limit, offset, ctr.QueryLicense, ovSet, stdout, stderr)
		},
	}

	cmd.Flags().StringVar(&spdx, "spdx", "", "filter by SPDX identifier (e.g. MIT)")
	cmd.Flags().StringVar(&copyright, "copyright", "", "filter by copyright holder substring (case-insensitive; loads full records)")
	cmd.Flags().IntVar(&limit, "limit", 50, "maximum number of records to return (0 = unlimited)")
	cmd.Flags().IntVar(&offset, "offset", 0, "skip this many records")

	return cmd
}

func runLicenseList(ctx context.Context, spdx, copyright string, limit, offset int, uc QueryLicenseUseCase, overrides domain.LicenseOverrideSet, stdout, stderr io.Writer) error {
	// When copyright filtering is active, fetch without a limit so we can
	// post-filter by full record; re-apply the caller's limit afterwards.
	// One row more than will be printed, so the extra row's presence answers
	// whether the limit bit. No count is taken: how many were withheld would
	// cost a second read this listing does not otherwise pay.
	// Paging goes to the port, which applies it to the same ordering the unpaged
	// listing produces — except under --copyright, where the population being
	// paged is the post-filtered set and a port offset would skip records the
	// filter had not yet seen. There the skip is applied to the filtered rows
	// below, on the only set that is the caller's page.
	fetchLimit := truncationFetchLimit(limit)
	fetchOffset := offset
	if copyright != "" {
		fetchLimit = 0
		fetchOffset = 0
	}
	filter := ports.LicenseFilter{SPDX: spdx, Limit: fetchLimit, Offset: fetchOffset}
	sums, err := uc.ListLicenseRecords(ctx, filter)
	if err != nil {
		return fmt.Errorf("listing license records: %w", err)
	}

	if copyright != "" {
		var matched []ports.LicenseSummary
		for _, s := range sums {
			coord, cErr := coordinate.NewModuleCoordinate(s.ModulePath, s.ModuleVersion)
			if cErr != nil {
				return fmt.Errorf("license record %s@%s names no module: %w", s.ModulePath, s.ModuleVersion, cErr)
			}
			rec, found, rerr := uc.GetLicenseRecord(ctx, coord, s.PipelineVersion)
			if rerr != nil || !found {
				continue
			}
			if domain.MatchesCopyrightHolder(rec.LicenseFiles, copyright) {
				matched = append(matched, s)
			}
		}
		sums = matched
		sums = skipList(sums, offset)
	}
	sums, truncated := truncateList(sums, limit)
	trunc := listTruncation{limit: limit, subject: "license records", truncated: truncated, offset: offset}
	if jsonOut {
		type entry struct {
			Module     string `json:"module"`
			Version    string `json:"version"`
			Status     string `json:"status"`
			License    string `json:"license"`
			Expression string `json:"expression,omitempty"`
			Source     string `json:"source"`
			// Conflict carries the disagreement composition refused to resolve. A
			// consumer parsing this must not read an absent license as "no licence".
			Conflict string `json:"conflict,omitempty"`
		}
		out := make([]entry, 0, len(sums))
		var jsonConflicts []error
		for _, s := range sums {
			coord, cErr := coordinate.NewModuleCoordinate(s.ModulePath, s.ModuleVersion)
			if cErr != nil {
				return fmt.Errorf("license record %s@%s names no module: %w", s.ModulePath, s.ModuleVersion, cErr)
			}
			if s.Conflict != nil {
				jsonConflicts = append(jsonConflicts, s.Conflict)
				out = append(out, entry{
					Module: s.ModulePath, Version: s.ModuleVersion,
					Status: "Conflict", Source: "scanner", Conflict: s.Conflict.Error(),
				})
				continue
			}
			license := s.PrimarySPDX
			expr := s.Expression
			source := "scanner"
			if ov, ok := overrides.Resolve(coord); ok {
				license = ov.SPDX
				expr = ""
				source = "override"
			}
			out = append(out, entry{s.ModulePath, s.ModuleVersion, s.OverallStatus.String(), license, expr, source, ""})
		}
		enc := json.NewEncoder(stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(out); err != nil {
			return fmt.Errorf("encoding JSON: %w", err)
		}
		if len(out) == 0 {
			scope, serr := licenseListZeroScope(ctx, spdx, copyright, offset, uc)
			if serr != nil {
				return serr
			}
			return writeListZeroNoticeJSON(stderr, scope)
		}
		if terr := writeListTruncationJSON(stderr, trunc); terr != nil {
			return terr
		}
		if len(jsonConflicts) > 0 {
			return fmt.Errorf("%d module(s) hold conflicting license records: %w", len(jsonConflicts), errors.Join(jsonConflicts...))
		}
		return nil
	}
	if len(sums) == 0 {
		scope, serr := licenseListZeroScope(ctx, spdx, copyright, offset, uc)
		if serr != nil {
			return serr
		}
		return writeListZeroNotice(stdout, scope)
	}
	var conflicts []error
	for _, s := range sums {
		coord, cErr := coordinate.NewModuleCoordinate(s.ModulePath, s.ModuleVersion)
		if cErr != nil {
			return fmt.Errorf("license record %s@%s names no module: %w", s.ModulePath, s.ModuleVersion, cErr)
		}
		if s.Conflict != nil {
			conflicts = append(conflicts, s.Conflict)
			if _, err := fmt.Fprintf(stdout, "%-50s %-12s %-20s %s\n",
				s.ModulePath+"@"+s.ModuleVersion, "CONFLICT", "unresolved",
				"run 'kanonarion license "+s.ModulePath+"@"+s.ModuleVersion+" --history'"); err != nil {
				return fmt.Errorf("writing output: %w", err)
			}
			continue
		}
		license := s.PrimarySPDX
		if s.Expression != "" {
			license = s.Expression
		}
		source := "scanner"
		if ov, ok := overrides.Resolve(coord); ok {
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
	if terr := writeListTruncationNotice(stdout, trunc); terr != nil {
		return terr
	}
	// Every module is listed first, then the command fails. A licence in dispute
	// must not be reported as a clean run.
	if len(conflicts) > 0 {
		return fmt.Errorf("%d module(s) hold conflicting license records: %w", len(conflicts), errors.Join(conflicts...))
	}
	return nil
}

// licenseListZeroScope lifts both filters and re-asks the store, so a zero
// distinguishes an identifier or holder that matched nothing from a store with
// no licence records in it. Reached only when the listing came back empty.
//
// The two filters are named together when both are set: dropping one from the
// statement would send the reader to check a spelling that was not the one that
// excluded their module.
func licenseListZeroScope(ctx context.Context, spdx, copyright string, offset int, uc QueryLicenseUseCase) (listZeroScope, error) {
	all, err := uc.ListLicenseRecords(ctx, ports.LicenseFilter{})
	if err != nil {
		return listZeroScope{}, fmt.Errorf("counting license records for the zero-result notice: %w", err)
	}
	scope := listZeroScope{
		subject:    "license record",
		considered: len(all),
		produce:    "kanonarion license <module>@<version>",
		listAll:    "kanonarion license-list",
	}
	if len(all) > 0 {
		scope.example = all[0].PrimarySPDX
	}
	switch {
	case spdx != "" && copyright != "":
		scope.filterName = "SPDX identifier and copyright holder"
		scope.filterValue = spdx + " / " + copyright
		scope.field = "primary SPDX identifier, then the copyright holder in the licence files"
		scope.matchKind = matchExact + " then " + matchSubstring
	case spdx != "":
		scope.filterName = "SPDX identifier"
		scope.filterValue = spdx
		scope.field = "primary SPDX identifier"
		scope.matchKind = matchExact
	case copyright != "":
		scope.filterName = "copyright holder"
		scope.filterValue = copyright
		scope.field = "copyright holder recorded in the licence files"
		scope.matchKind = matchSubstring
		// The illustration has to be in the shape the filter compares against,
		// and an SPDX identifier is not one.
		scope.example = ""
	}
	// An offset past the end empties the page without the filter having anything
	// to do with it, and the two look identical from the rows alone.
	// An empty corpus is not something a page can start past, so a zero over it
	// keeps the store-empty statement and its produce-a-record remedy.
	if scope.filterValue == "" && len(all) > 0 && offset > 0 && offset >= len(all) {
		scope.pagedPast = fmt.Sprintf("--offset %d starts past the last one", offset)
	}
	return scope, nil
}
