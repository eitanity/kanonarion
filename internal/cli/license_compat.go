package cli

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/eitanity/kanonarion/internal/coordinate"

	licapp "github.com/eitanity/kanonarion/internal/license/application"
	"github.com/eitanity/kanonarion/internal/license/domain"
	walkports "github.com/eitanity/kanonarion/internal/walk/ports"
	"github.com/spf13/cobra"
)

// newLicenseCompatCmd returns the license-compat command, which evaluates a
// module's dependency closure against a target distribution license using the
// compatibility engine.
func newLicenseCompatCmd(stdout, stderr io.Writer) *cobra.Command {
	var targetSPDX string

	cmd := &cobra.Command{
		Use:     "license-compat <module>@<version>",
		Aliases: []string{"licence-compat"},
		Short:   "Report license conflicts in a module's dependency closure",
		Long: `Evaluates whether the dependency closure of <module>@<version> is
redistributable under --target.

Exit codes:
  0  clean — no conflicts, no unknown pairs, no elections pending
  1  conflicts — one or more deps are incompatible with the target license
  2  unknown pairs or pending elections — dep licenses not in the modelled
     dataset, or dual-licensed deps whose compatible arm has not been elected
     (requires human review; these are never silently "compatible")
  4  no walk record, or no licence record for the root — the diagnostic names
     the command that produces the missing record
  20 bad invocation (unparseable coordinate, wrong argument count)`,
		Example: `  kanonarion license-compat github.com/spf13/cobra@v1.8.1 --target Apache-2.0
  kanonarion license-compat github.com/spf13/cobra@v1.8.1 --target Apache-2.0 --json
  kanonarion license-compat example.com/project@local`,
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) == 0 {
				return usageErr(cmd)
			}
			if len(args) > 1 {
				return fmt.Errorf("accepts 1 arg, received %d", len(args))
			}
			return runLicenseCompat(cmd.Context(), args[0], targetSPDX, stdout, stderr)
		},
	}

	cmd.Flags().StringVar(&targetSPDX, "target", "", "target distribution license SPDX id (e.g. Apache-2.0); omitted: use the root's own analysed licence record as the target")

	return cmd
}

func runLicenseCompat(ctx context.Context, arg, targetSPDX string, stdout, stderr io.Writer) error {
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

	return licenseCompatWith(ctx, ctr, coord, targetSPDX, stdout)
}

// licenseCompatWith holds the license-compat logic over an injected Container:
// it resolves the root walk, runs the closure compatibility check, maps the
// intent-aware diagnostics (unanalysed root vs. no-SPDX root) and the
// clean/conflict/unknown verdict to exit codes, and renders the report. Split
// from runLicenseCompat so the exit-code and diagnostic decisions are testable
// without a live store.
func licenseCompatWith(ctx context.Context, ctr *Container, coord coordinate.ModuleCoordinate, targetSPDX string, stdout io.Writer) error {
	// Require an existing walk record for the root module.
	target := coord
	summaries, err := ctr.QueryWalks.ListWalks(ctx, walkports.WalkFilter{Target: &target, Limit: 1})
	if err != nil {
		return fmt.Errorf("listing walks: %w", err)
	}
	if len(summaries) == 0 {
		// return error once via exitError; main prints it. No fmt.Fprintf here.
		return &exitError{
			code: ExitNotFound,
			msg:  fmt.Sprintf("no walk record found for %s — run 'kanonarion walk %s' first", coord, coord),
		}
	}
	walkID := summaries[0].ID
	// The frame the verdict was measured in. The lookup takes the newest walk of
	// the root and has no build-environment axis, so a closure judged here is one
	// platform's build list; a verdict that did not say which would read as a
	// statement about the module rather than about a build of it.
	walkFrame := summaries[0].BuildFrame()

	// license_overrides entries are the operator's recorded decisions —
	// corrections and dual-licence elections — and must reach the engine so a
	// recorded election settles the electable verdict. A container wired
	// without the override store (seam tests) carries no decisions.
	var overrides domain.LicenseOverrideSet
	if ctr.LicenseOverrides != nil {
		overrides, err = ctr.LicenseOverrides.LoadOverrides(ctx)
		if err != nil {
			return fmt.Errorf("loading license overrides: %w", err)
		}
	}

	report, err := ctr.CheckCompatibility.CheckCompatibilityForWalk(ctx, walkID, coord, targetSPDX, overrides)
	if err != nil {
		// Implicit-target resolution failures get intent-aware diagnostics
		// say what is missing and which command produces it.
		switch {
		case errors.Is(err, licapp.ErrRootLicenceNotAnalysed):
			hint := fmt.Sprintf("run 'kanonarion license %s' first, or pass --target", coord)
			if coord.IsLocal() {
				hint = "run 'kanonarion walk --gomod ./go.mod --analyse-root' then 'kanonarion extract <walk-id>' to analyse the project's own licence, or pass --target"
			}
			return &exitError{
				code: ExitNotFound,
				msg:  fmt.Sprintf("no licence record for root %s — %s", coord, hint),
			}
		case errors.Is(err, licapp.ErrRootLicenceNoSPDX):
			return &exitError{
				code: ExitFailed,
				msg:  fmt.Sprintf("root %s has a licence record but no SPDX identity (proprietary/unclassified roots are valid, just not usable as an implicit target) — pass --target explicitly", coord),
			}
		}
		return fmt.Errorf("checking compatibility: %w", err)
	}

	if jsonOut {
		if err := printCompatReportJSON(report, walkID, walkFrame, stdout); err != nil {
			return err
		}
	} else {
		printCompatReportText(report, coord, walkID, walkFrame, stdout)
	}

	// The caveat is derived from the WALK, not from the conflict rows: a clean
	// verdict is a claim about the whole closure, and a pre-modules module that
	// raised no conflict still contributed none of its own dependencies to the
	// closure the verdict covers.
	if rec, gerr := ctr.QueryWalks.GetWalk(ctx, walkID); gerr == nil {
		if werr := writePreModulesCaveatForSet(stdout, preModulesNodesIn(rec.Graph)); werr != nil {
			return werr
		}
	}

	return compatExitCode(report)
}

func printCompatReportJSON(report domain.ClosureCompatibilityReport, walkID, walkFrame string, stdout io.Writer) error {
	type conflictJSON struct {
		Module  string `json:"module"`
		Version string `json:"version"`
		// DepSPDX is the identifier that was EVALUATED, which is the module's
		// own licence only when spdx_origin is "module_root". Read it together
		// with spdx_origin and module_spdx; on its own it does not say whose
		// licence it is.
		DepSPDX string `json:"dep_spdx"`
		// SPDXOrigin is "module_root" or "bundled_component" and says whose
		// licence dep_spdx is; spdx_origin_path names the component.
		SPDXOrigin     string `json:"spdx_origin"`
		SPDXOriginPath string `json:"spdx_origin_path,omitempty"`
		// ModuleSPDX is the module's OWN licence expression, whole: a
		// conjunction appears in full with dep_spdx naming the arm that raised
		// this entry. This is the field that answers "what is this module
		// licensed under", and it agrees with license, sbom and audit.
		ModuleSPDX string `json:"module_spdx"`
		Target     string `json:"target_spdx"`
		Verdict    string `json:"verdict"`
		Kind       string `json:"kind"`
		// ElectableArms lists the compatible arms of a dual-licence
		// disjunction (verdict "electable"): the module is compatible if one
		// of these is elected via a license_overrides entry.
		ElectableArms []string `json:"electable_arms,omitempty"`
	}
	type coverageHoleJSON struct {
		SPDX    string `json:"spdx"`
		Modules int    `json:"modules"`
		// Deliberate false means the dataset has a gap for this identifier —
		// neither researched nor ruled out. True means it is unmodelled on
		// purpose and reason says why.
		Deliberate bool   `json:"deliberate"`
		Reason     string `json:"reason,omitempty"`
	}
	type reportJSON struct {
		TargetSPDX  string `json:"target_spdx"`
		DataVersion string `json:"data_version"`
		// WalkID and WalkFrame name the walk this verdict was measured over and
		// the GOOS/GOARCH it resolved for ("unrecorded" for a walk written before
		// the frame was projected). Always present: the verdict is about a build,
		// and a build has a platform.
		WalkID    string `json:"walk_id"`
		WalkFrame string `json:"walk_frame"`
		// TargetModelled false means the TARGET identifier is the one the
		// dataset does not model, so every conflict row below follows from that
		// single fact rather than from N independent findings.
		TargetModelled bool           `json:"target_modelled"`
		Clean          bool           `json:"clean"`
		Conflicts      []conflictJSON `json:"conflicts"`
		// CoverageHoles reports each distinct unmodelled identifier in this
		// closure ONCE, with how many modules carry it — the dataset gap, as
		// opposed to its per-module consequences in conflicts.
		CoverageHoles []coverageHoleJSON `json:"coverage_holes"`
	}

	out := reportJSON{
		TargetSPDX:     report.TargetSPDX,
		DataVersion:    report.DataVersion,
		WalkID:         walkID,
		WalkFrame:      walkFrame,
		TargetModelled: report.TargetModelled,
		Clean:          report.Clean,
		Conflicts:      make([]conflictJSON, 0, len(report.Conflicts)),
		CoverageHoles:  make([]coverageHoleJSON, 0, len(report.CoverageHoles)),
	}
	for _, c := range report.Conflicts {
		out.Conflicts = append(out.Conflicts, conflictJSON{
			Module:         c.ModulePath,
			Version:        c.ModuleVersion,
			DepSPDX:        c.DepSPDX,
			SPDXOrigin:     c.Origin.String(),
			SPDXOriginPath: c.OriginPath,
			ModuleSPDX:     c.ModuleExpression,
			Target:         c.TargetSPDX,
			Verdict:        c.Verdict.String(),
			Kind:           c.Kind.String(),
			ElectableArms:  c.ElectableArms,
		})
	}
	for _, h := range report.CoverageHoles {
		out.CoverageHoles = append(out.CoverageHoles, coverageHoleJSON{
			SPDX:       h.SPDX,
			Modules:    h.Modules,
			Deliberate: h.Deliberate,
			Reason:     h.Reason,
		})
	}

	enc := json.NewEncoder(stdout)
	enc.SetIndent("", "  ")
	if err := enc.Encode(out); err != nil {
		return fmt.Errorf("encoding JSON: %w", err)
	}
	return nil
}

// compatOriginLine renders the attribution line printed under every conflict
// row: whose licence the identifier is, and what the module's own licence is.
//
// It is printed even when the two coincide. A reader scanning the column has to
// be able to tell "this IS the module's licence" from "this is something the
// module bundles" without knowing which entries carry the extra line, and an
// origin that appears only sometimes is read as an origin that is sometimes
// unknown.
func compatOriginLine(c domain.CompatibilityConflict) string {
	if c.DepSPDX == "" && c.ModuleExpression == "" {
		// No licence record at all. There is no identifier, so there is nothing
		// to attribute — saying "the module's own licence" here would assert
		// the module has one.
		return "no licence record — there is no identifier to attribute"
	}
	moduleLicence := c.ModuleExpression
	if moduleLicence == "" {
		moduleLicence = "(none detected)"
	}
	if c.Origin == domain.OriginBundledComponent {
		where := c.OriginPath
		if where == "" {
			where = "(path not recorded)"
		}
		return fmt.Sprintf("from bundled component %s — the module's own licence is %s", where, moduleLicence)
	}
	if c.DepSPDX != "" && c.DepSPDX != c.ModuleExpression {
		// A conjunction: the module's licence is reported whole and this row
		// names the arm that raised it.
		return fmt.Sprintf("from the module's own licence %s — arm %s", moduleLicence, c.DepSPDX)
	}
	return "the module's own licence"
}

func writeCompatOrigin(stdout io.Writer, c domain.CompatibilityConflict) {
	_, _ = fmt.Fprintf(stdout, "      %s\n", compatOriginLine(c))
}

// printCompatCoverage reports the dataset's coverage holes for this closure:
// each unmodelled identifier once, with the modules it was seen on and whether
// it is unmodelled by decision or by gap. Printing it separately from the
// per-module rows is the point — one identifier the dataset has never been
// taught is one gap, not one open legal question per module that carries it.
func printCompatCoverage(report domain.ClosureCompatibilityReport, stdout io.Writer) {
	if !report.TargetModelled {
		_, _ = fmt.Fprintf(stdout, "\nThe TARGET licence %s is not in the compatibility dataset (data v%s):\n",
			report.TargetSPDX, report.DataVersion)
		_, _ = fmt.Fprintf(stdout, "every module below is unmodelled for that one reason, not on its own merits.\n")
	}
	if len(report.CoverageHoles) == 0 {
		return
	}
	noun, verb := "identifiers", "are"
	if len(report.CoverageHoles) == 1 {
		noun, verb = "identifier", "is"
	}
	_, _ = fmt.Fprintf(stdout, "\nDataset coverage — %d licence %s in this closure %s not modelled (data v%s):\n",
		len(report.CoverageHoles), noun, verb, report.DataVersion)
	for _, h := range report.CoverageHoles {
		_, _ = fmt.Fprintf(stdout, "  %-24s %d module(s)\n", h.SPDX, h.Modules)
		if h.Deliberate {
			_, _ = fmt.Fprintf(stdout, "      unmodelled by decision: %s\n", h.Reason)
		} else {
			_, _ = fmt.Fprintf(stdout, "      not yet researched — a gap in the dataset, not a property of the licence\n")
		}
	}
}

func printCompatReportText(report domain.ClosureCompatibilityReport, root coordinate.ModuleCoordinate, walkID, walkFrame string, stdout io.Writer) {
	if report.Clean {
		_, _ = fmt.Fprintf(stdout, "%s: closure is compatible with %s (data v%s, walk %s, frame %s)\n",
			root, report.TargetSPDX, report.DataVersion, walkID, walkFrame)
		return
	}

	var incompatible, unknown, electable []domain.CompatibilityConflict
	for _, c := range report.Conflicts {
		switch c.Verdict {
		case domain.VerdictUnknownPair:
			unknown = append(unknown, c)
		case domain.VerdictElectable:
			electable = append(electable, c)
		default:
			incompatible = append(incompatible, c)
		}
	}

	_, _ = fmt.Fprintf(stdout, "%s vs %s (data v%s, walk %s, frame %s):\n",
		root, report.TargetSPDX, report.DataVersion, walkID, walkFrame)

	if len(incompatible) > 0 {
		_, _ = fmt.Fprintf(stdout, "\nIncompatible (%d):\n", len(incompatible))
		for _, c := range incompatible {
			depSPDX := c.DepSPDX
			if depSPDX == "" {
				depSPDX = "(no license)"
			}
			_, _ = fmt.Fprintf(stdout, "  %-55s %s [%s]\n",
				c.ModulePath+"@"+c.ModuleVersion, depSPDX, c.Kind.String())
			writeCompatOrigin(stdout, c)
		}
	}

	if len(electable) > 0 {
		_, _ = fmt.Fprintf(stdout, "\nElectable — dual-licensed, election pending (%d):\n", len(electable))
		for _, c := range electable {
			_, _ = fmt.Fprintf(stdout, "  %-55s %s\n",
				c.ModulePath+"@"+c.ModuleVersion, c.DepSPDX)
			_, _ = fmt.Fprintf(stdout, "  %-55s compatible if %s is elected\n",
				"", strings.Join(c.ElectableArms, " or "))
			writeCompatOrigin(stdout, c)
		}
		_, _ = fmt.Fprintf(stdout, "\nAn election is an operator decision, not the tool's: record the elected\n")
		_, _ = fmt.Fprintf(stdout, "arm as a license_overrides entry for the module, then re-run license-compat.\n")
	}

	if len(unknown) > 0 {
		_, _ = fmt.Fprintf(stdout, "\nRequires review — unmodelled license pair (%d):\n", len(unknown))
		hasNoRecord := false
		for _, c := range unknown {
			depSPDX := c.DepSPDX
			if depSPDX == "" {
				depSPDX = "(no license detected)"
				hasNoRecord = true
			}
			_, _ = fmt.Fprintf(stdout, "  %-55s %s\n",
				c.ModulePath+"@"+c.ModuleVersion, depSPDX)
			writeCompatOrigin(stdout, c)
		}
		// hint so the user knows whether extraction is the next step.
		if hasNoRecord {
			_, _ = fmt.Fprintf(stdout, "\nTip: some deps show no license. Run 'kanonarion extract <walk-id>' to\n")
			_, _ = fmt.Fprintf(stdout, "     populate missing records, then re-run license-compat.\n")
		}
	}

	printCompatCoverage(report, stdout)
}

// compatExitCode returns an exitError for non-clean reports. ExitPartial (1)
// for confirmed incompatible pairs, ExitFailed (2) for unknown pairs and for
// dual-licence elections still pending — both require a human decision and are
// never silently "compatible".
func compatExitCode(report domain.ClosureCompatibilityReport) error {
	if report.Clean {
		return nil
	}
	hasIncompat := false
	hasUnknown := false
	hasElectable := false
	for _, c := range report.Conflicts {
		switch c.Verdict {
		case domain.VerdictIncompatible:
			hasIncompat = true
		case domain.VerdictUnknownPair:
			hasUnknown = true
		case domain.VerdictElectable:
			hasElectable = true
		case domain.VerdictCompatible:
			// Compatible entries never reach the conflict list.
		}
	}
	// Review items take priority: they require human review, which is a
	// stronger signal than a confirmed incompatibility.
	switch {
	case hasUnknown && hasElectable:
		return &exitError{code: ExitFailed, msg: "closure has unmodelled license pairs and pending dual-licence elections requiring review"}
	case hasUnknown:
		return &exitError{code: ExitFailed, msg: "closure has unmodelled license pairs requiring review"}
	case hasElectable:
		return &exitError{code: ExitFailed, msg: "closure has dual-licensed modules whose election is pending — record the elected arm via license_overrides"}
	case hasIncompat:
		return &exitError{code: ExitPartial, msg: "closure has license conflicts"}
	}
	return nil
}
