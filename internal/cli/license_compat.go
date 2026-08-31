package cli

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/eitanity/kanonarion/internal/coordinate"

	"github.com/oklog/ulid/v2"

	licapp "github.com/eitanity/kanonarion/internal/license/application"
	"github.com/eitanity/kanonarion/internal/license/domain"
	walkdomain "github.com/eitanity/kanonarion/internal/walk/domain"
	walkports "github.com/eitanity/kanonarion/internal/walk/ports"
	"github.com/spf13/cobra"
)

// newLicenseCompatCmd returns the license-compat command, which evaluates a
// module's dependency closure against a target distribution license using the
// compatibility engine.
func newLicenseCompatCmd(stdout, stderr io.Writer) *cobra.Command {
	var targetSPDX string
	var walkID string

	cmd := &cobra.Command{
		Use: "license-compat <module>@<version>",
		Annotations: map[string]string{
			annotationStoreIntent: StoreIntentRead,
			annotationNetworkUse:  NetworkNever,
		},
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
  20 bad invocation (unparseable coordinate, wrong argument count, or a
     --walk-id the store does not hold or that is rooted elsewhere)

Without --walk-id the answer comes from the most recent walk of the coordinate
whose recorded resolution still agrees with the go.mod in the directory that
walk was taken from, falling back to the most recent walk when none agrees or
when there is no manifest to compare against. Whenever the store holds more than
one walk of the coordinate, the answer states which walk it used and why.`,
		Example: `  kanonarion license-compat github.com/spf13/cobra@v1.8.1 --target Apache-2.0
  kanonarion license-compat github.com/spf13/cobra@v1.8.1 --target Apache-2.0 --json
  kanonarion license-compat example.com/project@local
  kanonarion license-compat example.com/project@local --walk-id 01KZ42BGN0T95D932JMC1GXX3C`,
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) == 0 {
				return usageErr(cmd)
			}
			if len(args) > 1 {
				return fmt.Errorf("accepts 1 arg, received %d", len(args))
			}
			return runLicenseCompat(cmd.Context(), args[0], targetSPDX, walkID, stdout, stderr)
		},
	}

	cmd.Flags().StringVar(&targetSPDX, "target", "", "target distribution license SPDX id (e.g. Apache-2.0); omitted: use the root's own analysed licence record as the target")
	cmd.Flags().StringVar(&walkID, "walk-id", "", "answer in the frame of this walk instead of the one the default rule picks")

	return cmd
}

func runLicenseCompat(ctx context.Context, arg, targetSPDX, walkID string, stdout, stderr io.Writer) error {
	logger := buildLogger(logLevel, stderr)

	coord, err := parseCoordinate(arg)
	if err != nil {
		// The positional slot takes a coordinate and the walk goes on --walk-id.
		// A caller who typed the walk id positionally asked the right question
		// with the wrong grammar, and "expected module@version" does not tell
		// them that; every sibling command that takes a walk id takes it
		// positionally, so the mistake is the natural one.
		if _, uerr := ulid.ParseStrict(arg); uerr == nil {
			return &exitError{
				code: ExitConfig,
				msg:  fmt.Sprintf("%q is a walk id, and license-compat takes a coordinate here: kanonarion license-compat <module>@<version> --walk-id %s", arg, arg),
			}
		}
		return fmt.Errorf("invalid coordinate %q: %w", arg, err)
	}

	ctr, cleanup, err := NewContainer(storeRoot, "", "", false, activeConfig, logger)
	if err != nil {
		return fmt.Errorf("initialising store: %w", err)
	}
	defer func() { _ = cleanup() }()

	return licenseCompatWith(ctx, ctr, coord, targetSPDX, walkID, stdout, stderr)
}

// licenseCompatWith holds the license-compat logic over an injected Container:
// it resolves the root walk, runs the closure compatibility check, maps the
// intent-aware diagnostics (unanalysed root vs. no-SPDX root) and the
// clean/conflict/unknown verdict to exit codes, and renders the report. Split
// from runLicenseCompat so the exit-code and diagnostic decisions are testable
// without a live store.
func licenseCompatWith(ctx context.Context, ctr *Container, coord coordinate.ModuleCoordinate, targetSPDX, walkID string,
	stdout, stderr io.Writer,
) error {
	// Require an existing walk record for the root module.
	target := coord

	// The frame the verdict was measured in. A licence position is a property of
	// one build: the same project walked at code scope and at complete scope
	// carries different module sets and therefore different conflicts, and GOOS
	// gates which files, and so which modules, a build selects. So the walk is
	// either the one the caller pinned, or one picked here by a stated rule — and
	// the verdict names it either way.
	var choice walkChoice
	var selection selectionJSON
	if walkID != "" {
		rec, err := resolvePinnedWalk(ctx, ctr.QueryWalks, walkID, target)
		if err != nil {
			return err
		}
		choice, selection = pinnedWalkChoice(rec), pinnedSelection()
	} else {
		summaries, err := ctr.QueryWalks.ListWalks(ctx, walkports.WalkFilter{Target: &target})
		if err != nil {
			return fmt.Errorf("listing walks: %w", err)
		}
		if len(summaries) == 0 {
			// The answer travels on the error, once: main prints it, and no
			// fmt.Fprintf here puts a second copy on the data channel.
			return walkTargetMiss(ctx, ctr.QueryWalks, target, stderr)
		}
		choice = chooseWalk(ctx, ctr.QueryWalks, summaries, "")
		selection = choice.selection()
	}
	walkID = choice.summary.ID
	walkFrame := choice.summary.Frame()

	// license_overrides entries are the operator's recorded decisions —
	// corrections and dual-licence elections — and must reach the engine so a
	// recorded election settles the electable verdict. A container wired
	// without the override store (seam tests) carries no decisions.
	var overrides domain.LicenseOverrideSet
	if ctr.LicenseOverrides != nil {
		var oerr error
		overrides, oerr = ctr.LicenseOverrides.LoadOverrides(ctx)
		if oerr != nil {
			return fmt.Errorf("loading license overrides: %w", oerr)
		}
	}

	report, err := ctr.CheckCompatibility.CheckCompatibilityForWalk(ctx, walkID, coord, targetSPDX, overrides)
	if err != nil {
		// Implicit-target resolution failures get intent-aware diagnostics
		// say what is missing and which command produces it.
		switch {
		case errors.Is(err, licapp.ErrRootLicenceNotAnalysed):
			return &exitError{
				code: ExitNotFound,
				msg: fmt.Sprintf("no licence record for root %s — %s, or pass --target",
					coord, missingLicenceRecordRemedy(coord, licenceRemedyBuildForWalk(ctx, ctr, walkID))),
			}
		case errors.Is(err, licapp.ErrRootLicenceNoSPDX):
			return &exitError{
				code: ExitFailed,
				msg:  fmt.Sprintf("root %s has a licence record but no SPDX identity (proprietary/unclassified roots are valid, just not usable as an implicit target) — pass --target explicitly", coord),
			}
		}
		return fmt.Errorf("checking compatibility: %w", err)
	}

	// The caveat is derived from the WALK, not from the conflict rows: a clean
	// verdict is a claim about the whole closure, and a pre-modules module that
	// raised no conflict still contributed none of its own dependencies to the
	// closure the verdict covers.
	var preModules []coordinate.ModuleCoordinate
	if rec, gerr := choice.walkRecord(ctx, ctr.QueryWalks); gerr == nil {
		preModules = preModulesNodesIn(rec.Graph)
	}

	if jsonOut {
		// Under --json the caveat is a FIELD of the document, never a line
		// after it: appended prose breaks every parser, and a consumer that
		// recovers by reading stdout as JSON would lose the one statement that
		// says what the licence answer does not cover.
		if err := printCompatReportJSON(report, walkID, walkFrame, selection, preModulesCaveatFor(preModules...), stdout); err != nil {
			return err
		}
	} else {
		// The statement goes above the report, not after it: it says which of
		// several builds the rows below describe, and a reader who has already
		// read the rows has already decided what they are about.
		if note := choice.statement(); note != "" {
			if _, werr := fmt.Fprint(stdout, note); werr != nil {
				return fmt.Errorf("writing walk selection notice: %w", werr)
			}
		}
		printCompatReportText(report, coord, walkID, walkFrame, stdout)
		if werr := writePreModulesCaveatForSet(stdout, preModules); werr != nil {
			return werr
		}
	}

	return compatExitCode(report)
}

func printCompatReportJSON(report domain.ClosureCompatibilityReport, walkID string, walkFrame walkdomain.WalkFrame, selection selectionJSON, caveat *preModulesCaveatJSON, stdout io.Writer) error {
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
		// LicenseMeasurement is "classified", "unmeasured" (no licence record
		// exists — extraction has not run and can still change this) or
		// "unclassifiable" (a record exists and the shipped files determined no
		// identifier — extraction cannot change it, a recorded human
		// determination can). It is what separates an open measurement from an
		// open question.
		LicenseMeasurement string `json:"license_measurement"`
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
		// the GOOS/GOARCH it resolved for, with WalkFrameBasis the same fact as
		// data: "platform", "not_platform_scoped" for a module-rooted walk (no
		// platform applies), or "unrecorded" (the platform is not known). Always
		// present: a project walk's verdict is about one platform's build, and the
		// fields state which — or state that the walk was not platform-scoped.
		WalkID         string `json:"walk_id"`
		WalkFrame      string `json:"walk_frame"`
		WalkFrameBasis string `json:"walk_frame_basis"`
		// WalkSelection says how walk_id was arrived at: "pinned" when the caller
		// named it, otherwise the rule that picked it and what that rule had to
		// work with. A consumer reading walk_id has to be able to tell an id it
		// asked for from one the tool chose on its behalf.
		WalkSelection selectionJSON `json:"walk_selection"`
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
		// PreModulesCaveat is present only when the closure holds a module
		// resolved under pre-modules semantics, whose own dependencies are
		// therefore ABSENT from this answer rather than measured to be none.
		// It narrows what the verdict covers, so a consumer needs it more than
		// a reader does; absent means no module in the closure is one.
		PreModulesCaveat *preModulesCaveatJSON `json:"pre_modules_caveat,omitempty"`
	}

	out := reportJSON{
		TargetSPDX:       report.TargetSPDX,
		DataVersion:      report.DataVersion,
		WalkID:           walkID,
		WalkFrame:        walkFrame.Text,
		WalkFrameBasis:   string(walkFrame.Basis),
		WalkSelection:    selection,
		TargetModelled:   report.TargetModelled,
		Clean:            report.Clean,
		Conflicts:        make([]conflictJSON, 0, len(report.Conflicts)),
		CoverageHoles:    make([]coverageHoleJSON, 0, len(report.CoverageHoles)),
		PreModulesCaveat: caveat,
	}
	for _, c := range report.Conflicts {
		out.Conflicts = append(out.Conflicts, conflictJSON{
			Module:             c.ModulePath,
			Version:            c.ModuleVersion,
			DepSPDX:            c.DepSPDX,
			SPDXOrigin:         c.Origin.String(),
			SPDXOriginPath:     c.OriginPath,
			ModuleSPDX:         c.ModuleExpression,
			Target:             c.TargetSPDX,
			Verdict:            c.Verdict.String(),
			Kind:               c.Kind.String(),
			ElectableArms:      c.ElectableArms,
			LicenseMeasurement: c.Measurement.String(),
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
		// No identifier, so there is nothing to attribute — saying "the
		// module's own licence" here would assert the module has one. WHY
		// there is none is the operator's next action, so it is said here
		// rather than in a third line under the row.
		if c.Measurement == domain.MeasurementUnclassifiable {
			return "nothing to attribute — the licence record exists and determined no identifier"
		}
		return "nothing to attribute — no licence record exists for this module"
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

func printCompatReportText(report domain.ClosureCompatibilityReport, root coordinate.ModuleCoordinate, walkID string, walkFrame walkdomain.WalkFrame, stdout io.Writer) {
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
		unmeasured, unclassifiable := 0, 0
		for _, c := range unknown {
			depSPDX := c.DepSPDX
			switch {
			case depSPDX != "":
			case c.Measurement == domain.MeasurementUnclassifiable:
				depSPDX = "(licence unclassifiable)"
				unclassifiable++
			default:
				depSPDX = "(no licence record)"
				unmeasured++
			}
			_, _ = fmt.Fprintf(stdout, "  %-55s %s\n",
				c.ModulePath+"@"+c.ModuleVersion, depSPDX)
			writeCompatOrigin(stdout, c)
		}
		// The two states have two different next actions, so each gets its own
		// statement and neither is printed for the other's modules. Each is
		// stated ONCE, here, rather than on every row it applies to: a real
		// closure holds nine of these in a row (corteza), and the same sentence
		// repeated nine times is what a reader skips. The row says which state
		// it is; this says what to do about it.
		if unmeasured > 0 {
			_, _ = fmt.Fprintf(stdout, "\nTip: %d dep(s) have no licence record. Run 'kanonarion extract <walk-id>' to\n", unmeasured)
			_, _ = fmt.Fprintf(stdout, "     populate them, then re-run license-compat.\n")
		}
		if unclassifiable > 0 {
			_, _ = fmt.Fprintf(stdout, "\nNote: %d dep(s) have a licence record whose files determined no identifier.\n", unclassifiable)
			_, _ = fmt.Fprintf(stdout, "      Extraction has already run for these and cannot settle them: record a\n")
			_, _ = fmt.Fprintf(stdout, "      human determination as a license_overrides entry, or carry them as\n")
			_, _ = fmt.Fprintf(stdout, "      accepted open items.\n")
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
	// A report that says it is not clean and whose conflicts carry no verdict
	// this build recognises is not a pass. Same rule as the three above: an
	// unjudged pair is never silently "compatible".
	return &exitError{code: ExitFailed, msg: fmt.Sprintf(
		"closure is not clean and its %d conflict(s) carry no verdict this build recognises",
		len(report.Conflicts))}
}
