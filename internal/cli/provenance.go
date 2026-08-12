package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/spf13/cobra"

	"github.com/eitanity/kanonarion/internal/coordinate"
	fetchdomain "github.com/eitanity/kanonarion/internal/fetch/domain"
	licapp "github.com/eitanity/kanonarion/internal/license/application"
	licdomain "github.com/eitanity/kanonarion/internal/license/domain"
	licports "github.com/eitanity/kanonarion/internal/license/ports"
)

// provenanceRepublicationIndicator is one copyright-tier inference in the JSON
// payload.
type provenanceRepublicationIndicator struct {
	Signal    string   `json:"signal"`
	Holders   []string `json:"holders,omitempty"`
	Evidence  []string `json:"evidence,omitempty"`
	Canonical string   `json:"canonical,omitempty"`
	Statement string   `json:"statement"`
}

// provenanceCopyrightSignal is the copyright-attribution tier's result.
//
// It is a peer of the name-path heuristic, not a sub-field of it. The two are
// blind to different things — the path comparison cannot see a project that
// changed its path, which is what a republication is — so a reader has to know
// which of them ran and what each said.
type provenanceCopyrightSignal struct {
	Status string `json:"status"`
	// Source names the licence record the copyright lines were read off, so the
	// evidence can be checked against a specific record rather than "the store".
	Source string `json:"source,omitempty"`
	// Detail explains a not_analysed status — which is never a negative result.
	Detail string `json:"detail,omitempty"`
	// Coverage states what the signal did not read, so a "no indicators" answer
	// says how thorough the search behind it was. Empty when nothing was missed.
	Coverage   string                             `json:"coverage,omitempty"`
	Indicators []provenanceRepublicationIndicator `json:"indicators,omitempty"`
}

// provenanceOutput is the JSON payload of the provenance command. It reuses
// the context section's fork-heuristic shape so consumers see one vocabulary
// across both surfaces.
type provenanceOutput struct {
	Module  string `json:"module"`
	Version string `json:"version,omitempty"`
	// Selection names the licence record the copyright signal answered from and
	// the rule that picked it.
	Selection       provenanceSelection       `json:"selection"`
	ForkHeuristic   contextForkHeuristic      `json:"fork_heuristic"`
	CopyrightSignal provenanceCopyrightSignal `json:"copyright_signal"`
}

func newProvenanceCmd(stdout, stderr io.Writer) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "provenance <module[@version]>",
		Short: "Show fork/republication provenance facts for a module (name-path heuristic + licence copyright lines)",
		Long: `Run two independent provenance signals over a module.

Name-path heuristic: when the path shares its trailing name element with a
catalogued canonical module under a different owner or host, report a caveated
fork inference. It is a pure function of the path.

Copyright-attribution signal: read the module's stored licence record and
report a caveated republication inference when the licence text attributes
copyright to more than one distinct holder, or when a holder names the owner of
a related module — one of the same name held in this store, or the module this
one replaces under a go.mod replace directive recorded in a walk. This is the
tier that can see a republication, which the name-path heuristic cannot: a
republication changes the path, so nothing about the new path collides with the
old one.

Without @version the copyright signal reads the record for the NEWEST version
the store holds, and where it holds several the output says a choice was made
and how to pin one. Where the versions disagree about the signal, the
disagreement is reported rather than resolved by picking.

Both results are inferences, never verdicts — "path suggests a fork of
<canonical> — verify". Confirming or refuting one requires comparing the
module's VCS origin or content with the canonical's.

A module with no stored licence record reports the copyright signal as
not_analysed, never as "no indicators": a signal that did not run has found
nothing to report either way.`,
		Example: `  kanonarion provenance github.com/someuser/cobra
  kanonarion provenance github.com/golang-jwt/jwt/v4@v4.5.1 --json`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			path, version, _ := strings.Cut(args[0], "@")
			if path == "" {
				return usageErr(cmd)
			}
			logger := buildLogger(logLevel, stderr)
			ctr, cleanup, err := NewContainer(storeRoot, "", "", false, activeConfig, logger)
			if err != nil {
				return fmt.Errorf("initialising store: %w", err)
			}
			defer func() { _ = cleanup() }()
			return runProvenance(cmd.Context(), path, version, ctr.QueryLicense, ctr.QueryWalks, stdout)
		},
	}
	return cmd
}

func runProvenance(ctx context.Context, path, version string, uc QueryLicenseUseCase, walks QueryWalksUseCase, stdout io.Writer) error {
	fp := fetchdomain.InferForkProvenance(path)
	signal, selection := copyrightProvenance(ctx, path, version, uc, walks)
	out := provenanceOutput{
		Module:  path,
		Version: version,
		ForkHeuristic: contextForkHeuristic{
			Status:           fp.Status.String(),
			CatalogueVersion: fp.CatalogueVersion,
		},
		Selection:       selection,
		CopyrightSignal: signal,
	}
	for _, ind := range fp.Indicators {
		out.ForkHeuristic.ForkIndicators = append(out.ForkHeuristic.ForkIndicators, contextForkIndicator{
			Canonical: ind.Canonical,
			Statement: ind.Statement,
		})
	}

	if jsonOut {
		raw, err := json.MarshalIndent(out, "", "  ")
		if err != nil {
			return fmt.Errorf("encoding provenance: %w", err)
		}
		if _, err := fmt.Fprintf(stdout, "%s\n", raw); err != nil {
			return fmt.Errorf("writing provenance: %w", err)
		}
		return nil
	}

	w := &errWriter{w: stdout}
	// The notice goes above the answer, not after it: it says which of several
	// versions the lines below describe, and a reader who has already read them
	// has already decided what they were about.
	if out.Selection.Statement != "" {
		w.printf("%s", out.Selection.Statement)
	}
	header := out.Module
	if out.Version != "" {
		header += "@" + out.Version
	}
	w.printf("%s\n", header)
	switch out.ForkHeuristic.Status {
	case forkStatusPathMatch:
		w.printf("  Fork Heuristic:    %s (name-path, catalogue %s)\n", out.ForkHeuristic.Status, out.ForkHeuristic.CatalogueVersion)
		for _, ind := range out.ForkHeuristic.ForkIndicators {
			w.printf("    %s\n", ind.Statement)
		}
	default:
		w.printf("  Fork Heuristic:    no indicators (name-path, catalogue %s)\n", out.ForkHeuristic.CatalogueVersion)
	}
	printCopyrightSignal(w, out.CopyrightSignal)
	if w.err != nil {
		return fmt.Errorf("writing provenance: %w", w.err)
	}
	return nil
}

// printCopyrightSignal renders the copyright tier, keeping "did not run" and
// "ran and found nothing" visibly apart. Undifferentiated silence over both is
// what let a republication carrying two copyright holders read as a clean
// module.
func printCopyrightSignal(w *errWriter, cs provenanceCopyrightSignal) {
	switch cs.Status {
	case fetchdomain.CopyrightSignalRepublication.String():
		w.printf("  Copyright Signal:  %s (licence record %s)\n", cs.Status, cs.Source)
		for _, ind := range cs.Indicators {
			w.printf("    %s\n", ind.Statement)
			for _, e := range ind.Evidence {
				w.printf("      evidence: %s\n", e)
			}
		}
	case fetchdomain.CopyrightSignalNone.String():
		w.printf("  Copyright Signal:  no indicators (licence copyright lines, record %s)\n", cs.Source)
		if cs.Coverage != "" {
			w.printf("    not covered: %s\n", cs.Coverage)
		}
	default:
		w.printf("  Copyright Signal:  not analysed — %s\n", cs.Detail)
	}
}

// copyrightProvenance reads the module's stored licence record and runs the
// copyright-attribution tier over its copyright lines.
//
// Every failure to read lands on not_analysed with the reason stated. None of
// them is evidence about the module, and reporting a store that could not be
// read as a module with no indicators would be the tier asserting a negative it
// never measured.
func copyrightProvenance(ctx context.Context, path, version string, uc QueryLicenseUseCase, walks QueryWalksUseCase,
) (provenanceCopyrightSignal, provenanceSelection) {
	if uc == nil {
		return provenanceCopyrightSignal{
			Status: fetchdomain.CopyrightSignalNotAnalysed.String(),
			Detail: "no licence store available to this command",
		}, provenanceSelection{}
	}
	// One listing serves both the record lookup and the cross-path rule, so the
	// two read the same generation of the ledger. Two listings could disagree if
	// a scan wrote between them, and the evidence would then quote one and the
	// candidate set come from the other.
	summaries, listErr := uc.ListLicenseRecords(ctx, licports.LicenseFilter{})
	replaced, coverage := replacedModulePaths(ctx, walks, path)
	related := append(
		fetchdomain.LedgerModules(storeModulePaths(summaries, listErr)),
		fetchdomain.ReplacedModules(replaced)...)

	basis, ok, detail := resolveLicenceBasis(ctx, path, version, uc, summaries, listErr)
	if !ok {
		return provenanceCopyrightSignal{
			Status:   fetchdomain.CopyrightSignalNotAnalysed.String(),
			Detail:   detail,
			Coverage: coverage,
		}, provenanceSelection{}
	}

	signal := copyrightSignalFor(path, basis.rec, related)
	signal.Source = basis.coord.String()
	if signal.Status == fetchdomain.CopyrightSignalNotAnalysed.String() {
		signal.Detail = fmt.Sprintf("the licence record for %s %s", signal.Source, signal.Detail)
	}
	signal.Coverage = coverage
	return signal, provenanceSelectionFor(ctx, path, basis, uc, related)
}

// copyrightSignalFor runs the tier over one record's copyright lines. The
// caller names the record; this decides only what the lines say.
func copyrightSignalFor(path string, rec licdomain.LicenseRecord, related []fetchdomain.RelatedModule) provenanceCopyrightSignal {
	attributions := licenceAttributions(rec)
	if len(attributions) == 0 {
		return provenanceCopyrightSignal{
			Status: fetchdomain.CopyrightSignalNotAnalysed.String(),
			Detail: fmt.Sprintf("carries no copyright lines (%s), so there was nothing to compare",
				rec.CopyrightStatus.String()),
		}
	}
	out := provenanceCopyrightSignal{Status: fetchdomain.CopyrightSignalNone.String()}
	for _, ind := range fetchdomain.InferRepublication(path, attributions, related) {
		out.Status = fetchdomain.CopyrightSignalRepublication.String()
		out.Indicators = append(out.Indicators, provenanceRepublicationIndicator{
			Signal:    ind.Signal.String(),
			Holders:   ind.Holders,
			Evidence:  ind.Evidence,
			Canonical: ind.Canonical,
			Statement: ind.Statement,
		})
	}
	return out
}

// provenanceSelectionFor describes the choice of basis, and — where the store
// holds several versions — whether their records agree about it.
//
// The other versions are read only when the caller pinned none and there is more
// than one, which is the only case where anything was chosen. Where they
// disagree, the disagreement IS the answer to a module-level question: one
// version's republication signal is not a fact about the module, and resolving
// it by picking a version would hide that the module has two answers.
func provenanceSelectionFor(
	ctx context.Context,
	path string,
	basis licenceBasis,
	uc QueryLicenseUseCase,
	related []fetchdomain.RelatedModule,
) provenanceSelection {
	sel := provenanceSelection{Rule: provenanceSelectionNewest, Basis: basis.coord.String(), Candidates: basis.candidates}
	if basis.pinned {
		sel.Rule, sel.Candidates = provenanceSelectionPinned, nil
		return sel
	}
	if len(basis.candidates) > 1 {
		sel.Disagreement = copyrightSignalDisagreement(ctx, path, basis, uc, related)
	}
	sel.Statement = sel.statement(path)
	return sel
}

// copyrightSignalDisagreement returns one "version status" entry per candidate
// when the candidates do not all report the same copyright signal, and nothing
// when they agree or when a candidate could not be read — an unread record is
// not a disagreeing one.
//
// Only the versions that produced a signal are compared. A record carrying no
// copyright lines measured nothing, and counting its silence as the opposite
// answer would raise a disagreement out of two versions that never disagreed —
// the same conflation between "did not run" and "ran and found nothing" the tier
// exists to keep apart. Once a real disagreement is found every candidate is
// listed, including those, because a reader deciding which version to pin needs
// to know which ones have nothing to say.
func copyrightSignalDisagreement(
	ctx context.Context,
	path string,
	basis licenceBasis,
	uc QueryLicenseUseCase,
	related []fetchdomain.RelatedModule,
) []string {
	entries := make([]string, 0, len(basis.candidates))
	measured := make(map[string]struct{}, len(basis.candidates))
	for _, v := range basis.candidates {
		coord, cerr := coordinate.NewModuleCoordinate(path, v)
		if cerr != nil {
			return nil
		}
		rec, found, gerr := uc.GetLicenseRecord(ctx, coord, licapp.PipelineVersion)
		if gerr != nil || !found {
			return nil
		}
		status := copyrightSignalFor(path, rec, related).Status
		if status != fetchdomain.CopyrightSignalNotAnalysed.String() {
			measured[status] = struct{}{}
		}
		entries = append(entries, fmt.Sprintf("%s %s", v, status))
	}
	if len(measured) <= 1 {
		return nil
	}
	return entries
}

// licenceAttributions projects a licence record's copyright statements onto the
// plain-string shape the inference takes. Vendored licence files are excluded:
// a vendored dependency's copyright line says nothing about who wrote this
// module.
func licenceAttributions(rec licdomain.LicenseRecord) []fetchdomain.CopyrightAttribution {
	var out []fetchdomain.CopyrightAttribution
	for _, f := range rec.LicenseFiles {
		if f.IsVendored {
			continue
		}
		for _, stmt := range f.CopyrightStatements {
			holder := ""
			if len(stmt.Holders) > 0 {
				holder = stmt.Holders[0]
			}
			out = append(out, fetchdomain.CopyrightAttribution{Holder: holder, Verbatim: stmt.Verbatim})
		}
	}
	return out
}

// storeModulePaths returns the distinct module paths the licence ledger holds,
// for the holder-matches-path rule. A listing failure yields none, which
// disables that rule and leaves the multiple-holders rule to answer — the tier
// degrades rather than claiming a negative it could not check.
func storeModulePaths(summaries []licports.LicenseSummary, err error) []string {
	if err != nil {
		return nil
	}
	seen := make(map[string]struct{}, len(summaries))
	out := make([]string, 0, len(summaries))
	for _, s := range summaries {
		if s.ModulePath == "" {
			continue
		}
		if _, ok := seen[s.ModulePath]; ok {
			continue
		}
		seen[s.ModulePath] = struct{}{}
		out = append(out, s.ModulePath)
	}
	sort.Strings(out)
	return out
}
