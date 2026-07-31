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
	Detail     string                             `json:"detail,omitempty"`
	Indicators []provenanceRepublicationIndicator `json:"indicators,omitempty"`
}

// provenanceOutput is the JSON payload of the provenance command. It reuses
// the context section's fork-heuristic shape so consumers see one vocabulary
// across both surfaces.
type provenanceOutput struct {
	Module          string                    `json:"module"`
	Version         string                    `json:"version,omitempty"`
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
a differently-owned module of the same name held in this store. This is the
tier that can see a republication, which the name-path heuristic cannot: a
republication changes the path, so nothing about the new path collides with the
old one.

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
			return runProvenance(cmd.Context(), path, version, ctr.QueryLicense, stdout)
		},
	}
	return cmd
}

func runProvenance(ctx context.Context, path, version string, uc QueryLicenseUseCase, stdout io.Writer) error {
	fp := fetchdomain.InferForkProvenance(path)
	out := provenanceOutput{
		Module:  path,
		Version: version,
		ForkHeuristic: contextForkHeuristic{
			Status:           fp.Status.String(),
			CatalogueVersion: fp.CatalogueVersion,
		},
		CopyrightSignal: copyrightProvenance(ctx, path, version, uc),
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
func copyrightProvenance(ctx context.Context, path, version string, uc QueryLicenseUseCase) provenanceCopyrightSignal {
	if uc == nil {
		return provenanceCopyrightSignal{
			Status: fetchdomain.CopyrightSignalNotAnalysed.String(),
			Detail: "no licence store available to this command",
		}
	}
	// One listing serves both the record lookup and the cross-path rule, so the
	// two read the same generation of the ledger. Two listings could disagree if
	// a scan wrote between them, and the evidence would then quote one and the
	// candidate set come from the other.
	summaries, listErr := uc.ListLicenseRecords(ctx, licports.LicenseFilter{})
	rec, source, ok, detail := latestLicenceRecord(ctx, path, version, uc, summaries, listErr)
	if !ok {
		return provenanceCopyrightSignal{
			Status: fetchdomain.CopyrightSignalNotAnalysed.String(),
			Detail: detail,
		}
	}

	attributions := licenceAttributions(rec)
	if len(attributions) == 0 {
		return provenanceCopyrightSignal{
			Status: fetchdomain.CopyrightSignalNotAnalysed.String(),
			Source: source,
			Detail: fmt.Sprintf("the licence record for %s carries no copyright lines (%s), so there was nothing to compare",
				source, rec.CopyrightStatus.String()),
		}
	}

	indicators := fetchdomain.InferRepublication(path, attributions, storeModulePaths(summaries, listErr))
	out := provenanceCopyrightSignal{Status: fetchdomain.CopyrightSignalNone.String(), Source: source}
	for _, ind := range indicators {
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

// latestLicenceRecord resolves the licence record to read copyright lines off.
// With a version it is the record for that coordinate; without one it is the
// most recently extracted record the store holds for the path, whose coordinate
// is returned so the evidence names the version it came from.
func latestLicenceRecord(ctx context.Context, path, version string, uc QueryLicenseUseCase, summaries []licports.LicenseSummary, listErr error) (licdomain.LicenseRecord, string, bool, string) {
	if version != "" {
		coord, cerr := coordinate.NewModuleCoordinate(path, version)
		if cerr != nil {
			return licdomain.LicenseRecord{}, "", false, fmt.Sprintf("%s@%s is not a module coordinate: %v", path, version, cerr)
		}
		rec, found, gerr := uc.GetLicenseRecord(ctx, coord, licapp.PipelineVersion)
		switch {
		case gerr != nil:
			return licdomain.LicenseRecord{}, "", false, fmt.Sprintf("reading the licence record for %s: %v", coord, gerr)
		case !found:
			return licdomain.LicenseRecord{}, "", false, fmt.Sprintf("no licence record for %s; run: kanonarion license %s", coord, coord)
		}
		return rec, coord.String(), true, ""
	}

	if listErr != nil {
		return licdomain.LicenseRecord{}, "", false, fmt.Sprintf("listing licence records: %v", listErr)
	}
	var best licports.LicenseSummary
	for _, s := range summaries {
		if s.ModulePath != path {
			continue
		}
		if best.ModulePath == "" || s.ExtractedAt.After(best.ExtractedAt) {
			best = s
		}
	}
	if best.ModulePath == "" {
		return licdomain.LicenseRecord{}, "", false, fmt.Sprintf(
			"no licence record for %s at any version; give a version or run: kanonarion license %s@<version>", path, path)
	}
	coord, cerr := coordinate.NewModuleCoordinate(best.ModulePath, best.ModuleVersion)
	if cerr != nil {
		return licdomain.LicenseRecord{}, "", false, fmt.Sprintf("the stored licence summary for %s names no usable coordinate: %v", path, cerr)
	}
	rec, found, gerr := uc.GetLicenseRecord(ctx, coord, licapp.PipelineVersion)
	if gerr != nil || !found {
		return licdomain.LicenseRecord{}, "", false, fmt.Sprintf("reading the licence record for %s: not readable", coord)
	}
	return rec, coord.String(), true, ""
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
