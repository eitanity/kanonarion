package cli

import (
	"bytes"
	"fmt"
	"io"
	"strings"

	licdomain "github.com/eitanity/kanonarion/internal/license/domain"
	vuldomain "github.com/eitanity/kanonarion/internal/vuln/domain"
)

// licenseSummaryLine renders the one-line licence summary for the context /
// inspect overview. It never returns an empty string: an Unclassified root
// (a licence file present but unmatched) is shown as the status word — with a
// low-confidence fragment caveat when one was recognised — so absence of
// classification is never displayed as absence of a licence.
func licenseSummaryLine(l contextLicense) string {
	if l.SPDX != "" {
		return l.SPDX
	}
	if l.Status == licdomain.LicenseStatusNone.String() {
		return "None (no license file found)"
	}
	if l.LowConfidenceSPDX != "" {
		return fmt.Sprintf("%s — license file present; low-confidence %s match (~%d%% coverage)",
			l.Status, l.LowConfidenceSPDX, coveragePercent(lowConfidenceCoverageOf(l)))
	}
	return fmt.Sprintf("%s (license file present, could not classify)", l.Status)
}

// lowConfidenceCoverageOf reads the coverage of a sub-threshold licence match,
// which is absent whenever no such match was found. The text form prints it
// only under a non-empty LowConfidenceSPDX, so the fallback is never reached in
// practice and is here so a nil can never panic a renderer.
func lowConfidenceCoverageOf(l contextLicense) float64 {
	if l.LowConfidenceCoverage == nil {
		return 0
	}
	return *l.LowConfidenceCoverage
}

// coveragePercent converts a 0.0–1.0 coverage fraction to a whole-number
// percentage, rounding to the nearest point but never down to zero when a
// non-zero fragment matched (so a 0.4% match reads "~1%", not "~0%").
func coveragePercent(frac float64) int {
	pct := int(frac*100 + 0.5)
	if pct == 0 && frac > 0 {
		pct = 1
	}
	return pct
}

// statusWithReason renders a section's status word together with the reason the
// record recorded for it, in the "(status: detail)" shape the read-error
// branches already print as "(failed: %s)".
//
// Without it a section printed the status word alone while the reason sat in the
// same struct, reachable only under --json: the same two words were printed for
// a module whose analysis environment was unusable and for one with a genuine
// fault of its own, and the text output could not tell a measurement that never
// happened from a finding about the module. Text and --json now carry the same
// facts.
//
// A record that recorded no detail renders the bare status word. That is the
// true value for it — records written before a stage recorded its reason state
// nothing, and there is no reason here to invent one from.
func statusWithReason(status, detail string) string {
	if detail == "" {
		return status
	}
	return status + ": " + collapseLines(detail)
}

// collapseLines folds a multi-line detail onto a single line so a summary
// section keeps its one-row-per-section shape. The detail is never truncated:
// it is the fact the row exists to carry, and a cut one could hide the clause
// that distinguishes an environment failure from a module fault.
func collapseLines(s string) string {
	return strings.Join(strings.Fields(s), " ")
}

func renderContextText(out contextOutput, compact bool) ([]byte, error) {
	var buf bytes.Buffer
	if compact {
		if err := printContextSummary(out, &buf); err != nil {
			return nil, err
		}
	} else {
		if err := printContextFull(out, &buf); err != nil {
			return nil, err
		}
	}
	return buf.Bytes(), nil
}

// errWriter accumulates the first write error so callers avoid repetitive
// error checks on every fmt.Fprintf call.
type errWriter struct {
	w   io.Writer
	err error
}

func (ew *errWriter) printf(format string, args ...any) {
	if ew.err != nil {
		return
	}
	_, ew.err = fmt.Fprintf(ew.w, format, args...)
}

// indented writes text with prefix prepended to every line, preserving
// multi-line content such as type signatures and example bodies.
func (ew *errWriter) indented(prefix, text string) {
	for line := range strings.SplitSeq(strings.TrimRight(text, "\n"), "\n") {
		ew.printf("%s%s\n", prefix, line)
	}
}

// printContextText renders the module's text block and closes it with the
// context-size hint.
//
// The hint measures the module's full JSON document, not the block above it:
// that is what --size-only reports for the same module under the same flags, and
// what a caller deciding whether to pull the context is budgeting against. The
// text block is a digest of that document, four orders of magnitude smaller for
// a large module, so reporting its length under the words "context size" gave a
// number that barely moved between modules and answered a question nobody asked.
// The line therefore names what it is a size of.
func printContextText(out contextOutput, compact bool, stdout io.Writer) error {
	data, err := renderContextText(out, compact)
	if err != nil {
		return err
	}
	byteCount, err := jsonDocumentBytes(out)
	if err != nil {
		return err
	}
	tokenEst := byteCount / 4
	var hint string
	if compact {
		hint = fmt.Sprintf("\nContext size: ~%d tokens (%d bytes) of JSON for this module  (use --full for complete docs, --json for machine-readable)\n", tokenEst, byteCount)
	} else {
		hint = fmt.Sprintf("\nContext size: ~%d tokens (%d bytes) of JSON for this module  (use --json for machine-readable)\n", tokenEst, byteCount)
	}
	if _, err = fmt.Fprint(stdout, string(data)+hint); err != nil {
		return fmt.Errorf("writing context: %w", err)
	}
	return nil
}

func printContextSummary(out contextOutput, stdout io.Writer) error {
	w := &errWriter{w: stdout}

	w.printf("%s@%s\n", out.Module.Path, out.Module.Version)

	switch out.Verification.Status {
	case sectionStatusNotFetched:
		w.printf("  Verification:    (not fetched)\n")
	case sectionStatusReadError:
		w.printf("  Verification:    (failed: %s)\n", out.Verification.Error)
	default:
		v := out.Verification
		line := v.Status
		if v.GitURL != "" {
			line += " (git: " + v.GitURL + ")"
		}
		if v.Retracted {
			line += " [RETRACTED]"
		}
		w.printf("  Verification:    %s\n", line)
	}

	switch out.Provenance.ForkHeuristic.Status {
	case forkStatusPathMatch:
		for _, ind := range out.Provenance.ForkHeuristic.ForkIndicators {
			w.printf("  Provenance:      %s\n", ind.Statement)
		}
	case forkStatusNone:
		w.printf("  Provenance:      no fork indicators (name-path heuristic, catalogue %s)\n",
			out.Provenance.ForkHeuristic.CatalogueVersion)
	default:
		w.printf("  Provenance:      (not analysed)\n")
	}

	switch out.Dependencies.Status {
	case sectionStatusNotRun:
		w.printf("  Dependencies:    (not run — run: %s)\n",
			walkInvocationForRendered(out.Module.Path+"@"+out.Module.Version))
	case sectionStatusReadError:
		w.printf("  Dependencies:    (failed: %s)\n", out.Dependencies.Error)
	default:
		line := fmt.Sprintf("%d direct (%s)", out.Dependencies.Count, out.Dependencies.Status)
		if out.Dependencies.Partial {
			line += " [partial]"
		}
		w.printf("  Dependencies:    %s\n", line)
		printPreModulesCaveat(w, out.Dependencies.PreModulesCaveat)
	}

	switch out.License.Status {
	case sectionStatusNotRun:
		if out.Commands.License != "" {
			w.printf("  License:         (not run — run: %s)\n", out.Commands.License)
		} else {
			w.printf("  License:         (not run)\n")
		}
	case sectionStatusReadError:
		w.printf("  License:         (failed: %s)\n", out.License.Error)
	default:
		line := licenseSummaryLine(out.License)
		if out.License.Error != "" {
			// The licence summary line carries no status word of its own when a
			// SPDX identifier was matched, so the recorded reason is appended as
			// its own clause rather than folded into one that may not be printed.
			line += " (" + statusWithReason(out.License.Status, out.License.Error) + ")"
		}
		w.printf("  License:         %s\n", line)
	}

	switch out.Interface.Status {
	case sectionStatusNotRun:
		if out.Commands.Interface != "" {
			w.printf("  Interface:       (not run — run: %s)\n", out.Commands.Interface)
		} else {
			w.printf("  Interface:       (not run)\n")
		}
	case sectionStatusReadError:
		w.printf("  Interface:       (failed: %s)\n", out.Interface.Error)
	case sectionStatusSuperseded:
		w.printf("  Interface:       (superseded — %s)\n", out.Interface.Error)
	default:
		total := 0
		for _, p := range out.Interface.Packages {
			total += len(p.Types) + len(p.Methods) + len(p.Funcs) + len(p.Consts) + len(p.Vars)
		}
		w.printf("  Interface:       %d package(s), %d symbol(s) (%s)\n",
			len(out.Interface.Packages), total,
			statusWithReason(out.Interface.Status, out.Interface.Error))
	}

	switch out.CallGraph.Status {
	case sectionStatusNotRun:
		if out.Commands.CallGraph != "" {
			w.printf("  Call Graph:      (not run — run: %s)\n", out.Commands.CallGraph)
		} else {
			w.printf("  Call Graph:      (not run)\n")
		}
	case sectionStatusReadError:
		w.printf("  Call Graph:      (failed: %s)\n", out.CallGraph.Error)
	default:
		w.printf("  Call Graph:      %d nodes, %d edges (%s)\n",
			out.CallGraph.NodeCount, out.CallGraph.EdgeCount,
			statusWithReason(out.CallGraph.Status, out.CallGraph.Error))
	}

	switch out.Examples.Status {
	case sectionStatusNotRun:
		if out.Commands.Examples != "" {
			w.printf("  Examples:        (not run — run: %s)\n", out.Commands.Examples)
		} else {
			w.printf("  Examples:        (not run)\n")
		}
	case sectionStatusReadError:
		w.printf("  Examples:        (failed: %s)\n", out.Examples.Error)
	default:
		w.printf("  Examples:        %d (%s)\n", out.Examples.Count,
			statusWithReason(out.Examples.Status, out.Examples.Error))
	}

	printVulnerabilitiesSummary(w, out)

	return w.err
}

// printVulnerabilitiesSummary is the vulnerabilities line of the summary, split
// out because the section has four states and the summary as a whole has a
// complexity ceiling.
func printVulnerabilitiesSummary(w *errWriter, out contextOutput) {
	switch out.Vulnerabilities.Status {
	case sectionStatusSuperseded:
		w.printf("  Vulnerabilities: (superseded — %s)\n", out.Vulnerabilities.Error)
	case sectionStatusNotRun:
		if out.Commands.Vulnerabilities != "" {
			w.printf("  Vulnerabilities: (not run — run: %s)\n", out.Commands.Vulnerabilities)
		} else {
			w.printf("  Vulnerabilities: (not run)\n")
		}
	case sectionStatusReadError:
		w.printf("  Vulnerabilities: (failed: %s)\n", out.Vulnerabilities.Error)
	default:
		line := out.Vulnerabilities.Status + contextFindingCount(out.Vulnerabilities.Findings)
		if ann := walkAnnotation(out.Vulnerabilities); ann != "" {
			line += " " + ann
		}
		w.printf("  Vulnerabilities: %s\n", line)
		printWalkBasis(w, "  Walk basis:      %s\n", out.Vulnerabilities)
		printScanProvenance(w, out.Vulnerabilities)
	}
}

// printScanProvenance names the advisory snapshot and the vuln-scan pipeline
// behind the verdict on the line beneath it. A verdict is only meaningful
// relative to the database and the analysis that produced it — "Clean" against
// a stale snapshot, or from a pipeline that reported no source findings, is a
// different claim from "Clean" today. Each fact is printed only when present,
// so a scan that recorded neither stays silent rather than showing empty
// fields.
func printScanProvenance(w *errWriter, v contextVulnerabilities) {
	switch {
	case v.SnapshotVersion != "" && v.PipelineVersion != "":
		w.printf("  Snapshot:        %s (pipeline %s)\n", v.SnapshotVersion, v.PipelineVersion)
	case v.SnapshotVersion != "":
		w.printf("  Snapshot:        %s\n", v.SnapshotVersion)
	case v.PipelineVersion != "":
		w.printf("  Pipeline:        %s\n", v.PipelineVersion)
	}
}

// printWalkBasis names the walk an unanchored answer was read from. The verdict
// and the walk annotation above it hold in that build; another walk in the
// window may answer differently, so the one that answered is named rather than
// left for the reader to assume. Silent when the caller anchored the read, which
// states its own build.
//
// The frame is stated when the walk record could be read and its absence is said
// in words, because a missing frame is a gap in what is known about the answer,
// not a property of the answer.
func printWalkBasis(w *errWriter, format string, v contextVulnerabilities) {
	if v.WalkWindowNote != "" {
		// Printed even without a basis id: the note is precisely the case where
		// the run context is missing, and a reader has to be able to tell a
		// bounded read from a scan that found nothing to say.
		w.printf(format, v.WalkWindowNote)
	}
	if v.WalkBasisID == "" {
		return
	}
	if v.WalkBasisFrame == "" {
		w.printf(format, fmt.Sprintf("%s (frame unknown — the walk record is not in the store)", v.WalkBasisID))
		return
	}
	w.printf(format, fmt.Sprintf("%s (frame %s)", v.WalkBasisID, v.WalkBasisFrame))
}

// walkAnnotation renders the inline walk-level note appended to a module's
// vulnerability line. It carries two independent axes and prints each when it
// says something this module's own line does not, together when both do:
//
//   - findings: affected peers in the module's transitive closure are named so
//     the reader can act ("affected via x@v"); a long list collapses to the
//     first peer plus a count.
//   - coverage: a Partial / Failed walk warns that the broader scan is
//     incomplete.
//
// The two answer different questions, so neither suppresses the other — a Partial
// run that also carries an affected peer prints both. A run with no affected peer
// in this module's closure and complete coverage yields no annotation.
// contextFindingCount renders the parenthesised tally beside a module's
// vulnerability status, counting retracted advisories apart from live ones.
//
// A single "N finding(s)" could not distinguish them, so a module whose only
// advisory had been withdrawn read identically to one carrying a live finding —
// the status word said Withdrawn while the count beside it still asserted a
// finding. A mixture states both numbers, because the live one is what the reader
// must act on and the retracted one is what explains the rest of the entry.
func contextFindingCount(findings []contextCVE) string {
	if len(findings) == 0 {
		return ""
	}
	withdrawn := 0
	for _, f := range findings {
		if f.WithdrawnAt != "" {
			withdrawn++
		}
	}
	switch live := len(findings) - withdrawn; {
	case withdrawn == 0:
		return fmt.Sprintf(" (%d finding(s))", live)
	case live == 0:
		// No "finding(s)" word at all when every advisory was retracted: the status
		// word beside this tally says Withdrawn, and a count of findings there
		// contradicts it.
		return fmt.Sprintf(" (%d retracted)", withdrawn)
	default:
		return fmt.Sprintf(" (%d finding(s), %d retracted)", live, withdrawn)
	}
}

func walkAnnotation(v contextVulnerabilities) string {
	var parts []string
	switch n := len(v.WalkAffected); {
	case n == 1:
		parts = append(parts, fmt.Sprintf("[walk: affected via %s]", v.WalkAffected[0]))
	case n > 1:
		parts = append(parts, fmt.Sprintf("[walk: affected via %s +%d more]", v.WalkAffected[0], n-1))
	}
	switch vuldomain.CoverageStatus(v.WalkCoverage) {
	case vuldomain.CoveragePartial:
		parts = append(parts, "[walk coverage: Partial — other modules unscanned]")
	case vuldomain.CoverageFailed:
		parts = append(parts, "[walk coverage: Failed — other modules failed]")
	}
	if v.WalkError != "" {
		// A peer verdict could not be read: state the uncertainty rather than
		// implying the affected-peer set is complete.
		parts = append(parts, "[walk: affected-peer status unavailable]")
	}
	return strings.Join(parts, " ")
}
