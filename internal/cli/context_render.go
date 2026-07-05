package cli

import (
	"bytes"
	"encoding/json"
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
			l.Status, l.LowConfidenceSPDX, coveragePercent(l.LowConfidenceCoverage))
	}
	return fmt.Sprintf("%s (license file present, could not classify)", l.Status)
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

// printContextSize measures the full JSON representation of out and reports
// estimated token count and byte size. JSON is always used for measurement
// because it represents the full document, not the compact text summary.
func printContextSize(out contextOutput, jsonOut bool, stdout io.Writer) error {
	raw, err := json.MarshalIndent(out, "", "  ")
	if err != nil {
		return fmt.Errorf("encoding context: %w", err)
	}
	byteCount := len(raw) + 1 // +1 for trailing newline
	if jsonOut {
		type sizeResult struct {
			EstimatedTokens int `json:"estimated_tokens"`
			ByteCount       int `json:"byte_count"`
		}
		enc := json.NewEncoder(stdout)
		if err := enc.Encode(sizeResult{EstimatedTokens: byteCount / 4, ByteCount: byteCount}); err != nil {
			return fmt.Errorf("encoding size: %w", err)
		}
		return nil
	}
	if _, err := fmt.Fprintf(stdout, "~%d tokens (%d bytes)\n", byteCount/4, byteCount); err != nil {
		return fmt.Errorf("writing size: %w", err)
	}
	return nil
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
	for _, line := range strings.Split(strings.TrimRight(text, "\n"), "\n") {
		ew.printf("%s%s\n", prefix, line)
	}
}

func printContextText(out contextOutput, compact bool, stdout io.Writer) error {
	data, err := renderContextText(out, compact)
	if err != nil {
		return err
	}
	tokenEst := len(data) / 4
	var hint string
	if compact {
		hint = fmt.Sprintf("\nContext size: ~%d tokens  (use --full for complete docs, --json for machine-readable)\n", tokenEst)
	} else {
		hint = fmt.Sprintf("\nContext size: ~%d tokens  (use --json for machine-readable)\n", tokenEst)
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
		w.printf("  Dependencies:    (not run — run: kanonarion walk %s@%s)\n", out.Module.Path, out.Module.Version)
	case sectionStatusReadError:
		w.printf("  Dependencies:    (failed: %s)\n", out.Dependencies.Error)
	default:
		line := fmt.Sprintf("%d direct (%s)", out.Dependencies.Count, out.Dependencies.Status)
		if out.Dependencies.Partial {
			line += " [partial]"
		}
		w.printf("  Dependencies:    %s\n", line)
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
		w.printf("  License:         %s\n", licenseSummaryLine(out.License))
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
	default:
		total := 0
		for _, p := range out.Interface.Packages {
			total += len(p.Types) + len(p.Funcs) + len(p.Consts) + len(p.Vars)
		}
		w.printf("  Interface:       %d package(s), %d symbol(s) (%s)\n",
			len(out.Interface.Packages), total, out.Interface.Status)
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
			out.CallGraph.NodeCount, out.CallGraph.EdgeCount, out.CallGraph.Status)
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
		w.printf("  Examples:        %d (%s)\n", out.Examples.Count, out.Examples.Status)
	}

	switch out.Vulnerabilities.Status {
	case sectionStatusNotRun:
		if out.Commands.Vulnerabilities != "" {
			w.printf("  Vulnerabilities: (not run — run: %s)\n", out.Commands.Vulnerabilities)
		} else {
			w.printf("  Vulnerabilities: (not run)\n")
		}
	case sectionStatusReadError:
		w.printf("  Vulnerabilities: (failed: %s)\n", out.Vulnerabilities.Error)
	default:
		line := out.Vulnerabilities.Status
		if len(out.Vulnerabilities.Findings) > 0 {
			line += fmt.Sprintf(" (%d finding(s))", len(out.Vulnerabilities.Findings))
		}
		if ann := walkAnnotation(out.Vulnerabilities); ann != "" {
			line += " " + ann
		}
		w.printf("  Vulnerabilities: %s\n", line)
	}

	return w.err
}

// walkAnnotation renders the inline walk-level note appended to a module's
// vulnerability line. When affected peers in the module's transitive closure
// are known, it names them so the reader can act ("affected via x@v"); a long
// list collapses to the first peer plus a count.
//
// Otherwise it surfaces only walk statuses that say something this module's own
// line does not: Partial / ScanFailed warn that the broader scan is incomplete.
// A fully-clean walk (AllClean) adds nothing to a Clean module and an Affected
// walk with no peer in this module's closure is irrelevant to it, so both yield
// no annotation — the walk note appears only when it is actionable here.
func walkAnnotation(v contextVulnerabilities) string {
	switch n := len(v.WalkAffected); {
	case n == 1:
		return fmt.Sprintf("[walk: affected via %s]", v.WalkAffected[0])
	case n > 1:
		return fmt.Sprintf("[walk: affected via %s +%d more]", v.WalkAffected[0], n-1)
	}
	switch vuldomain.WalkScanStatus(v.WalkStatus) {
	case vuldomain.WalkStatusPartial:
		return "[walk coverage: Partial — other modules unscanned]"
	case vuldomain.WalkStatusFailed:
		return "[walk coverage: ScanFailed — other modules failed]"
	}
	return ""
}
