package cli

import (
	"io"
	"sort"
	"strings"
)

func printContextFull(out contextOutput, stdout io.Writer) error {
	w := &errWriter{w: stdout}
	w.printf("%s@%s\n", out.Module.Path, out.Module.Version)
	w.printf("\n=== Verification ===\n")
	printFullVerification(w, out.Verification)
	w.printf("\n=== Provenance ===\n")
	printFullProvenance(w, out.Provenance)
	w.printf("\n=== Dependencies ===\n")
	printFullDependencies(w, out.Dependencies, out.Module.Path+"@"+out.Module.Version)
	w.printf("\n=== License ===\n")
	printFullLicense(w, out.License, out.Commands.License)
	w.printf("\n=== Interface ===\n")
	printFullInterface(w, out.Interface, out.Commands.Interface)
	w.printf("\n=== Call Graph ===\n")
	printFullCallGraph(w, out.CallGraph, out.Commands.CallGraph)
	w.printf("\n=== Examples ===\n")
	printFullExamples(w, out.Examples, out.Commands.Examples)
	w.printf("\n=== Vulnerabilities ===\n")
	printFullVulnerabilities(w, out.Vulnerabilities, out.Commands)
	return w.err
}

func printFullVerification(w *errWriter, v contextVerification) {
	switch v.Status {
	case sectionStatusNotFetched:
		w.printf("(not fetched)\n")
	case sectionStatusReadError:
		w.printf("(failed: %s)\n", v.Error)
	default:
		w.printf("Status:     %s\n", v.Status)
		if v.ExtractedAt != "" {
			w.printf("Fetched At: %s\n", v.ExtractedAt)
		}
		if v.GitURL != "" {
			w.printf("Git URL:    %s\n", v.GitURL)
		}
		if v.Retracted {
			w.printf("RETRACTED\n")
		}
	}
}

func printFullProvenance(w *errWriter, p contextProvenance) {
	fh := p.ForkHeuristic
	switch fh.Status {
	case forkStatusPathMatch, forkStatusNone:
		w.printf("Fork Heuristic: %s (name-path heuristic, catalogue %s)\n", fh.Status, fh.CatalogueVersion)
		for _, ind := range fh.ForkIndicators {
			w.printf("  %s\n", ind.Statement)
		}
	default:
		w.printf("Fork Heuristic: (not analysed)\n")
	}
}

func printFullDependencies(w *errWriter, d contextDependencies, mod string) {
	switch d.Status {
	case sectionStatusNotRun:
		w.printf("(not run — run: kanonarion walk %s)\n", mod)
	case sectionStatusReadError:
		w.printf("(failed: %s)\n", d.Error)
	default:
		w.printf("Status:  %s\n", d.Status)
		if d.WalkID != "" {
			w.printf("Walk ID: %s\n", d.WalkID)
		}
		if d.Partial {
			w.printf("Partial: true (some transitive deps could not be resolved)\n")
		}
		for _, dep := range d.Dependencies {
			w.printf("  %s@%s\n", dep.Path, dep.Version)
		}
		if len(d.Dependencies) == 0 {
			w.printf("(no direct dependencies)\n")
		}
	}
}

func printFullLicense(w *errWriter, l contextLicense, cmd string) {
	switch l.Status {
	case sectionStatusNotRun:
		if cmd != "" {
			w.printf("(not run — run: %s)\n", cmd)
		} else {
			w.printf("(not run)\n")
		}
	case sectionStatusReadError:
		w.printf("(failed: %s)\n", l.Error)
	default:
		if l.SPDX != "" {
			w.printf("SPDX:         %s\n", l.SPDX)
		}
		w.printf("Status:       %s\n", l.Status)
		if l.SPDX == "" && l.LowConfidenceSPDX != "" {
			w.printf("Low-confidence match: %s (~%d%% coverage)\n",
				l.LowConfidenceSPDX, coveragePercent(l.LowConfidenceCoverage))
		}
		if l.ExtractedAt != "" {
			w.printf("Extracted At: %s\n", l.ExtractedAt)
		}
		if l.Error != "" {
			w.printf("Detail:       %s\n", l.Error)
		}
		switch l.CopyrightStatus {
		case "not_analysed", "":
			w.printf("Copyright:    (not analysed)\n")
		case "none_found":
			w.printf("Copyright:    (none found)\n")
		case "extraction_failed":
			w.printf("Copyright:    (extraction failed)\n")
		case "found":
			w.printf("Copyright (%d statements):\n", len(l.CopyrightStatements))
			for _, s := range l.CopyrightStatements {
				w.printf("  %s  [%s]\n", s.Verbatim, s.Source)
			}
		}
	}
}

func printFullInterface(w *errWriter, ifc contextInterface, cmd string) {
	switch ifc.Status {
	case sectionStatusNotRun:
		if cmd != "" {
			w.printf("(not run — run: %s)\n", cmd)
		} else {
			w.printf("(not run)\n")
		}
	case sectionStatusReadError:
		w.printf("(failed: %s)\n", ifc.Error)
	default:
		w.printf("Status:       %s\n", ifc.Status)
		if ifc.ExtractedAt != "" {
			w.printf("Extracted At: %s\n", ifc.ExtractedAt)
		}
		if ifc.Error != "" {
			w.printf("Detail:       %s\n", ifc.Error)
		}
		for _, pkg := range ifc.Packages {
			w.printf("\n  %s\n", pkg.ImportPath)
			for _, t := range pkg.Types {
				w.indented("    ", t)
			}
			for _, fn := range pkg.Funcs {
				w.indented("    ", fn)
			}
			for _, c := range pkg.Consts {
				w.printf("    const %s\n", c)
			}
			for _, v := range pkg.Vars {
				w.printf("    var %s\n", v)
			}
		}
	}
}

func printFullCallGraph(w *errWriter, cg contextCallGraph, cmd string) {
	switch cg.Status {
	case sectionStatusNotRun:
		if cmd != "" {
			w.printf("(not run — run: %s)\n", cmd)
		} else {
			w.printf("(not run)\n")
		}
	case sectionStatusReadError:
		w.printf("(failed: %s)\n", cg.Error)
	default:
		w.printf("Status:       %s\n", cg.Status)
		if cg.ExtractedAt != "" {
			w.printf("Extracted At: %s\n", cg.ExtractedAt)
		}
		w.printf("Algorithm:    %s\n", cg.Algorithm)
		w.printf("Nodes:        %d\n", cg.NodeCount)
		w.printf("Edges:        %d\n", cg.EdgeCount)
		if cg.Error != "" {
			w.printf("Detail:       %s\n", cg.Error)
		}
		if cg.EntryPointCount > 0 {
			w.printf("Entry Points: %d\n", cg.EntryPointCount)
		} else if len(cg.EntryPointsByPackage) > 0 {
			w.printf("Entry Points by Package:\n")
			pkgs := make([]string, 0, len(cg.EntryPointsByPackage))
			for pkg := range cg.EntryPointsByPackage {
				pkgs = append(pkgs, pkg)
			}
			sort.Strings(pkgs)
			for _, pkg := range pkgs {
				w.printf("  %s: %d\n", pkg, cg.EntryPointsByPackage[pkg])
			}
		}
		if len(cg.EntryPoints) > 0 {
			w.printf("Entry Points:\n")
			for _, ep := range cg.EntryPoints {
				w.printf("  %s\n", ep)
			}
		}
	}
}

func printFullExamples(w *errWriter, ex contextExamples, cmd string) {
	switch ex.Status {
	case sectionStatusNotRun:
		if cmd != "" {
			w.printf("(not run — run: %s)\n", cmd)
		} else {
			w.printf("(not run)\n")
		}
	case sectionStatusReadError:
		w.printf("(failed: %s)\n", ex.Error)
	default:
		w.printf("Status:       %s\n", ex.Status)
		if ex.ExtractedAt != "" {
			w.printf("Extracted At: %s\n", ex.ExtractedAt)
		}
		if ex.Error != "" {
			w.printf("Detail:       %s\n", ex.Error)
		}
		for _, e := range ex.Examples {
			printFullExample(w, e)
		}
	}
}

func printFullExample(w *errWriter, e contextExample) {
	w.printf("\n  %s", e.Name)
	if e.Symbol != "" {
		w.printf(" (%s)", e.Symbol)
	}
	w.printf("\n")
	if e.Doc != "" {
		w.indented("    // ", e.Doc)
	}
	w.indented("    ", e.Body)
	if e.Output != "" {
		w.printf("    // Output:\n")
		for _, line := range strings.Split(strings.TrimRight(e.Output, "\n"), "\n") {
			w.printf("    // %s\n", line)
		}
	}
}

func printFullVulnerabilities(w *errWriter, v contextVulnerabilities, cmd contextCommands) {
	switch v.Status {
	case sectionStatusNotRun:
		if cmd.Vulnerabilities != "" {
			w.printf("(not run — run: %s)\n", cmd.Vulnerabilities)
		} else {
			w.printf("(not run)\n")
		}
	case sectionStatusReadError:
		w.printf("(failed: %s)\n", v.Error)
	default:
		w.printf("Status:       %s\n", v.Status)
		if v.WalkStatus != "" {
			w.printf("Walk Status:  %s\n", v.WalkStatus)
		}
		for i, peer := range v.WalkAffected {
			if i == 0 {
				w.printf("Walk Affected (in dependency closure):\n")
			}
			w.printf("  - %s\n", peer)
		}
		if v.Reason != "" {
			w.printf("Reason:       %s\n", v.Reason)
		}
		if v.FirstValidatedAt != "" {
			w.printf("First Validated: %s\n", v.FirstValidatedAt)
		}
		if v.LastValidatedAt != "" {
			w.printf("Last Validated:  %s\n", v.LastValidatedAt)
		} else if v.ExtractedAt != "" {
			w.printf("Scanned At:   %s\n", v.ExtractedAt)
		}
		if v.WalkID != "" {
			w.printf("Walk ID:      %s\n", v.WalkID)
		}
		if v.SnapshotVersion != "" {
			w.printf("Snapshot:     %s\n", v.SnapshotVersion)
		}
		if v.SnapshotRetrievedAt != "" {
			w.printf("Snapshot Age: retrieved %s (%d day(s) old at validation)\n", v.SnapshotRetrievedAt, v.SnapshotAgeDays)
		}
		for _, cve := range v.Findings {
			printFullCVE(w, cve)
		}
	}
}

func printFullCVE(w *errWriter, cve contextCVE) {
	w.printf("\n  %s", cve.ID)
	if len(cve.Aliases) > 0 {
		w.printf(" (%s)", strings.Join(cve.Aliases, ", "))
	}
	w.printf("\n")
	if cve.Summary != "" {
		w.printf("    Summary:   %s\n", cve.Summary)
	}
	if cve.FixedIn != "" {
		w.printf("    Fixed In:  %s\n", cve.FixedIn)
	}
	if cve.Score != 0 {
		w.printf("    Score:     %.1f\n", cve.Score)
	}
	if cve.Reachable != nil {
		w.printf("    Reachable: %v\n", *cve.Reachable)
	}
}
