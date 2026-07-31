package cli

import (
	"path/filepath"
	"strings"

	"github.com/eitanity/kanonarion/internal/coordinate"
)

// reachabilityRemedy is the command-line half of a reachability refusal: the
// lead sentence, and the invocations that carry it out.
//
// The invocations are held apart from the prose because they are a contract,
// not decoration. A refusal that prints a command the tool then rejects costs
// the caller exactly the round trip the refusal existed to save, and every
// remedy in this file used to do that: they printed
// "kanonarion vuln-scan <module>@<version> --reachability", and vuln-scan takes
// a walk id positionally, never a coordinate, so following the advice verbatim
// failed with "walk record not found". Keeping the lines as data is what lets a
// contract test push every one of them through the CLI's own argument parser.
type reachabilityRemedy struct {
	// lead introduces the invocations. It ends without punctuation of its own;
	// String supplies the colon.
	lead string
	// lines are whole invocations, "kanonarion" included, each parseable on its
	// own. Prose never appears here — an annotation inside a line would be
	// indistinguishable from an argument to the parser and to the reader.
	lines []string
}

// String renders the remedy as the tail of a refusal message: the lead, then one
// indented invocation per line.
func (r reachabilityRemedy) String() string {
	var b strings.Builder
	b.WriteString(r.lead)
	b.WriteString(":")
	for _, l := range r.lines {
		b.WriteString("\n  ")
		b.WriteString(l)
	}
	return b.String()
}

// remedyScanModule is the remedy for a coordinate the store holds no usable
// reachability answer for and has no walk of: walk it, then scan that walk.
//
// The scan step names the walk through --module rather than passing the
// coordinate positionally. vuln-scan's positional argument is a walk id; the
// flag is the form that takes a coordinate, and it resolves the walk the first
// line just produced.
func remedyScanModule(coord coordinate.ModuleCoordinate) reachabilityRemedy {
	return reachabilityRemedy{
		lead: "Run",
		lines: []string{
			"kanonarion walk " + coord.String(),
			"kanonarion vuln-scan --module " + coord.String() + " --reachability",
		},
	}
}

// remedyRescanModule is the remedy for a coordinate whose scan failed. No
// --force: a ScanFailed record is never served from the scan cache, so the
// re-run measures rather than replaying the failure.
func remedyRescanModule(coord coordinate.ModuleCoordinate) reachabilityRemedy {
	return reachabilityRemedy{
		lead: "Re-run",
		lines: []string{
			"kanonarion vuln-scan --module " + coord.String() + " --reachability",
		},
	}
}

// remedyRebuildGraphThenRescan is the remedy for a coordinate that HAS a usable
// scan whose reachability leg could not see a call graph. --force is on the scan
// because a stored answer for this coordinate already exists: without it the run
// may be served from cache and report the same undetermined answer, which reads
// as the remedy having been tried and failed.
func remedyRebuildGraphThenRescan(coord coordinate.ModuleCoordinate) reachabilityRemedy {
	return reachabilityRemedy{
		lead: "Run",
		lines: []string{
			"kanonarion callgraph " + coord.String(),
			"kanonarion vuln-scan --module " + coord.String() + " --reachability --force",
		},
	}
}

// remedyProjectRooted is the remedy for a module whose newest scan was rooted at
// the module itself.
//
// Re-scanning that module cannot help however it is invoked: rooted at itself it
// is the analysis's own main module, so there is no consumer above it for a
// route to start from. Only a scan rooted at the consumer can produce one, so
// every line here names a project-rooted form.
func remedyProjectRooted() reachabilityRemedy {
	return reachabilityRemedy{
		lead: "Only a scan rooted at the consuming project can produce a consumer route. From the project's own directory, run",
		lines: []string{
			"kanonarion walk --gomod ./go.mod",
			"kanonarion vuln-scan --gomod ./go.mod --reachability",
			"kanonarion reachability --local .",
		},
	}
}

// remedyScanUncovered is the route to a probe answer that covers the modules
// the current one does not.
//
// The local probe reads stored findings; a module the store has never been asked
// about therefore contributes nothing however often the probe is re-run. What
// makes the next answer wider is scanning the build, so that is what this names
// — and naming it is the point, because the probe has no refresh flag and an
// operator told only that modules were uncovered would have no route at all.
func remedyScanUncovered() reachabilityRemedy {
	return reachabilityRemedy{
		lead: "These modules carry no stored record, so re-running the probe cannot widen the answer. Scan the build first, from the project's own directory",
		lines: []string{
			"kanonarion walk --gomod ./go.mod",
			"kanonarion vuln-scan --gomod ./go.mod --reachability",
		},
	}
}

// remedyRescanProject is the remedy for a re-scan that refused because it could
// not reproduce the project-rooted frame of the run it was asked to re-scan.
//
// It names the project spelling of the scan rather than the walk spelling,
// because that is the form that carries the root: --gomod points the analysis at
// the tree, so the re-run is rooted where the original was. Repeating
// vuln-scan-rescan would repeat the refusal.
func remedyRescanProject(dir string) reachabilityRemedy {
	return reachabilityRemedy{
		lead: "Re-scan rooted at the project itself, from a machine that holds its working tree",
		lines: []string{
			"kanonarion vuln-scan --gomod " + filepath.Join(dir, "go.mod") + " --reachability",
		},
	}
}

// remedyShowRecord points at the record itself, for a refusal that no re-run
// resolves.
func remedyShowRecord(coord coordinate.ModuleCoordinate) reachabilityRemedy {
	return reachabilityRemedy{
		lead: "See",
		lines: []string{
			"kanonarion vuln-show " + coord.String(),
		},
	}
}

// reachabilityRemedies returns every remedy the reachability surfaces can print,
// built against one coordinate. It exists so the contract test enumerates the
// set from the code rather than from a hand-copied list that a new refusal would
// quietly fall outside of.
func reachabilityRemedies(coord coordinate.ModuleCoordinate) []reachabilityRemedy {
	return []reachabilityRemedy{
		remedyScanModule(coord),
		remedyRescanModule(coord),
		remedyRebuildGraphThenRescan(coord),
		remedyProjectRooted(),
		remedyScanUncovered(),
		remedyRescanProject("/srv/checkouts/project"),
		remedyShowRecord(coord),
	}
}
