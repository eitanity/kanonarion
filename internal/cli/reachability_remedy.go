package cli

import (
	"fmt"
	"path/filepath"
	"strings"

	cgdomain "github.com/eitanity/kanonarion/internal/callgraph/domain"
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
	// own — with one exception, held to the same standard. Where no command can
	// be given, a line may be the sentence saying why, and it must still name the
	// command it is about, so a reader is never left without one. What stays
	// forbidden is an annotation bolted onto an otherwise runnable line: that is
	// indistinguishable from an argument, to the parser and to the reader alike.
	lines []string
}

// empty reports a remedy that names no command. A refusal names a command that
// resolves for the record in hand, or it names none — so callers ask this
// rather than printing a lead over nothing.
func (r reachabilityRemedy) empty() bool { return len(r.lines) == 0 }

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

// walkInvocation names the command that produces a walk of coord.
//
// A project module carries the synthetic "local" version, which the walk command
// cannot take positionally: there is no published artefact to resolve, and the
// form that walks a tree is --gomod. Everything that prints "walk <coordinate>"
// as advice goes through here so the two forms are not chosen per site.
func walkInvocation(coord coordinate.ModuleCoordinate) string {
	return walkInvocationForRendered(coord.String())
}

// walkInvocationForRendered is walkInvocation for a coordinate a caller already
// holds as "<path>@<version>" text rather than as a value.
func walkInvocationForRendered(coord string) string {
	if strings.HasSuffix(coord, "@"+coordinate.LocalVersion) {
		return "kanonarion walk --gomod ./go.mod"
	}
	return "kanonarion walk " + coord
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
			walkInvocation(coord),
			"kanonarion vuln-scan --module " + coord.String() + " --reachability",
		},
	}
}

// rescanInvocation names the vuln-scan that re-measures coord.
//
// vuln-scan's --module form resolves only a walk ROOTED at the coordinate, and
// a module measured in a consumer's build has none — so where the record names
// the walk that measured it, that walk id is the form that resolves.
func rescanInvocation(coord coordinate.ModuleCoordinate, walkID string, force bool) string {
	target := "--module " + coord.String()
	if walkID != "" {
		target = walkID
	}
	line := "kanonarion vuln-scan " + target + " --reachability"
	if force {
		line += " --force"
	}
	return line
}

// remedyRescanModule is the remedy for a coordinate whose scan failed. No
// --force: a ScanFailed record is never served from the scan cache, so the
// re-run measures rather than replaying the failure.
//
// walkID is the walk the failed record was written by, empty when it names
// none.
func remedyRescanModule(coord coordinate.ModuleCoordinate, walkID string) reachabilityRemedy {
	return reachabilityRemedy{
		lead: "Re-run",
		lines: []string{
			rescanInvocation(coord, walkID, false),
		},
	}
}

// remedyRescanSuperseded is the remedy for a coordinate the store holds only
// under scan logic this build supersedes.
//
// rooted says a walk targets the coordinate, which is the only case --module
// resolves; otherwise the walks its records name are what re-scan it. The other
// walks are counted rather than listed: one runnable command is what the reader
// needs, and the count is what tells them it was a choice.
func remedyRescanSuperseded(lead string, coord coordinate.ModuleCoordinate, rooted bool, walkIDs []string) reachabilityRemedy {
	if rooted {
		return reachabilityRemedy{lead: lead, lines: []string{rescanInvocation(coord, "", false)}}
	}
	if len(walkIDs) == 0 {
		return reachabilityRemedy{lead: lead}
	}
	if len(walkIDs) > 1 {
		lead = fmt.Sprintf("%s — the walk that measured it most recently, of the %d that hold it", lead, len(walkIDs))
	} else {
		lead += " — the walk that measured it"
	}
	return reachabilityRemedy{lead: lead, lines: []string{rescanInvocation(coord, walkIDs[0], false)}}
}

// remedyRescanWalk is the remedy for a report whose records a walk still holds
// at a generation this build reads nothing from.
func remedyRescanWalk(walkID string) reachabilityRemedy {
	if walkID == "" {
		return reachabilityRemedy{lead: supersededRunRemedyLead}
	}
	return reachabilityRemedy{
		lead:  supersededRunRemedyLead,
		lines: []string{"kanonarion vuln-scan " + walkID + " --reachability"},
	}
}

// supersededRunRemedyLead introduces the walk re-scan under a run report.
const supersededRunRemedyLead = "Scan the walk again for a current answer"

// remedyRebuildGraphThenRescan is the remedy for a coordinate that HAS a usable
// scan whose reachability leg could not see a call graph. --force is on the scan
// because a stored answer for this coordinate already exists: without it the run
// may be served from cache and report the same undetermined answer, which reads
// as the remedy having been tried and failed.
func remedyRebuildGraphThenRescan(coord coordinate.ModuleCoordinate, walkID string) reachabilityRemedy {
	return reachabilityRemedy{
		lead: "Run",
		lines: []string{
			cgdomain.ReanalysisInstruction(coord, ""),
			rescanInvocation(coord, walkID, true),
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
	// An empty directory is not a gap here: the refusal that prints this may have
	// been raised by a walk that names no tree at all, whose frame was read off
	// the run's own records instead. "./go.mod" is then the right instruction —
	// run it from the project — where filepath.Join would have produced a bare
	// "go.mod" that reads as a file in whatever directory the reader is in.
	goMod := "./go.mod"
	if dir != "" {
		goMod = filepath.Join(dir, "go.mod")
	}
	return reachabilityRemedy{
		lead: "Re-scan rooted at the project itself, from a machine that holds its working tree",
		lines: []string{
			"kanonarion vuln-scan --gomod " + goMod + " --reachability",
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

// printableRemedies returns every remedy the reachability and superseded-record
// surfaces can print, built against one coordinate and one walk id. It exists so
// the contract test enumerates the set from the code rather than from a
// hand-copied list that a new refusal would quietly fall outside of.
//
// Both branches of the walk-or-module choice are built, because only one of them
// is reached per store and a line the parser never sees is a line nothing checks.
func printableRemedies(coord coordinate.ModuleCoordinate, walkID string) []reachabilityRemedy {
	other := walkID + "X"
	return []reachabilityRemedy{
		remedyScanModule(coord),
		remedyRescanModule(coord, walkID),
		remedyRescanModule(coord, ""),
		remedyRebuildGraphThenRescan(coord, walkID),
		remedyRebuildGraphThenRescan(coord, ""),
		remedyProjectRooted(),
		remedyScanUncovered(),
		remedyRescanProject("/srv/checkouts/project"),
		remedyShowRecord(coord),
		remedyRescanSuperseded("Re-scan it", coord, true, nil),
		remedyRescanSuperseded("Re-scan it", coord, false, []string{walkID}),
		remedyRescanSuperseded("Re-scan it", coord, false, []string{walkID, other}),
		remedyRescanSuperseded(supersededHistoryRemedyLead, coord, true, nil),
		remedyRescanSuperseded(supersededHistoryRemedyLead, coord, false, []string{walkID}),
		remedyRescanWalk(walkID),
	}
}
