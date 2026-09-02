package cli

import (
	"context"
	"fmt"
	"strings"
	"unicode/utf8"

	"github.com/eitanity/kanonarion/internal/coordinate"

	vulnports "github.com/eitanity/kanonarion/internal/vuln/ports"
)

// Telling "never vuln-scanned" from "scanned under logic this build supersedes".
//
// Every per-coordinate vulnerability read takes the pipeline version as part of
// its key, so a bump empties all of them at once for coordinates whose whole
// history is still in the table. Read from the answer alone the two conditions
// are identical, and they are opposite instructions: one says a dependency has
// never been checked, the other says the check ran and must run again. An
// operator deciding whether they have a coverage gap or a stale cache is reading
// exactly this distinction.
//
// This mirrors the call graph's supersededPipelineError and the interface
// reader's supersededInterfaceLine, deliberately: it is one condition, and one
// binary must not describe it three ways. What it cannot mirror is their method.
// Those readers list the store unfiltered and see the other generations for
// themselves; the vulnerability reads cannot, which is why the census below is a
// store read of its own.

// supersededVulnGenerations reports the generations the store holds for coord,
// none of which this build serves. The second result is false when the store
// holds nothing for the coordinate at all, or holds it at the version this build
// reads — neither is this diagnostic's case, and the caller keeps the statement
// it already had.
//
// A diagnostic must not become a fault of its own. A caller wired without the
// use case, or a census that fails to read, yields false: less precise, never
// wrong, and never an error about the error.
//
// It is a second store read, so it runs on the empty path only. A read that
// found records has nothing to diagnose and pays nothing.
func supersededVulnGenerations(
	ctx context.Context,
	uc QueryVulnUseCase,
	coord coordinate.ModuleCoordinate,
) ([]vulnports.VulnerabilityRecordGeneration, bool) {
	if uc == nil {
		return nil, false
	}
	gens, err := uc.ListRecordGenerationsForModule(ctx, coord)
	if err != nil || len(gens) == 0 {
		return nil, false
	}
	out := make([]vulnports.VulnerabilityRecordGeneration, 0, len(gens))
	for _, g := range gens {
		if g.PipelineVersion == vulnPipelineVersion {
			// Served at this version: whatever emptied the answer, it was not the
			// pipeline version, and naming one would send the reader after a
			// re-scan that changes nothing.
			return nil, false
		}
		out = append(out, g)
	}
	return out, true
}

// supersededVulnHeld renders what the store holds, generation by generation.
// The counts are stated because "there is something there" and "there are 16
// scans carrying 252 findings there" are different sizes of the same fact, and
// the second is what tells an operator whether to re-scan now or at leisure.
func supersededVulnHeld(gens []vulnports.VulnerabilityRecordGeneration) string {
	parts := make([]string, 0, len(gens))
	for _, g := range gens {
		parts = append(parts, fmt.Sprintf("%s (%d record(s), %d finding(s))",
			g.PipelineVersion, g.Records, g.Findings))
	}
	return strings.Join(parts, ", ")
}

// supersededVulnLine is the statement for one coordinate the store holds only
// under superseded scan logic. It names the generations held and the one this
// build reads, because "re-scan" is only actionable against a coordinate and the
// reader has no other way to see why the records went dark.
//
// It says what the emptiness is NOT, in the words the wrong message used, because
// that is the sentence the reader arrived with.
func supersededVulnLine(coord coordinate.ModuleCoordinate, gens []vulnports.VulnerabilityRecordGeneration) string {
	return fmt.Sprintf(
		"no vulnerability record for %s that this build serves: %s Re-scan it:\n  %s",
		coord,
		supersededVulnCause("this coordinate at pipeline "+supersededVulnHeld(gens), "the module has"),
		"kanonarion vuln-scan --module "+coord.String()+" --reachability")
}

// supersededVulnCause is the whole explanation, and the only one this binary
// gives: which generation it reads, which one the store holds, and that the two
// together are a stale cache rather than a gap in coverage.
//
// It is a function of two noun phrases rather than a constant because the
// readers differ in what they are talking about — one coordinate, or the set of
// modules one run named — and nothing else about the condition differs at all.
// Copying the sentence per reader is how one condition acquires three
// descriptions that drift apart; the callers compose their own subject and share
// this.
//
// holds completes "the store holds ..."; scanned completes "... been
// vuln-scanned", so it carries its own auxiliary verb and number.
func supersededVulnCause(holds, scanned string) string {
	return fmt.Sprintf(
		"it reads pipeline %s and the store holds %s. A superseded record is not served, so this "+
			"answer is empty for want of a scan at this generation — %s been vuln-scanned, and "+
			"this is a stale cache, not a coverage gap.",
		vulnPipelineVersion, holds, scanned)
}

// supersededVulnError is supersededVulnLine as the refusal a command exits on.
//
// The exit code stays ExitNotFound. No record was served, which is what that code
// says; what changes is that the reason is now true. A command that had exited 4
// on this coordinate still exits 4, so nothing scripted around the old behaviour
// starts passing silently.
func supersededVulnError(coord coordinate.ModuleCoordinate, gens []vulnports.VulnerabilityRecordGeneration) error {
	return &exitError{code: ExitNotFound, msg: supersededVulnLine(coord, gens)}
}

// supersededVulnRefusal is the whole check as one call, for the readers whose
// empty branch is a refusal: nil when the emptiness has some other cause, and
// the caller carries on to whatever it said before.
func supersededVulnRefusal(ctx context.Context, uc QueryVulnUseCase, coord coordinate.ModuleCoordinate) error {
	gens, superseded := supersededVulnGenerations(ctx, uc, coord)
	if !superseded {
		return nil
	}
	return supersededVulnError(coord, gens)
}

// The same condition, one level up: a RUN whose records this build does not read.
//
// A coordinate's gap closes at the next re-scan of that coordinate. A run's
// never does. A run stores the record identities it was built from, so scanning
// again writes new records beside the old ones and leaves the run pointing where
// it pointed; the modules it named stay unreadable from it for as long as the
// run is kept. So this is not a transient state awaiting a re-scan — it is the
// permanent reading of a historical run, and the wording has to be true of a run
// that is simply old.

// supersededRunRecord is one module a run named whose record the store still
// holds, at a generation this build does not read.
//
// The counts are the size of what is behind the gap, per module, and they are
// the reason this is reported per coordinate rather than as one run-wide
// sentence: "there is something there" and "there are 4 scans carrying 11
// findings there" are different facts.
type supersededRunRecord struct {
	Coordinate      string `json:"coordinate"`
	PipelineVersion string `json:"pipeline_version"`
	Records         int    `json:"records"`
	Findings        int    `json:"findings"`
}

// supersededRunGeneration reports what the store holds for coord at the
// generation runPipeline, when that generation is not the one this build reads.
//
// It is the check that makes the difference between "no record backs this
// module" and "the record backing this module is in the store and is declined",
// and only the second is true when it answers true. False keeps the caller's
// existing statement, which is then the accurate one: a caller wired without the
// use case, a census that will not read, a run at this build's own generation,
// or a coordinate the store genuinely no longer holds at that generation.
//
// Like the coordinate census it is a second store read on the empty path only.
func supersededRunGeneration(
	ctx context.Context,
	uc QueryVulnUseCase,
	coord coordinate.ModuleCoordinate,
	runPipeline string,
) (supersededRunRecord, bool) {
	if uc == nil || runPipeline == "" || runPipeline == vulnPipelineVersion {
		return supersededRunRecord{}, false
	}
	gens, err := uc.ListRecordGenerationsForModule(ctx, coord)
	if err != nil {
		return supersededRunRecord{}, false
	}
	for _, g := range gens {
		if g.PipelineVersion != runPipeline {
			continue
		}
		return supersededRunRecord{
			Coordinate:      coord.String(),
			PipelineVersion: g.PipelineVersion,
			Records:         g.Records,
			Findings:        g.Findings,
		}, true
	}
	return supersededRunRecord{}, false
}

// supersededRunHeading is the section heading over the modules a run named and
// this build declines. It states the count and the cause on the line that
// introduces them, in the section shape the read-error and coverage-gap sections
// already use.
func supersededRunHeading(n int, runPipeline string) string {
	return fmt.Sprintf(
		"Superseded scan records (%d): the store holds these modules at pipeline %s and this build "+
			"reads pipeline %s, so none of them is served", n, runPipeline, vulnPipelineVersion)
}

// supersededRunNote is the run's whole explanation, printed once under the
// report.
//
// It shares supersededVulnCause with the coordinate refusal, because it is that
// condition and one binary must not describe it twice. What it adds is the part
// that is only true of a run: re-scanning does not repair this one. A reader
// told "stale cache, re-scan" and nothing else would re-scan, look again, and
// find the run unchanged.
//
// walkID is empty when the walk this run names is no longer in the store, and
// the remedy line is then omitted rather than printed against an id that
// resolves to nothing.
func supersededRunNote(recs []supersededRunRecord, total int, runPipeline, walkID string) string {
	if len(recs) == 0 {
		return ""
	}
	records, findings := 0, 0
	for _, r := range recs {
		records += r.Records
		findings += r.Findings
	}
	body := fmt.Sprintf(
		"%d of %d module(s) this run names are recorded at pipeline %s, holding %d record(s) and "+
			"%d finding(s) this build does not serve: %s Re-scanning does not repair this run: a run "+
			"names the records it was built from, so a new scan writes new records beside these and "+
			"leaves this run reading as it does.",
		len(recs), total, runPipeline, records, findings,
		supersededVulnCause("them at pipeline "+runPipeline, "they have"))

	var b strings.Builder
	b.WriteString("\n")
	// The label is wrapped with the sentence rather than written in front of it,
	// so the first line is measured to the same width as the rest.
	b.WriteString(wrapContinued("notice: "+body, supersededNoteWidth, supersededNoteIndent))
	b.WriteString("\n")
	if walkID != "" {
		b.WriteString(supersededNoteIndent + "Scan the walk again for a current answer:\n")
		fmt.Fprintf(&b, "%s  kanonarion vuln-scan %s --reachability\n", supersededNoteIndent, walkID)
	}
	return b.String()
}

// The notice's shape. The indent is the width of "notice: ", so the wrapped
// sentence hangs under its own first line rather than under the margin.
const (
	supersededNoteWidth  = 88
	supersededNoteIndent = "        "
)

// wrapContinued breaks text on word boundaries at width columns, indenting every
// line after the first.
//
// The sentence it wraps is composed from a shared function, so it arrives as one
// string and cannot be hand-broken at the call site without becoming a second
// copy of the wording. Width is counted in runes: the sentence carries an em
// dash, and counting bytes would wrap it three columns early.
//
// A single word longer than the width is emitted whole rather than cut — a
// broken module coordinate is worse than a long line.
func wrapContinued(text string, width int, indent string) string {
	words := strings.Fields(text)
	if len(words) == 0 {
		return ""
	}
	var b strings.Builder
	b.WriteString(words[0])
	line := utf8.RuneCountInString(words[0])
	for _, w := range words[1:] {
		n := utf8.RuneCountInString(w)
		if line+1+n > width {
			b.WriteString("\n")
			b.WriteString(indent)
			b.WriteString(w)
			line = utf8.RuneCountInString(indent) + n
			continue
		}
		b.WriteString(" ")
		b.WriteString(w)
		line += 1 + n
	}
	return b.String()
}

// scanShowServedExit is the exit code for a run report whose body is short of
// the modules the run counted.
//
// ExitNotFound, the code vuln-show already gives this condition: the records
// asked for are not ones this build serves. The header asserting a verdict is
// the reason the code matters — a caller that branches on the exit status alone
// read 0 and took an Affected run with no findings body for a clean one.
//
// It is the last thing a successful render does, so the report is on stdout
// before the refusal reaches stderr: the reader gets the modules and the reason,
// not only the number.
func scanShowServedExit(superseded []supersededRunRecord, missing []string, total int) error {
	n := len(superseded) + len(missing)
	if n == 0 {
		return nil
	}
	switch {
	case len(missing) == 0:
		return &exitError{code: ExitNotFound, msg: fmt.Sprintf(
			"%d of %d module(s) this run names are recorded at a pipeline generation this build does "+
				"not read; no status above rests on them", n, total)}
	case len(superseded) == 0:
		return &exitError{code: ExitNotFound, msg: fmt.Sprintf(
			"%d of %d module(s) this run names have no record in the store; no status above rests on them",
			n, total)}
	default:
		return &exitError{code: ExitNotFound, msg: fmt.Sprintf(
			"%d of %d module(s) this run names produced no record this build serves (%d superseded, "+
				"%d absent); no status above rests on them", n, total, len(superseded), len(missing))}
	}
}
