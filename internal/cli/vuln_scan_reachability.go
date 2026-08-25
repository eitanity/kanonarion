package cli

import (
	"fmt"
	"io"

	vuldomain "github.com/eitanity/kanonarion/internal/vuln/domain"
)

// This file holds the reachability roll-up a stored scan run's TEXT surface
// states.
//
// Reachability is the distinction the product exists to make: "16 affected
// modules" and "28 findings with a route, 33 undecided" are different answers to
// the release question, and only the second is actionable. The run's --json has
// carried the routes and the rung on every finding all along; the human surface
// printed advisory ids and left the reader to infer.
//
// The split is free. Every field it reads is already on the findings the text
// path holds, and the rung beside each one is the SAME derivation --json
// publishes, taken once — so the two surfaces cannot report different numbers.
// What it must not do is trigger the route-root classification the text path
// deliberately skips (see runScanShow: 0.08s text against 1.5s with it on a
// 176-module run); a root is per-finding detail, and this is a tally.

// scanReachabilitySplit is a scan run's findings in the three buckets a release
// decision turns on, with the undecided bucket kept per rung.
//
// The buckets are not derivable from is_reachable. Measured on a 128-module run:
// all 33 negatives were unsound, so counting is_reachable renders "28 reachable,
// 33 not reachable, 0 undecided" — a clean negative for 33 findings no search
// ever looked at.
type scanReachabilitySplit struct {
	// total is the findings the split covers, so a reader can check it against
	// the sections below it.
	total int
	// reachable is a route that exists. A route is its own evidence and answers
	// its own soundness question, which is why the positives carry no rung.
	reachable int
	// notReachable is a negative that satisfies IsConfirmed, and nothing else.
	notReachable int
	// undecided is every remaining negative: a recorded "no" that no search
	// stands behind. It is NOT a weaker form of notReachable — it is the absence
	// of the search that would make one.
	undecided int
	// byRung keys the undecided bucket by the rung the finding earned, so the
	// contradicted negative is never tallied beside the merely uninvestigated
	// one.
	byRung map[vuldomain.ReachabilitySoundness]int
}

// reachabilitySplitOf tallies a run's affected modules.
//
// Withdrawn advisories are excluded wherever they sit. The report already says
// they are "not counted as findings", and a retracted advisory counted into an
// undecided bucket would inflate the one figure an operator reads as work
// outstanding. Modules whose every advisory was withdrawn are not passed here at
// all; this drops the ones sitting inside a module that also has live findings.
//
// The rung is read off the finding's own projection rather than re-derived, so
// the text tally and the --json field are one derivation and cannot disagree.
func reachabilitySplitOf(modules []scanAffectedModule) scanReachabilitySplit {
	split := scanReachabilitySplit{byRung: make(map[vuldomain.ReachabilitySoundness]int)}
	for _, m := range modules {
		for _, f := range m.Findings {
			if f.IsWithdrawn() {
				continue
			}
			split.total++
			if f.Reachable != nil && f.Reachable.IsReachable {
				split.reachable++
				continue
			}
			if f.Soundness.IsConfirmed() {
				split.notReachable++
				continue
			}
			split.undecided++
			split.byRung[f.Soundness]++
		}
	}
	return split
}

// writeScanReachabilitySplit states the split, or nothing at all when the run
// counted no findings.
//
// A run with nothing to split gets no block: an empty reachability heading over
// three zeros is a paragraph that says only what "Affected modules" already said
// by being absent.
//
// The zeros ARE printed when there is something to split. "not reachable 0"
// beside "undecided 33" is the whole statement — a complete scan with 33
// undecided findings is not a pass, and a bucket left out because it was empty
// is a bucket a reader assumes was full.
func writeScanReachabilitySplit(w io.Writer, split scanReachabilitySplit) {
	if split.total == 0 {
		return
	}
	_, _ = fmt.Fprintf(w, "Reachability of %d finding(s):\n", split.total)
	_, _ = fmt.Fprintf(w, "  %-14s %4d\n", "reachable", split.reachable)
	_, _ = fmt.Fprintf(w, "  %-14s %4d — %s\n", "not reachable", split.notReachable,
		vuldomain.SoundnessConfirmed.Statement())
	_, _ = fmt.Fprintf(w, "  %-14s %4d — %s\n", "undecided", split.undecided,
		"a recorded negative no search stands behind; none of these is a clean negative")
	// The breakdown walks the domain's own ladder rather than a list restated
	// here, so a rung added to the type is rendered under its own name and its
	// own words with no edit to this renderer — and can never be folded into a
	// neighbour's tally on the way.
	for _, rung := range vuldomain.ReachabilitySoundnessLevels() {
		n := split.byRung[rung]
		if n == 0 {
			continue
		}
		line := fmt.Sprintf("    %-12s %4d", rung.String(), n)
		if statement := rung.Statement(); statement != "" {
			line += " — " + statement
		}
		_, _ = fmt.Fprintf(w, "%s\n", line)
	}
}
