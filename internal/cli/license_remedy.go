package cli

import (
	"fmt"
	"strings"

	"github.com/eitanity/kanonarion/internal/coordinate"
)

// missingLicenceRecordRemedy names the command that produces the licence record
// a coordinate does not have.
//
// One missing record has one fix, so the commands that meet the gap from
// different ends — 'sbom' inventorying a closure, 'license-compat' judging one —
// state it from here instead of each phrasing its own. The split is on the
// coordinate, not on the caller: the local main module is unpublished, so its
// own licence comes from re-walking the project with --analyse-root, while every
// other component is a published module that is analysed by coordinate.
func missingLicenceRecordRemedy(coord coordinate.ModuleCoordinate) string {
	if coord.IsLocal() {
		return "run 'kanonarion walk --gomod ./go.mod --analyse-root' then " +
			"'kanonarion extract <walk-id>' to analyse the project's own licence"
	}
	return fmt.Sprintf("run 'kanonarion license %s'", coord)
}

// missingLicenceRecordRemedies states the fix for a SET of coordinates with no
// licence record — one sentence per kind of missing record, because the root's
// own licence and a dependency's are produced by different commands and a
// message that always named one of them would send half its readers to the
// wrong one.
//
// Dependencies share a remedy that differs only in the coordinate, so one is
// spelled out and the rest are counted: the components themselves are already
// named in the message this joins.
func missingLicenceRecordRemedies(coords []coordinate.ModuleCoordinate) string {
	var parts []string
	var firstDep coordinate.ModuleCoordinate
	root, deps := false, 0
	for _, c := range coords {
		switch {
		case c.IsLocal():
			if !root {
				root = true
				parts = append(parts, missingLicenceRecordRemedy(c))
			}
		default:
			if deps == 0 {
				firstDep = c
			}
			deps++
		}
	}
	if deps > 0 {
		dep := missingLicenceRecordRemedy(firstDep)
		if deps > 1 {
			dep += fmt.Sprintf(", and the same for the other %d component(s) named", deps-1)
		}
		parts = append(parts, dep)
	}
	return strings.Join(parts, "; ")
}
