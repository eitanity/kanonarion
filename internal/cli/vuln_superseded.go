package cli

import (
	"context"
	"fmt"
	"strings"

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
		"no vulnerability record for %s that this build serves: it reads pipeline %s and the store "+
			"holds this coordinate at pipeline %s. A superseded record is not served, so this answer "+
			"is empty for want of a scan at this generation — the module has been vuln-scanned, and "+
			"this is a stale cache, not a coverage gap. Re-scan it:\n  %s",
		coord, vulnPipelineVersion, supersededVulnHeld(gens),
		"kanonarion vuln-scan --module "+coord.String()+" --reachability")
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
