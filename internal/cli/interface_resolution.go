package cli

import (
	"context"
	"fmt"
	"strings"

	"github.com/eitanity/kanonarion/internal/coordinate"

	ifaceapp "github.com/eitanity/kanonarion/internal/iface/application"
	ifaceports "github.com/eitanity/kanonarion/internal/iface/ports"
)

// Telling "never extracted" from "extracted under superseded logic".
//
// A record is served only at the pipeline version this build produces — that is
// what a pipeline bump means. Both conditions read as an absent record at the
// query, and they have opposite remedies: one is a coordinate to check, the
// other is a re-extraction to run. A reader sent after the first when the cause
// was the second goes hunting for a spelling error that does not exist.
//
// This mirrors the call graph's supersededPipelineError, deliberately: it is one
// condition, and one binary must not describe it two ways.

// storedInterfaceSummaries reads the WHOLE ledger, unfiltered by pipeline
// version. It answers the store-wide form of the question — "does this build
// serve anything at all" — and nothing else: a question about one coordinate
// goes through supersededInterfaceRecord, which asks the store for that
// coordinate.
//
// A diagnostic must not become a fault of its own. A caller wired without this
// use case — a seam built for one command — or a read that fails yields no
// summaries, and the caller keeps the statement it already had: less precise,
// never wrong, and never a panic in place of an answer.
func storedInterfaceSummaries(ctx context.Context, uc QueryInterfaceUseCase) []ifaceports.InterfaceSummary {
	if uc == nil {
		return nil
	}
	sums, err := uc.ListInterfaceRecords(ctx, ifaceports.InterfaceFilter{})
	if err != nil {
		return nil
	}
	return sums
}

// supersededInterfaceRecord answers, for ONE coordinate, whether the store holds
// it only under extraction logic this build no longer serves.
//
// The read is filtered to the coordinate because that is the question. Asking it
// with a whole-store listing made the diagnostic cost the composition of every
// multi-generation key in the ledger, once per module, and `context --gomod` on
// a project whose records are all superseded spent minutes discarding rows.
func supersededInterfaceRecord(ctx context.Context, uc QueryInterfaceUseCase, coord coordinate.ModuleCoordinate) ([]string, bool) {
	if uc == nil {
		return nil, false
	}
	sums, err := uc.ListInterfaceRecords(ctx, ifaceports.InterfaceFilter{Coordinate: &coord})
	if err != nil {
		return nil, false
	}
	return supersededInterfacePipelines(coord, sums)
}

// supersededInterfacePipelines returns the pipeline versions the store holds for
// coord, none of which this build serves. The second result is false when the
// store holds nothing for the coordinate at all, or holds a record this build
// does serve — neither is this diagnostic's case.
func supersededInterfacePipelines(coord coordinate.ModuleCoordinate, stored []ifaceports.InterfaceSummary) ([]string, bool) {
	seen := make(map[string]bool)
	for _, s := range stored {
		if s.ModulePath != coord.Path() || s.ModuleVersion != coord.Version() {
			continue
		}
		if s.PipelineVersion == ifaceapp.PipelineVersion {
			// Served at this version: whatever emptied the answer, it was not
			// the pipeline version.
			return nil, false
		}
		seen[s.PipelineVersion] = true
	}
	if len(seen) == 0 {
		return nil, false
	}
	return sortedKeys(seen), true
}

// supersededInterfaceLine is the statement for one coordinate the store holds
// only under superseded extraction logic. It names the versions held and the
// version this build serves, because "re-extract" is only actionable against a
// coordinate and the reader has no other way to see why the record went dark.
func supersededInterfaceLine(coord coordinate.ModuleCoordinate, pipelines []string) string {
	return fmt.Sprintf(
		"the interface record for %s was produced by superseded extraction logic: this build "+
			"serves pipeline %s and the store holds this coordinate at pipeline %s. A superseded "+
			"record is not served, so this answer is empty for want of a measurement of this "+
			"module, not because the coordinate is wrong. Re-extract it:\n  kanonarion interface %s",
		coord, ifaceapp.PipelineVersion, strings.Join(pipelines, ", "), coord)
}

// supersededInterfaceStoreLine is the same statement for a query that names no
// coordinate: every interface record in the store predates this build's
// extraction logic, so a symbol lookup has nothing it is allowed to read.
// Reports false while any served record remains, which is the ordinary case.
func supersededInterfaceStoreLine(stored []ifaceports.InterfaceSummary) (string, bool) {
	if len(stored) == 0 {
		return "", false
	}
	seen := make(map[string]bool)
	for _, s := range stored {
		if s.PipelineVersion == ifaceapp.PipelineVersion {
			return "", false
		}
		seen[s.PipelineVersion] = true
	}
	return fmt.Sprintf(
		"the store holds %d interface record(s), every one produced by superseded extraction "+
			"logic: this build serves pipeline %s and the store holds pipeline %s. A superseded "+
			"record is not served, so this answer is empty for want of a measurement, not because "+
			"nothing exports this name. Re-extract a module:\n  kanonarion interface <module>@<version>",
		len(stored), ifaceapp.PipelineVersion, strings.Join(sortedKeys(seen), ", ")), true
}
