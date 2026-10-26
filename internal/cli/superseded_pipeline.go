package cli

import (
	"context"
	"fmt"
	"slices"
	"strings"

	"code.eitanity.com/kanonarion/internal/coordinate"

	exapp "code.eitanity.com/kanonarion/internal/example/application"
	licapp "code.eitanity.com/kanonarion/internal/license/application"
)

// supersededRecordLine is the statement for a coordinate whose every stored
// record of one type was produced at a pipeline this build does not serve. One
// sentence for every record type: it is one condition, and the remedy differs
// only in the command.
func supersededRecordLine(record string, coord coordinate.ModuleCoordinate, served string, held []string, verb, remedy string) string {
	return fmt.Sprintf(
		"the %s for %s was produced by superseded extraction logic: this build "+
			"serves pipeline %s and the store holds this coordinate at pipeline %s. A superseded "+
			"record is not served, so this answer is empty for want of a measurement of this "+
			"module, not because the coordinate is wrong. %s it:\n  %s",
		record, coord, served, strings.Join(held, ", "), verb, remedy)
}

// pipelinesHeldReader lists the pipelines one coordinate is held at, from that
// coordinate's keys alone.
type pipelinesHeldReader interface {
	PipelinesHeld(ctx context.Context, coord coordinate.ModuleCoordinate) ([]string, error)
}

// supersededPipelines is the pipelines coord is held at when none is served.
// A read that fails answers false: the not_run it leaves is less precise,
// never wrong.
func supersededPipelines(ctx context.Context, r pipelinesHeldReader, coord coordinate.ModuleCoordinate, served string) ([]string, bool) {
	held, err := r.PipelinesHeld(ctx, coord)
	if err != nil || len(held) == 0 || slices.Contains(held, served) {
		return nil, false
	}
	return held, true
}

// supersededLicenceLine is the licence section's statement for a coordinate
// held only at superseded licence pipelines, or "" when it is not.
func supersededLicenceLine(ctx context.Context, uc QueryLicenseUseCase, coord coordinate.ModuleCoordinate) string {
	held, ok := supersededPipelines(ctx, uc, coord, licapp.PipelineVersion)
	if !ok {
		return ""
	}
	return supersededRecordLine("licence record", coord, licapp.PipelineVersion, held,
		"Re-extract", "kanonarion license "+coord.String())
}

// supersededExamplesLine is supersededLicenceLine for example records.
func supersededExamplesLine(ctx context.Context, uc QueryExamplesUseCase, coord coordinate.ModuleCoordinate) string {
	held, ok := supersededPipelines(ctx, uc, coord, exapp.PipelineVersion)
	if !ok {
		return ""
	}
	return supersededRecordLine("example record", coord, exapp.PipelineVersion, held,
		"Re-extract", "kanonarion examples "+coord.String())
}
