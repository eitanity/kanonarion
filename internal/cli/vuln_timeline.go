package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"time"

	"github.com/eitanity/kanonarion/internal/coordinate"

	vuldomain "github.com/eitanity/kanonarion/internal/vuln/domain"
)

// timelineJSON is the --timeline --json document.
type timelineJSON struct {
	FindingID  string                      `json:"finding_id"`
	WalkID     string                      `json:"walk_id,omitempty"`
	Timelines  []vuldomain.FindingTimeline `json:"timelines"`
	Unreadable []any                       `json:"unreadable,omitempty"`
}

// runVulnTimeline prints the timelines the query computes, and the rows it
// could not read.
func runVulnTimeline(ctx context.Context, findingID, walkID string, jsonOut bool, uc QueryVulnUseCase, stdout io.Writer) error {
	timelines, err := uc.FindingTimelines(ctx, findingID, walkID)
	unreadable, survivable := unreadableRowReport(err)
	if err != nil && !survivable {
		return fmt.Errorf("vuln-by-id: %w", err)
	}
	if jsonOut {
		doc := timelineJSON{FindingID: findingID, WalkID: walkID, Timelines: timelines}
		if doc.Timelines == nil {
			doc.Timelines = []vuldomain.FindingTimeline{}
		}
		for _, u := range unreadable {
			doc.Unreadable = append(doc.Unreadable, toUnreadableRecordJSON(u))
		}
		enc := json.NewEncoder(stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(doc); err != nil {
			return fmt.Errorf("encoding the timeline: %w", err)
		}
		return nil
	}
	writeTimelines(stdout, findingID, walkID, timelines, unreadable)
	return nil
}

func writeTimelines(stdout io.Writer, findingID, walkID string, timelines []vuldomain.FindingTimeline, unreadable []unreadableRowEntry) {
	if walkID != "" {
		_, _ = fmt.Fprintf(stdout, "notice: results restricted to the modules scanned under walk %q\n", walkID)
	}
	if len(timelines) == 0 && len(unreadable) == 0 {
		if walkID != "" {
			_, _ = fmt.Fprintf(stdout, "no modules in walk %s affected by %s\n", walkID, findingID)
			return
		}
		_, _ = fmt.Fprintf(stdout, "no modules affected by %s\n", findingID)
		return
	}
	for _, tl := range timelines {
		writeTimeline(stdout, tl)
	}
	if len(unreadable) > 0 {
		_, _ = fmt.Fprintln(stdout, "\nnotice: the timelines above are built without these rows; a change shown across one may be two.")
		writeUnreadableRows(stdout, unreadable, vulnRecordIDColumn)
	}
}

func writeTimeline(w io.Writer, tl vuldomain.FindingTimeline) {
	head := fmt.Sprintf("%s  frame %s", coordLabel(tl.Coordinate), tl.Rooting)
	if len(tl.Entries) == 0 {
		line := fmt.Sprintf("%s  no change of state in %d record(s): %s", head, tl.RecordCount, tl.State)
		if fr := tl.FirstReported; fr != nil {
			line += ", first reported at or before " + ledgerStamp(fr.Record.ScannedAt)
		}
		_, _ = fmt.Fprintln(w, line)
		return
	}
	_, _ = fmt.Fprintf(w, "%s  %d record(s)\n", head, tl.RecordCount)
	if fr := tl.FirstReported; fr != nil {
		if fr.AtOrBefore {
			_, _ = fmt.Fprintf(w, "  first reported: at or before %s\n", ledgerStamp(fr.Record.ScannedAt))
		} else {
			_, _ = fmt.Fprintf(w, "  first reported: %s; the analysed record of %s did not report it\n",
				ledgerStamp(fr.Record.ScannedAt), ledgerStamp(fr.Previous.ScannedAt))
		}
	}
	for _, e := range tl.Entries {
		_, _ = fmt.Fprintf(w, "  %-32s %s\n", ledgerStamp(e.ToRecord.ScannedAt), timelineEntryText(e))
	}
	if nl := tl.NoLongerReported; nl != nil {
		at := ledgerStamp(nl.Record.ScannedAt)
		switch {
		case nl.Established:
			_, _ = fmt.Fprintf(w, "  no longer reported: %s (%s)\n", at, nl.Reason)
		case nl.EntryKind == vuldomain.TimelineGenerationDisagreement:
			_, _ = fmt.Fprintf(w, "  no longer reported: not established; the record of %s is another pipeline\n", at)
		default:
			_, _ = fmt.Fprintf(w, "  no longer reported: not established; the record of %s analysed nothing (coverage=%s)\n", at, nl.Record.Coverage)
		}
	}
}

func coordLabel(c coordinate.ModuleCoordinate) string { return c.Path() + "@" + c.Version() }

// timelineEntryText renders one entry: the reason word, the states, and the
// fact the reason rests on.
func timelineEntryText(e vuldomain.TimelineEntry) string {
	if e.Kind == vuldomain.TimelineGenerationDisagreement {
		return fmt.Sprintf("%-24s %s -> %s  pipeline %s -> %s, not a change",
			e.Kind, e.From, e.To, e.FromRecord.PipelineVersion, e.ToRecord.PipelineVersion)
	}
	text := fmt.Sprintf("%-24s %s -> %s  pipeline=%s", e.Reason, e.From, e.To, e.ToRecord.PipelineVersion)
	switch e.Reason {
	case vuldomain.ReasonWithdrawn:
		text += " withdrawn_at=" + e.WithdrawnAt.UTC().Format(time.RFC3339)
	case vuldomain.ReasonCoverageLost:
		text += fmt.Sprintf(" coverage=%s, nothing analysed", e.ToRecord.Coverage)
	}
	return text
}
