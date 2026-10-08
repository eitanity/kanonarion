package cli

import (
	"fmt"
	"io"
)

// listGeneration is the generation contract a per-coordinate listing keeps:
// by default only records at the generation this build serves are listed,
// --all-generations includes the earlier ones and marks each, and both paths
// state which generation answered. A record at a generation this build does not
// serve answers no query, so listing it unmarked pads the count of what is known.
//
// One value per listing carries the wording, so the filter, the row mark and
// the statement are written once for license-list, native-list, interface-list,
// examples-list and callgraph-list.
type listGeneration struct {
	// served is the generation this build answers from, and all is
	// --all-generations.
	served string
	all    bool
	// subject is the listing's rows in the plural, as the truncation line names
	// them.
	subject string
	// at, servedNoun and supersededNoun are the ledger's words for a
	// generation: "at pipeline 1.4.0, the version this build serves" against
	// "at generation 0.3.0, the generation this build serves".
	at, servedNoun, supersededNoun string
	// producedAt says how a superseded row came to be, redo names the remedy and
	// produce is the invocation that re-derives one.
	producedAt, redo, produce string
}

// pipelineGeneration is the contract for a ledger keyed on its extraction
// pipeline version.
func pipelineGeneration(subject, served string, all bool, produce string) listGeneration {
	return listGeneration{
		served: served, all: all, subject: subject,
		at: "pipeline", servedNoun: "version", supersededNoun: "pipeline version",
		producedAt: "extracted at a superseded pipeline version",
		redo:       "Re-extract one", produce: produce,
	}
}

// filterVersion is the generation the store is asked for, empty under
// --all-generations.
func (g listGeneration) filterVersion() string {
	if g.all {
		return ""
	}
	return g.served
}

// superseded reports whether a row at this generation is one this build does
// not serve.
func (g listGeneration) superseded(version string) bool { return version != g.served }

// mark is the text row's suffix for a row at this generation: empty at the
// served one.
func (g listGeneration) mark(version string) string {
	if !g.superseded(version) {
		return ""
	}
	return "  [superseded generation " + version + "]"
}

// listGenerationJSON is the listing document's statement of which generation
// answered. It is a field of its own rather than words in `subject`, because
// the truncation line renders the subject mid-sentence — "showing license
// records 3-4" — and a subject carrying a version reads as a range of versions.
type listGenerationJSON struct {
	// Served is stated in both modes: a consumer comparing a row's generation
	// against it needs the value whether or not the listing was restricted.
	Served string `json:"served"`
	// AllGenerations names the state, and is present at both values.
	AllGenerations bool `json:"all_generations"`
	// Remedy is the flag that lifts the restriction, absent under
	// --all-generations where there is nothing left to lift.
	Remedy string `json:"remedy,omitempty"`
}

// statement renders the generation half of the listing document.
func (g listGeneration) statement() listGenerationJSON {
	out := listGenerationJSON{Served: g.served, AllGenerations: g.all}
	if !g.all {
		out.Remedy = "--all-generations"
	}
	return out
}

// writeNotice states on the text path which generation the rows were drawn
// from. The restricted listing says so on every page, because a reader not told
// the rows were restricted cannot tell a restricted count from a whole one;
// under --all-generations it counts the rows it marked.
func (g listGeneration) writeNotice(stdout io.Writer, superseded, listed int) error {
	if !g.all {
		_, err := fmt.Fprintf(stdout,
			"listing %s at %s %s, the %s this build serves; "+
				"records from a superseded %s are not shown (--all-generations)\n",
			g.subject, g.at, g.served, g.servedNoun, g.supersededNoun)
		if err != nil {
			return fmt.Errorf("writing generation notice: %w", err)
		}
		return nil
	}
	if superseded == 0 {
		return nil
	}
	_, err := fmt.Fprintf(stdout,
		"%d of %d listed record(s) were %s; this build serves %s "+
			"and answers no query from them. %s:\n  %s\n",
		superseded, listed, g.producedAt, g.served, g.redo, g.produce)
	if err != nil {
		return fmt.Errorf("writing superseded notice: %w", err)
	}
	return nil
}
