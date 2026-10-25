package cli

import (
	"fmt"
	"sort"
	"strings"

	"github.com/eitanity/kanonarion/internal/coordinate"

	cgdomain "github.com/eitanity/kanonarion/internal/callgraph/domain"
	capapp "github.com/eitanity/kanonarion/internal/capability/application"
	capdomain "github.com/eitanity/kanonarion/internal/capability/domain"
)

// contextCapability is `capability` reduced to counts, derived from the record
// the call-graph section read. Its status is that section's status, so an
// absent or failed graph never reads as a module that can do nothing.
type contextCapability struct {
	Status     string   `json:"status"`
	Error      string   `json:"error,omitempty"`
	HeldFrames []string `json:"held_frames,omitempty"`
	ReadWith   []string `json:"read_with,omitempty"`
	// The answer is present only where a graph was extracted to search.
	*contextCapabilityAnswer
}

// contextCapabilityAnswer carries `capability --json`'s names where it has
// one; a list it carries is reduced here to a _count.
type contextCapabilityAnswer struct {
	TestRoots                string         `json:"test_roots"`
	Partial                  bool           `json:"partial"`
	Caveat                   string         `json:"caveat,omitempty"`
	Capabilities             []string       `json:"capabilities"`
	RowsByCapability         map[string]int `json:"rows_by_capability"`
	RowCount                 int            `json:"row_count"`
	SensitiveCallsCount      int            `json:"sensitive_calls_count"`
	CollectsAndEgressesCount int            `json:"collects_and_egresses_count"`
	InitReachesBothCount     int            `json:"init_reaches_both_count"`
	UnanalyzedCallees        int            `json:"unanalyzed_callees"`
	Command                  string         `json:"command"`
}

// capabilityFollowing is the section for a call-graph section that read no
// record: the same status and frames. The statement and remedy stay on
// call_graph alone, so a budgeted document does not carry them twice.
func capabilityFollowing(cg contextCallGraph) contextCapability {
	return contextCapability{Status: cg.Status, HeldFrames: cg.HeldFrames, ReadWith: cg.ReadWith}
}

// buildCapability analyses rec under capability's default scope. A graph that
// did not extract was never searched, so it gets its status and no answer.
func buildCapability(coord coordinate.ModuleCoordinate, rec cgdomain.CallGraphRecord) contextCapability {
	out := contextCapability{Status: rec.OverallStatus.String()}
	if rec.OverallStatus != cgdomain.CallGraphStatusExtracted && rec.OverallStatus != cgdomain.CallGraphStatusPartial {
		out.Error = "the call graph is " + out.Status + ", so no capability was searched for"
		return out
	}
	scope := capabilityRootScope(false)
	r := capapp.AnalyseRecord(rec, scope)
	byCap := make(map[string]int)
	for _, row := range r.Rows {
		byCap[string(row.Capability)]++
	}
	out.contextCapabilityAnswer = &contextCapabilityAnswer{
		TestRoots:                capabilityRootScopeJSON(scope),
		Partial:                  r.Partial,
		Caveat:                   r.Caveat,
		Capabilities:             capsToStrings(r.Capabilities()),
		RowsByCapability:         byCap,
		RowCount:                 len(r.Rows),
		SensitiveCallsCount:      len(r.SensitiveCalls),
		CollectsAndEgressesCount: len(r.CollectsAndEgresses),
		InitReachesBothCount:     len(r.InitReachesBoth),
		UnanalyzedCallees:        r.UnanalyzedCallees,
		Command:                  "kanonarion capability " + coord.String(),
	}
	return out
}

// capabilityLine is the section's one-line text form; the summary and the full
// renderer both print it. A section that follows the call graph names its
// status and points there for the statement.
func capabilityLine(c contextCapability) string {
	switch {
	case c.Status == sectionStatusNotRun:
		return "(not run — see Call Graph)"
	case c.Status == sectionStatusReadError:
		return "(failed — see Call Graph)"
	case c.Status == sectionStatusConflict:
		return "(conflict — see Call Graph)"
	case c.Status == sectionStatusSuperseded:
		return "(superseded — see Call Graph)"
	case c.Status == sectionStatusOtherFrame:
		return "(held under " + strings.Join(c.HeldFrames, ", ") + " — see Call Graph)"
	case c.contextCapabilityAnswer == nil:
		return "(" + c.Error + ")"
	}
	a := c.contextCapabilityAnswer
	shown, _ := splitSuppressed(a.Capabilities)
	return fmt.Sprintf("%d label(s), %d sensitive call(s), %d collect-and-egress, %d init-reaches-both, "+
		"%d unanalysed callee(s) (%s; test roots %s)",
		len(shown), a.SensitiveCallsCount, a.CollectsAndEgressesCount, a.InitReachesBothCount,
		a.UnanalyzedCallees, c.Status, a.TestRoots)
}

// splitSuppressed separates the labels capability's text hides by default
// (the suppressed tier) from the rest; JSON carries both.
func splitSuppressed(labels []string) (shown, hidden []string) {
	for _, l := range labels {
		if capdomain.Capability(l).Tier() == capdomain.TierSuppressed {
			hidden = append(hidden, l)
		} else {
			shown = append(shown, l)
		}
	}
	return shown, hidden
}

// printCapabilityLines prints the section under label, with the per-label row
// counts, the labels hidden as capability hides them, and the command for the
// full record beneath an answer.
func printCapabilityLines(w *errWriter, label, indent string, c contextCapability) {
	w.printf("%s%s\n", label, capabilityLine(c))
	a := c.contextCapabilityAnswer
	if a == nil {
		return
	}
	if a.Caveat != "" {
		w.printf("%scaveat:        %s\n", indent, a.Caveat)
	}
	labels := make([]string, 0, len(a.RowsByCapability))
	for l := range a.RowsByCapability {
		labels = append(labels, l)
	}
	sort.Strings(labels)
	shown, hidden := splitSuppressed(labels)
	if len(shown) > 0 {
		parts := make([]string, 0, len(shown))
		for _, l := range shown {
			parts = append(parts, fmt.Sprintf("%s %d", l, a.RowsByCapability[l]))
		}
		w.printf("%srows:          %s\n", indent, strings.Join(parts, ", "))
	}
	if len(hidden) > 0 {
		w.printf("%shidden:        %d label(s): %s (suppressed by default; --json carries them)\n",
			indent, len(hidden), strings.Join(hidden, ", "))
	}
	w.printf("%sfull record:   %s\n", indent, a.Command)
}
