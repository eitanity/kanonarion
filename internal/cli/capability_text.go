package cli

import (
	"fmt"
	"io"
	"strings"

	"github.com/eitanity/kanonarion/internal/coordinate"

	cgdomain "github.com/eitanity/kanonarion/internal/callgraph/domain"
	capdomain "github.com/eitanity/kanonarion/internal/capability/domain"
)

// capabilityShowSuppressedFlagName reveals what text hides by default. JSON
// always carries everything, each entry marked "suppressed".
const capabilityShowSuppressedFlagName = "show-suppressed"

// textLines accumulates a rendering so it is written, and its error checked,
// once.
type textLines struct{ b strings.Builder }

func (t *textLines) add(format string, args ...any) {
	fmt.Fprintf(&t.b, format, args...)
	t.b.WriteByte('\n')
}

func (t *textLines) writeTo(w io.Writer, what string) error {
	if _, err := io.WriteString(w, t.b.String()); err != nil {
		return fmt.Errorf("writing %s: %w", what, err)
	}
	return nil
}

func printCapabilityReport(stdout io.Writer, coord coordinate.ModuleCoordinate, r capdomain.CapabilityReport, scope cgdomain.RootScope, showSuppressed bool, rec cgdomain.CallGraphRecord) error {
	var t textLines
	t.add("%s@%s capabilities:", coord.Path(), coord.Version())
	t.b.WriteString(recordFrameLine(rec))
	t.add("  %s", capabilityRootScopeLine(scope))
	if r.Partial {
		t.add("  ⚠ %s", r.Caveat)
	}
	if len(r.Findings) == 0 {
		t.add("  (no sensitive capabilities witnessed)")
	}
	hidden := 0
	for _, f := range r.Findings {
		if f.Suppressed() && !showSuppressed {
			hidden++
			continue
		}
		addCapabilityFinding(&t, f, "  ")
	}
	if hidden > 0 {
		t.add("  %s hidden: %s is suppressed by default (--%s shows it)",
			countOf(hidden, "findings"), capdomain.CapabilityRuntimeInternal, capabilityShowSuppressedFlagName)
	}
	addSensitiveCalls(&t, r.SensitiveCalls)
	addCoLocation(&t, "", r.CollectsAndEgresses, r.InitReachesBoth)
	addUnanalyzed(&t, r)
	if len(r.Observations) > 0 {
		t.add("  not capabilities of this module — what the path establishes instead:")
		for _, f := range r.Observations {
			addCapabilityFinding(&t, f, "    ")
		}
	}
	return t.writeTo(stdout, "capability report")
}

// addCapabilityFinding renders one finding; a basis other than use adds the
// line saying what the path proved instead, so the label is never read alone.
func addCapabilityFinding(t *textLines, f capdomain.CapabilityFinding, indent string) {
	marks := ""
	if f.PlumbingOnly && f.Basis == capdomain.BasisUse {
		marks += "  plumbing-only"
	}
	if f.ClassifiedBy == capdomain.ClassifiedByPackageDefault {
		marks += "  (package default)"
	}
	t.add("%s%-16s [%s]  [%s]  %s  via %s.%s%s", indent, string(f.Capability), string(f.WeakestConfidence),
		string(f.CallerKind), string(f.Reach), f.SinkPackage, f.SinkSymbol, marks)
	if note := f.Basis.Explanation(); note != "" {
		t.add("%s  %s", indent, note)
	}
	t.add("%s  path: %s", indent, strings.Join(f.Path, " → "))
}

func addSensitiveCalls(t *textLines, calls []capdomain.SensitiveCall) {
	if len(calls) == 0 {
		t.add("  sensitive calls: none (no exported sensitive function called over a Direct edge)")
		return
	}
	t.add("  sensitive calls (%d): exported sensitive functions called over at least one Direct edge", len(calls))
	for _, c := range calls {
		t.add("    %s", sensitiveCallLine(c))
	}
}

func sensitiveCallLine(c capdomain.SensitiveCall) string {
	kinds := make([]string, 0, len(c.CallerKinds))
	for _, k := range c.CallerKinds {
		kinds = append(kinds, string(k))
	}
	return fmt.Sprintf("%-14s %s  from %s (%s)", string(c.Capability), c.Callee,
		strings.Join(kinds, ", "), countOf(c.Callers, "callers"))
}

func coLocationLine(c capdomain.CoLocation) string {
	return fmt.Sprintf("collects and egresses: %s [%s]  collects %s; egresses %s",
		c.Function, c.CallerKind, strings.Join(c.Collection, ", "), strings.Join(c.Egress, ", "))
}

func initReachLine(r capdomain.InitReach) string {
	return fmt.Sprintf("init reaches both: %s [%s] at depth %d  (%s at %d, %s at %d, over Direct edges)",
		r.Init, r.CallerKind, r.Depth, r.Collection, r.CollectionDepth, r.Egress, r.EgressDepth)
}

// addCoLocation prints both co-location facts, each prefixed with sign ("" on
// a report, "+ " or "- " in a diff).
func addCoLocation(t *textLines, sign string, cs []capdomain.CoLocation, rs []capdomain.InitReach) {
	if sign == "" {
		if len(cs) == 0 && len(rs) == 0 {
			t.add("  co-location: no function collects and egresses, and no initialiser reaches both")
			return
		}
		t.add("  co-location (%d):", len(cs)+len(rs))
	}
	for _, c := range cs {
		t.add("    %s%s", sign, coLocationLine(c))
	}
	for _, r := range rs {
		t.add("    %s%s", sign, initReachLine(r))
	}
}

func addUnanalyzed(t *textLines, r capdomain.CapabilityReport) {
	if len(r.Unanalyzed) > 0 {
		t.add("  unanalysed bodies (%d): this module's own assembly or //go:linkname functions; the graph cannot see what they do",
			len(r.Unanalyzed))
		for _, id := range r.Unanalyzed {
			t.add("    %s", id)
		}
	}
	if r.UnanalyzedCallees > 0 {
		t.add("  unanalysed callees: %s with an assembly or //go:linkname body and no capability label",
			countOf(r.UnanalyzedCallees, "external functions"))
	}
	if len(r.PackageDefaults) > 0 {
		parts := make([]string, 0, len(r.PackageDefaults))
		for _, d := range r.PackageDefaults {
			parts = append(parts, fmt.Sprintf("%s %d", d.Package, d.Callees))
		}
		t.add("  package defaults: %s (callees labelled by their package's default, not a named rule)", strings.Join(parts, ", "))
	}
}

func printCapabilityDiff(stdout io.Writer, from, to coordinate.ModuleCoordinate, diff capdomain.CapabilityDiff, scope cgdomain.RootScope, showSuppressed bool, fromRec, toRec cgdomain.CallGraphRecord) error {
	var t textLines
	t.add("capability diff %s@%s → %s@%s:", from.Path(), from.Version(), to.Path(), to.Version())
	// Both sides are read under one frame; a second line only where they state it differently.
	t.b.WriteString(recordFrameLine(fromRec))
	if to := recordFrameLine(toRec); to != recordFrameLine(fromRec) {
		t.b.WriteString(to)
	}
	t.add("  %s", capabilityRootScopeLine(scope))
	if !diff.ParityOK {
		t.add("  ⚠ %s", diff.Caveat)
	}
	if diff.Unchanged() {
		line := "  no change: no row, no sensitive call and no unanalysed body changed; neither version holds a row"
		if diff.ToRows > 0 {
			line = fmt.Sprintf("  no change: no row, no sensitive call and no unanalysed body changed; both versions hold %s",
				countOf(diff.ToRows, "rows"))
		}
		t.add("%s", line)
		return t.writeTo(stdout, "capability diff")
	}
	t.add("  sensitive calls: %d added, %d removed", len(diff.SensitiveAdded), len(diff.SensitiveRemoved))
	for _, c := range diff.SensitiveAdded {
		t.add("    + %s", sensitiveCallLine(c))
	}
	for _, c := range diff.SensitiveRemoved {
		t.add("    - %s", sensitiveCallLine(c))
	}
	t.add("  co-location: %d added, %d removed, %d changed depth",
		len(diff.CollectsAndEgressesAdded)+len(diff.InitReachesBothAdded),
		len(diff.CollectsAndEgressesRemoved)+len(diff.InitReachesBothRemoved),
		len(diff.InitReachesBothDepthChanged))
	addCoLocation(&t, "+ ", diff.CollectsAndEgressesAdded, diff.InitReachesBothAdded)
	addCoLocation(&t, "- ", diff.CollectsAndEgressesRemoved, diff.InitReachesBothRemoved)
	for _, c := range diff.InitReachesBothDepthChanged {
		t.add("    ~ init reaches both: %s [%s] depth %d → %d  (%s, %s)",
			c.To.Init, c.To.CallerKind, c.From.Depth, c.To.Depth, c.To.Collection, c.To.Egress)
	}
	t.add("  unanalysed bodies: %d added, %d removed", len(diff.UnanalyzedAdded), len(diff.UnanalyzedRemoved))
	for _, id := range diff.UnanalyzedAdded {
		t.add("    + %s", id)
	}
	for _, id := range diff.UnanalyzedRemoved {
		t.add("    - %s", id)
	}
	t.add("  capabilities: %s added, %s removed", capabilityList(diff.Added), capabilityList(diff.Removed))
	addRowBlock(&t, "added", "+", diff.RowsAdded, showSuppressed)
	addRowBlock(&t, "removed", "-", diff.RowsRemoved, showSuppressed)
	return t.writeTo(stdout, "capability diff")
}

func capabilityList(caps []capdomain.Capability) string {
	if len(caps) == 0 {
		return "0"
	}
	return fmt.Sprintf("%d (%s)", len(caps), strings.Join(capsToStrings(caps), ", "))
}

// addRowBlock prints one side's rows. The count always covers every row; the
// hidden ones are counted and named, never dropped silently.
func addRowBlock(t *textLines, what, sign string, rows []capdomain.WitnessRow, showSuppressed bool) {
	hidden := 0
	for _, r := range rows {
		if r.Suppressed {
			hidden++
		}
	}
	head := fmt.Sprintf("  rows %s: %d", what, len(rows))
	if hidden > 0 && !showSuppressed {
		head += fmt.Sprintf(" (%d suppressed: runtime internals and unexported plumbing; --%s shows them)",
			hidden, capabilityShowSuppressedFlagName)
	}
	t.add("%s", head)
	for _, g := range capdomain.GroupRows(rows) {
		if g.Suppressed && !showSuppressed {
			continue
		}
		t.add("    %s %s", sign, rowGroupLine(g))
	}
}

func rowGroupLine(g capdomain.RowGroup) string {
	callee := g.Callee
	who := strings.Join(g.Callers, ", ")
	switch {
	case g.BodyFact:
		callee, who = g.Callee+" (own body)", "itself"
	case g.CallerKind.Collapsed():
		who = countOf(len(g.Callers), "callers")
	}
	line := fmt.Sprintf("[%s] %s %s %s  [%s]  %s", g.CallerKind, g.Capability, g.Reach, callee, g.Confidence, who)
	if g.PlumbingOnly {
		line += "  plumbing-only"
	}
	return line
}
