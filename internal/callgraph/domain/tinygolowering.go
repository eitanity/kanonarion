package domain

import (
	"regexp"
	"slices"
	"strings"
)

// TinyGoLoweringGap is a TinyGo build analysed by a kanonarion with no lowering
// table for its release: the calls TinyGo's compiler inserts were not recorded.
// It is kanonarion's limit, like an analyser limit, so neither the source nor
// the environment is at fault and no cause is filed for it.
type TinyGoLoweringGap struct {
	// Found is the TinyGo release that ran ("0.45.0").
	Found string
	// Covered are the releases the analysing kanonarion's table covers.
	Covered []string
}

// tinyGoLoweringGapClause is Clause's own spelling. Every record that states
// the gap carries it, including those written before it had a reader.
var tinyGoLoweringGapClause = regexp.MustCompile(
	`compiler-inserted runtime calls and the entry points TinyGo exports by name are not recorded: ` +
		`TinyGo ([^ ;]+) is outside kanonarion's lowering table, which covers TinyGo ([^ ;,]+(?:, [^ ;,]+)*)`)

// Clause is the gap as a record's failure detail states it.
func (g TinyGoLoweringGap) Clause() string {
	return "compiler-inserted runtime calls and the entry points TinyGo exports by name are not recorded: TinyGo " +
		g.Found + " is outside kanonarion's lowering table, which covers TinyGo " + strings.Join(g.Covered, ", ")
}

// ReadTinyGoLoweringGap reads the gap out of a record's failure detail.
func ReadTinyGoLoweringGap(detail string) (TinyGoLoweringGap, bool) {
	m := tinyGoLoweringGapClause.FindStringSubmatch(detail)
	if m == nil {
		return TinyGoLoweringGap{}, false
	}
	return TinyGoLoweringGap{Found: m[1], Covered: strings.Split(m[2], ", ")}, true
}

// withoutTinyGoLoweringGap is detail with the gap's clause taken out, so what
// is left is what the load itself reported.
func withoutTinyGoLoweringGap(detail string) string {
	rest := tinyGoLoweringGapClause.ReplaceAllString(detail, "")
	return strings.TrimSuffix(strings.TrimPrefix(rest, "; "), "; ")
}

// tinyGoLoweringReleases are the releases this binary's lowering table covers,
// set by the analyser that owns the table.
var tinyGoLoweringReleases []string

// SetTinyGoLoweringReleases records the releases this binary's lowering table
// covers and returns the restore.
func SetTinyGoLoweringReleases(v []string) (restore func()) {
	prev := tinyGoLoweringReleases
	tinyGoLoweringReleases = slices.Clone(v)
	return func() { tinyGoLoweringReleases = prev }
}

// ClosedByThisBinary reports whether this kanonarion's table covers the release.
func (g TinyGoLoweringGap) ClosedByThisBinary() bool {
	return slices.Contains(tinyGoLoweringReleases, g.Found)
}

// Statement says whose gap it is; the record's detail has already named it.
func (g TinyGoLoweringGap) Statement() string {
	return "The gap is in kanonarion, not in the source or the environment."
}

// Detail names the release that ran and those covered, for a sink.
func (g TinyGoLoweringGap) Detail() string {
	return "TinyGo " + g.Found + " ran; the kanonarion that analysed it has lowering tables for TinyGo " + strings.Join(g.Covered, ", ")
}

// Sink is the gap as the soundness sink of an answer read over the record at site.
func (g TinyGoLoweringGap) Sink(site string) SoundnessSink {
	return SoundnessSink{Kind: SinkTinyGoLoweringUnrecorded, Site: site, Detail: g.Detail()}
}

// Remedy names what closes the gap.
func (g TinyGoLoweringGap) Remedy() string {
	return "Use a kanonarion whose lowering table covers TinyGo " + g.Found +
		": a newer release, or `go install code.eitanity.com/kanonarion@latest`. A covered tinygo (" +
		strings.Join(g.Covered, ", ") + ") first on PATH also closes it, and the record then describes that release's build."
}
