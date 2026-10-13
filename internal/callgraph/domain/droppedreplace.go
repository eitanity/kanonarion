package domain

import (
	"sort"
	"strconv"
	"strings"
)

// DroppedReplace names one replace directive an analysis removed from an
// extracted module's own go.mod before loading it.
//
// It exists for the reason SynthesisedGoMod exists: the tree that was analysed
// is not the tree that was published, and a record that does not say so is
// claiming more than it read. Where SynthesisedGoMod records a file kanonarion
// WROTE, this records a directive kanonarion REMOVED, and both are the same
// statement about the same divergence.
//
// Two kinds of filesystem replace are removed, both dead weight in a published
// artefact: the go command ignores a replace in any module that is not the MAIN
// module, so no consumer's build has ever applied one, and the analysis is the
// first context in which the module IS the main module. One targets a directory
// OUTSIDE the extracted tree — a monorepo's sibling checkout, "replace
// example.com/mod/a => ../a/". The other targets an absent directory inside it
// and replaces a nested module of this module — "replace example.com/mod/a =>
// ./a" — which the zip format leaves out of the parent's zip by construction.
// Either way the requirement dangles here and resolves for every consumer.
//
// Every other replace is left alone. One pointing at a directory inside the tree
// that exists resolves exactly as published; one pointing at an absent directory
// for any other module is the module's own fault, and the go command's message
// says so; one pointing at a MODULE VERSION resolves without a filesystem.
//
// The zero value — an empty list — means nothing was dropped. That is
// unambiguous rather than merely absent: no analysis removed a directive before
// this field existed, so no stored record can be one that did.
type DroppedReplace struct {
	// Path is the module path on the left of the arrow.
	Path string
	// Version is the version on the left, empty when the directive replaced every
	// version of Path — which is the ordinary form.
	Version string
	// Target is the filesystem path on the right of the arrow, verbatim as the
	// module published it. It is kept because it is the evidence: "../credentials/"
	// is visibly a sibling checkout of a monorepo, and a reader can see that no
	// published artefact could ever contain it.
	Target string
}

// String renders the directive as the module wrote it.
func (d DroppedReplace) String() string {
	left := d.Path
	if d.Version != "" {
		left += " " + d.Version
	}
	return left + " => " + d.Target
}

// DroppedReplaceLess orders two dropped directives by path then version, so a
// record's list is stable across runs and its content hash is a function of what
// was dropped rather than of map iteration order.
func DroppedReplaceLess(a, b DroppedReplace) bool {
	if a.Path != b.Path {
		return a.Path < b.Path
	}
	if a.Version != b.Version {
		return a.Version < b.Version
	}
	return a.Target < b.Target
}

// SortDroppedReplaces orders a list in place.
func SortDroppedReplaces(ds []DroppedReplace) {
	sort.Slice(ds, func(i, j int) bool { return DroppedReplaceLess(ds[i], ds[j]) })
}

// DroppedReplacesSummary renders the intervention for a human reading a record's
// provenance, returning the empty string when nothing was dropped so a caller can
// append it unconditionally.
//
// Every directive is named. The count alone would leave a reader unable to tell
// whether the analysed build list is the one the module declares, and the list is
// short by construction — it is bounded by what one go.mod holds.
func DroppedReplacesSummary(ds []DroppedReplace) string {
	if len(ds) == 0 {
		return ""
	}
	out := strconv.Itoa(len(ds)) + " replace directive"
	if len(ds) != 1 {
		out += "s"
	}
	rendered := make([]string, 0, len(ds))
	for _, d := range ds {
		rendered = append(rendered, d.String())
	}
	return out + " dropped, each targeting a directory outside the published zip " +
		"and applied by no consumer's build: " + strings.Join(rendered, "; ")
}
