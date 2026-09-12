package domain

import (
	"errors"
	"fmt"
	"sort"
	"strings"
)

// ForeignModule names a module OTHER than the analysed one whose packages this
// analysis built with bodies, at the version resolution gave it.
//
// It exists because target selection for the syntax load is deliberately not the
// membership rule. Selection admits every package whose import path lies under
// the analysed module's path, and Go module paths NEST — cloud.google.com/go and
// cloud.google.com/go/auth are separately published, separately versioned
// modules — so a record routinely holds another module's code, built with real
// bodies rather than types alone. Node attribution already says which module each
// node came from; what was missing is the record saying it holds them at all,
// while claiming BUILT_WITH_BODIES uniformly.
//
// The version is the point of the pair. The parent record names its own
// coordinate and nothing else, so a route through a nested module's nodes was a
// route through a version nobody stated. It is whatever the loader resolved for
// that build, which is not necessarily what the nested module's own record was
// analysed at.
//
// An empty Version means resolution named none — a replaced or otherwise
// unversioned module. That is a statement, not a gap to fill in with a guess.
type ForeignModule struct {
	Path    string
	Version string
}

// String renders the pair the way a coordinate is written, and says so in words
// when resolution named no version rather than rendering a bare "@".
func (f ForeignModule) String() string {
	if f.Version == "" {
		return f.Path + " (no version resolved)"
	}
	return f.Path + "@" + f.Version
}

// ForeignModuleLess is the canonical ordering for ForeignModule slices. Path
// leads; Version follows, so one module path resolved at two versions in one
// analysis still has a defined order.
func ForeignModuleLess(a, b ForeignModule) bool {
	if a.Path != b.Path {
		return a.Path < b.Path
	}
	return a.Version < b.Version
}

// ForeignModuleOwning returns the foreign module in mods that owns the node or
// type identified by id, and whether one does.
//
// Identity is by import-path prefix, which is exact here rather than the guess
// it is in membership: mods holds module paths the LOADER named, so a match says
// the analysis itself placed that package in that module. A node ID is
// "<package>.<symbol>" or "<package>.(<recv>).<method>", so a package belongs to
// module M exactly when the ID continues M with "." (M's own root package) or
// "/" (a package under it).
func ForeignModuleOwning(mods []ForeignModule, id string) (ForeignModule, bool) {
	for _, m := range mods {
		if m.Path == "" || !strings.HasPrefix(id, m.Path) {
			continue
		}
		if rest := id[len(m.Path):]; strings.HasPrefix(rest, ".") || strings.HasPrefix(rest, "/") {
			return m, true
		}
	}
	return ForeignModule{}, false
}

// foreignModuleColumnSeparator joins the pairs in the denormalised column.
// A module path and a version can each contain neither a space nor an "@", so
// the rendering below is unambiguous without quoting.
const foreignModuleColumnSeparator = " "

// ForeignModulesColumn renders a record's foreign-module set for the
// denormalised column beside it, sorted, as space-separated "path@version".
//
// The column exists so a query can qualify its answer without decompressing and
// decoding the record — the same job completeness, node_count and edge_count
// already do from their own columns. The blob stays authoritative: this is a
// copy, written in the same transaction as the blob it copies, and nothing reads
// it to decide what a record IS.
//
// A module resolution gave no version renders with the "@" and nothing after it.
// That keeps every entry one shape, so the reader splits on the last "@" and
// gets an empty version rather than having to tell two renderings apart.
//
// The empty string is the empty set, and it is the only thing it is. Rows
// written before the column existed are back-filled from their own blobs, so
// there is no unrecorded third state here for a reader to ladder against — the
// record's SchemaVersion is where "predates the field" is still readable.
func ForeignModulesColumn(mods []ForeignModule) string {
	if len(mods) == 0 {
		return ""
	}
	ordered := append([]ForeignModule(nil), mods...)
	sort.Slice(ordered, func(i, j int) bool { return ForeignModuleLess(ordered[i], ordered[j]) })
	parts := make([]string, 0, len(ordered))
	for _, m := range ordered {
		if m.Path == "" {
			continue
		}
		parts = append(parts, m.Path+"@"+m.Version)
	}
	if len(parts) == 0 {
		return ""
	}
	return strings.Join(parts, foreignModuleColumnSeparator)
}

// ErrMalformedForeignModulesColumn is returned for a stored value that is not
// what ForeignModulesColumn writes.
var ErrMalformedForeignModulesColumn = errors.New("malformed foreign modules column value")

// ParseForeignModulesColumn reads back what ForeignModulesColumn wrote.
//
// An entry it does not understand is an ERROR rather than an absence, on the
// same terms as the analyser column: only the write leg and the back-fill write
// here, both write this shape, and a third value can only be a hand-edited row.
// Reading one as "no foreign modules" would answer a query with a qualification
// the store is carrying but could not parse — silently, which is the failure
// mode the whole axis exists to remove.
func ParseForeignModulesColumn(s string) ([]ForeignModule, error) {
	if s == "" {
		return nil, nil
	}
	fields := strings.Split(s, foreignModuleColumnSeparator)
	out := make([]ForeignModule, 0, len(fields))
	for _, f := range fields {
		at := strings.LastIndex(f, "@")
		if at <= 0 {
			return nil, fmt.Errorf("%w: entry %q is not \"path@version\"", ErrMalformedForeignModulesColumn, f)
		}
		out = append(out, ForeignModule{Path: f[:at], Version: f[at+1:]})
	}
	sort.Slice(out, func(i, j int) bool { return ForeignModuleLess(out[i], out[j]) })
	return out, nil
}
