package coordinate

import "sort"

// ModuleSet is a set of module coordinates naming the resolved version set of
// one build — the answer to "which module@version pairs are actually in this
// binary", as opposed to "which ones does the store happen to hold".
//
// The store accumulates every version of every module it has ever analysed, so
// a query keyed on a symbol alone answers across all of them. That is the right
// default for "where has this symbol ever been called", and the wrong answer for
// "is this symbol called in my build": a caller edge from a version the build
// does not contain reads as live when it is dead. A ModuleSet is how a caller
// says which build it means.
//
// The zero value is unrestricted and matches everything, so a caller that has no
// build in mind keeps the historical all-versions behaviour without naming it.
// A set built by NewModuleSet is restricted even when it is empty, because "this
// build contains no modules" is a different statement from "no build was named"
// and must not silently widen back to every version in the store.
type ModuleSet struct {
	restricted bool
	members    map[ModuleCoordinate]struct{}
}

// NewModuleSet returns a restricted set containing exactly coords. Zero
// coordinates are dropped: they name no module, so they can never match a stored
// row, and admitting one as a member would make the set claim membership for a
// module that does not exist.
//
// The result is restricted even when coords is empty or contains only zero
// coordinates — see the type documentation for why that is not the same as the
// zero value.
func NewModuleSet(coords []ModuleCoordinate) ModuleSet {
	members := make(map[ModuleCoordinate]struct{}, len(coords))
	for _, c := range coords {
		if c.IsZero() {
			continue
		}
		members[c] = struct{}{}
	}
	return ModuleSet{restricted: true, members: members}
}

// IsRestricted reports whether the set constrains anything. False for the zero
// value only.
func (s ModuleSet) IsRestricted() bool { return s.restricted }

// Len returns the number of member coordinates. Always 0 for the zero value,
// which is unrestricted rather than empty — test IsRestricted to tell the two
// apart.
func (s ModuleSet) Len() int { return len(s.members) }

// Contains reports whether c is admitted by the set. An unrestricted set admits
// every coordinate including the zero one, since it constrains nothing; a
// restricted set never admits the zero coordinate, which names no module.
func (s ModuleSet) Contains(c ModuleCoordinate) bool {
	if !s.restricted {
		return true
	}
	_, ok := s.members[c]
	return ok
}

// ContainsPathVersion is Contains for a coordinate held as its two raw strings,
// which is the shape rows come back from storage in. An unrestricted set admits
// any pair. A pair that is not a valid coordinate cannot be a member of a
// restricted set, so it is refused rather than validated — a stored row that
// names no module is not a module in the build.
func (s ModuleSet) ContainsPathVersion(path, version string) bool {
	if !s.restricted {
		return true
	}
	_, ok := s.members[ModuleCoordinate{path: path, version: version}]
	return ok
}

// Coordinates returns the members in canonical order (path, then version). The
// result is a fresh slice; mutating it does not affect the set. Callers use it
// for diagnostics that have to name the build they filtered against.
func (s ModuleSet) Coordinates() []ModuleCoordinate {
	out := make([]ModuleCoordinate, 0, len(s.members))
	for c := range s.members {
		out = append(out, c)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].path != out[j].path {
			return out[i].path < out[j].path
		}
		return out[i].version < out[j].version
	})
	return out
}

// HasPath reports whether the set contains any version of path. It answers a
// different question from Contains: "is this module in the build at all",
// which is what a diagnostic needs when it has to explain that a module is
// present at a version other than the one asked about.
//
// An unrestricted set has no members, so it reports true for every path — it
// admits every version of every module.
func (s ModuleSet) HasPath(path string) bool {
	if !s.restricted {
		return true
	}
	for c := range s.members {
		if c.path == path {
			return true
		}
	}
	return false
}

// VersionsOf returns the versions of path held by the set, in ascending string
// order. Empty for a path the set does not contain, and always empty for the
// unrestricted set, which holds no members.
func (s ModuleSet) VersionsOf(path string) []string {
	var out []string
	for c := range s.members {
		if c.path == path {
			out = append(out, c.version)
		}
	}
	sort.Strings(out)
	return out
}
