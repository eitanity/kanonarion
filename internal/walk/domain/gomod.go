package domain

import (
	fetchdomain "github.com/eitanity/kanonarion/internal/fetch/domain"
	"golang.org/x/mod/semver"
)

// PrePruning reports whether a go.mod's declared go version predates
// module-graph pruning (go < 1.17). A pre-pruning module forces the toolchain
// to load its full transitive requirement subgraph — including the go.mod of
// versions MVS ultimately discards — so a graph that contains one cannot build
// its module graph offline unless those superseded go.mod files are present.
// An absent or unparseable version is treated as pre-pruning: such modules do
// not record their full requirements, so the toolchain must expand them.
func PrePruning(goVersion string) bool {
	if goVersion == "" {
		return true
	}
	canonical := semver.Canonical("v" + goVersion)
	if canonical == "" {
		return true
	}
	return semver.Compare(canonical, "v1.17.0") < 0
}

// ParsedGoMod is the structured representation of a parsed go.mod file.
// It is a value object: GoModParser produces it, GraphResolver consumes it.
type ParsedGoMod struct {
	// ModulePath is the module path declared in the module directive.
	ModulePath string
	// GoVersion is the minimum Go version declared (e.g. "1.21").
	GoVersion string
	// Toolchain is the toolchain directive value, if present (e.g. "go1.21.0").
	Toolchain string
	// Require contains all require directives (direct and indirect).
	Require []Requirement
	// Replace contains all replace directives.
	Replace []Replacement
	// Exclude contains all exclude directives.
	Exclude []Exclusion
	// Retract contains all retract directives.
	Retract []RetractRange
	// Tools contains the module paths listed in tool directives (Go 1.24+).
	// Versions are not stored here; cross-reference with Require to resolve them.
	Tools []string
}

// Requirement is a single require directive entry.
type Requirement struct {
	Coordinate fetchdomain.ModuleCoordinate
	// Indirect is true when the entry is marked // indirect in go.mod.
	Indirect bool
}

// Replacement is a single replace directive entry.
//
// OldVersion may be empty, meaning the replacement applies to all versions of OldPath.
// When IsLocal is true, NewCoordinate is the zero value and LocalPath holds the
// directory path. Local replacements are recorded but not followed during resolution.
type Replacement struct {
	OldPath    string
	OldVersion string
	IsLocal    bool
	LocalPath  string
	// NewCoordinate is the replacement module coordinate. Zero when IsLocal is true.
	NewCoordinate fetchdomain.ModuleCoordinate
}

// Exclusion is a single exclude directive entry.
type Exclusion struct {
	Coordinate fetchdomain.ModuleCoordinate
}

// RetractRange is a single retract directive entry covering a version range.
// When a single version is retracted, Low == High.
type RetractRange struct {
	Low       string
	High      string
	Rationale string
}
