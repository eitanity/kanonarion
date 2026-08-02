package domain

import (
	"slices"
	"strings"
)

// ModuleRef is the module identity the SBOM assembly policy operates on.
// PURL formatting and CycloneDX mapping are serialization concerns owned by
// the generator adapter, not by this policy.
type ModuleRef struct {
	Path    string
	Version string
}

func (m ModuleRef) sortKey() string { return m.Path + "@" + m.Version }

// LicenseClause applies the license-attachment policy: a license is only
// recorded when license data is present. Returns the SPDX expression (or id)
// to attach, or "" for no license clause. Expression takes precedence over
// primarySPDX when present.
func LicenseClause(hasLicense bool, primarySPDX, expression string) string {
	if !hasLicense {
		return ""
	}
	if expression != "" {
		return expression
	}
	return primarySPDX
}

// ComponentInput is one walk-graph node projected to the fields the
// component-assembly policy depends on.
type ComponentInput struct {
	Module      ModuleRef
	HasLicense  bool
	PrimarySPDX string
	Expression  string // SPDX expression; preferred over PrimarySPDX when non-empty
	Copyright   string // pre-formatted attribution string; "" when absent or not analysed
}

// Component is the policy decision for a single SBOM component: which module
// it is and the SPDX license to attach ("" for none).
type Component struct {
	Module    ModuleRef
	License   string
	Copyright string // "" when absent; omit from SBOM when empty
}

// AssembleComponents applies the SBOM component policy: one component per
// graph node, license attached per LicenseClause, ordered deterministically
// by module identity.
//
// undetermined names every component the document will carry with no license
// identity on it, in the same order as components. The test is what the
// document ends up saying, not whether a license record was found: an
// extraction that ran, read the module and could identify nothing — no license
// file at the root, or files that match no known SPDX text — writes a record
// whose expression is empty, and a component built from it carries no licenses
// block at all. Counting that as complete because a row exists reports the
// extraction's coverage where a reader is asking about the artefact's licensing,
// and publishes an undetermined license as an absent question.
func AssembleComponents(nodes []ComponentInput) (components []Component, undetermined []ModuleRef) {
	components = make([]Component, 0, len(nodes))
	for _, n := range nodes {
		components = append(components, Component{
			Module:    n.Module,
			License:   LicenseClause(n.HasLicense, n.PrimarySPDX, n.Expression),
			Copyright: n.Copyright,
		})
	}
	slices.SortFunc(components, func(a, b Component) int {
		return strings.Compare(a.Module.sortKey(), b.Module.sortKey())
	})
	for _, c := range components {
		if c.License == "" {
			undetermined = append(undetermined, c.Module)
		}
	}
	return components, undetermined
}
