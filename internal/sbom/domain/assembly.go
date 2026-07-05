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
// by module identity. licensesIncomplete is true when at least one node
// lacked license data.
func AssembleComponents(nodes []ComponentInput) (components []Component, licensesIncomplete bool) {
	components = make([]Component, 0, len(nodes))
	for _, n := range nodes {
		if !n.HasLicense {
			licensesIncomplete = true
		}
		components = append(components, Component{
			Module:    n.Module,
			License:   LicenseClause(n.HasLicense, n.PrimarySPDX, n.Expression),
			Copyright: n.Copyright,
		})
	}
	slices.SortFunc(components, func(a, b Component) int {
		return strings.Compare(a.Module.sortKey(), b.Module.sortKey())
	})
	return components, licensesIncomplete
}

// FindingInput is one vulnerability finding projected to the fields the
// aggregation policy depends on. SeverityLabel is "" when severity is
// unknown or absent.
type FindingInput struct {
	Module        ModuleRef
	ID            string
	Summary       string
	SeverityLabel string
}

// AggregatedVulnerability is the policy decision for a single deduplicated
// vulnerability. Summary and SeverityLabel come from the first occurrence of
// the ID in input order; Affected is the deduplicated, ordered set of
// modules the vulnerability applies to.
type AggregatedVulnerability struct {
	ID            string
	Summary       string
	SeverityLabel string
	Affected      []ModuleRef
}

// AggregateVulnerabilities collapses findings that share an ID into a single
// vulnerability, accumulating affected modules. Summary/severity are taken
// from the first occurrence (input order); affected modules are deduplicated
// and ordered by module identity. The result is ordered by vulnerability ID.
func AggregateVulnerabilities(findings []FindingInput) []AggregatedVulnerability {
	type acc struct {
		v       AggregatedVulnerability
		modKeys map[string]struct{}
	}
	byID := make(map[string]*acc, len(findings))

	for _, f := range findings {
		a, ok := byID[f.ID]
		if !ok {
			a = &acc{
				v: AggregatedVulnerability{
					ID:            f.ID,
					Summary:       f.Summary,
					SeverityLabel: f.SeverityLabel,
				},
				modKeys: make(map[string]struct{}),
			}
			byID[f.ID] = a
		}
		k := f.Module.sortKey()
		if _, dup := a.modKeys[k]; !dup {
			a.modKeys[k] = struct{}{}
			a.v.Affected = append(a.v.Affected, f.Module)
		}
	}

	result := make([]AggregatedVulnerability, 0, len(byID))
	for _, a := range byID {
		slices.SortFunc(a.v.Affected, func(x, y ModuleRef) int {
			return strings.Compare(x.sortKey(), y.sortKey())
		})
		result = append(result, a.v)
	}
	slices.SortFunc(result, func(a, b AggregatedVulnerability) int {
		return strings.Compare(a.ID, b.ID)
	})
	return result
}
