package domain

import "sort"

// CompatibilityDataVersion identifies the version of the static compatibility
// dataset. Bump deliberately when a new license pair is researched and added.
const CompatibilityDataVersion = "1.0.0"

// CopyleftStrength describes the copyleft obligations imposed by a license.
type CopyleftStrength int

const (
	// CopyleftNone means the license imposes no copyleft obligations (permissive).
	CopyleftNone CopyleftStrength = iota
	// CopyleftWeak means file- or library-level copyleft; linking into a larger
	// work under a different license is permitted (e.g. MPL-2.0, LGPL).
	CopyleftWeak
	// CopyleftStrong means the combined work must be distributed under the same
	// license (e.g. GPL-2.0-only, GPL-3.0-only).
	CopyleftStrong
	// CopyleftNetwork means strong copyleft plus a network-use trigger: using the
	// software over a network counts as distribution (e.g. AGPL-3.0-only).
	CopyleftNetwork
)

// String returns the human-readable name of the copyleft strength.
func (s CopyleftStrength) String() string {
	switch s {
	case CopyleftNone:
		return "none"
	case CopyleftWeak:
		return "weak"
	case CopyleftStrong:
		return "strong"
	case CopyleftNetwork:
		return "network"
	default:
		return "unknown"
	}
}

// CompatibilityVerdict is the result of evaluating a dep license against a
// target distribution license.
type CompatibilityVerdict int

const (
	// VerdictCompatible means the dep license is compatible with distributing the
	// combined work under the target license.
	VerdictCompatible CompatibilityVerdict = iota
	// VerdictIncompatible means the dep's copyleft obligations conflict with the
	// target license; redistribution of the combined work is not permitted.
	VerdictIncompatible
	// VerdictUnknownPair means the dep or target license is not in the modelled
	// dataset. Per this is never treated as compatible — it requires
	// human review.
	VerdictUnknownPair
)

// String returns the human-readable name of the verdict.
func (v CompatibilityVerdict) String() string {
	switch v {
	case VerdictCompatible:
		return "compatible"
	case VerdictIncompatible:
		return "incompatible"
	case VerdictUnknownPair:
		return "unknown_pair"
	default:
		return "unknown"
	}
}

// ConflictKind classifies why two licenses conflict.
type ConflictKind int

const (
	// ConflictPairIncompatible means the dep/target pair is explicitly
	// incompatible (e.g. GPL-2.0-only vs Apache-2.0).
	ConflictPairIncompatible ConflictKind = iota + 1
	// ConflictCopyleftPropagation means the dep's strong copyleft propagates to
	// the combined work, preventing distribution under the permissive target.
	ConflictCopyleftPropagation
	// ConflictNetworkTrigger means the dep's network-use copyleft trigger applies
	// (e.g. AGPL-3.0-only) and the combined work cannot be distributed under the
	// permissive target.
	ConflictNetworkTrigger
	// ConflictUnknownPair means one or both licenses are not in the dataset;
	// human review is required.
	ConflictUnknownPair
)

// String returns the human-readable name of the conflict kind.
func (k ConflictKind) String() string {
	switch k {
	case ConflictPairIncompatible:
		return "pair_incompatible"
	case ConflictCopyleftPropagation:
		return "copyleft_propagation"
	case ConflictNetworkTrigger:
		return "network_trigger"
	case ConflictUnknownPair:
		return "unknown_pair"
	default:
		return "unknown"
	}
}

// CompatibilityConflict records a concrete conflict between a dep license and
// the target distribution license.
type CompatibilityConflict struct {
	ModulePath    string
	ModuleVersion string
	DepSPDX       string
	TargetSPDX    string
	Verdict       CompatibilityVerdict
	Kind          ConflictKind
}

// CompatibilityInput describes a single module's resolved license for
// compatibility checking.
type CompatibilityInput struct {
	ModulePath    string
	ModuleVersion string
	SPDX          string // empty when the module has no detected license
}

// ClosureCompatibilityReport is the result of checking all dependencies in a
// closure against a target distribution license.
type ClosureCompatibilityReport struct {
	TargetSPDX  string
	DataVersion string
	// Conflicts lists every dep that is incompatible with or unmodelled against
	// the target license. Sorted by ModulePath then ModuleVersion for
	// determinism.
	Conflicts []CompatibilityConflict
	// Clean reports whether the entire closure is compatible (no conflicts and no
	// unknown pairs).
	Clean bool
}

// copyleftStrengths maps known SPDX identifiers to their copyleft strength.
// Only identifiers in this map are "known" to the engine; anything else
// produces VerdictUnknownPair per.
var copyleftStrengths = map[string]CopyleftStrength{
	// Permissive — CopyleftNone
	"Apache-2.0":    CopyleftNone,
	"MIT":           CopyleftNone,
	"BSD-2-Clause":  CopyleftNone,
	"BSD-3-Clause":  CopyleftNone,
	"ISC":           CopyleftNone,
	"Zlib":          CopyleftNone,
	"0BSD":          CopyleftNone,
	"Unlicense":     CopyleftNone,
	"CC0-1.0":       CopyleftNone,
	"BlueOak-1.0.0": CopyleftNone,
	"BSD-4-Clause":  CopyleftNone,

	// Weak copyleft — file/library-level, linking permitted
	"MPL-2.0":           CopyleftWeak,
	"LGPL-2.0-only":     CopyleftWeak,
	"LGPL-2.0-or-later": CopyleftWeak,
	"LGPL-2.1-only":     CopyleftWeak,
	"LGPL-2.1-or-later": CopyleftWeak,
	"LGPL-3.0-only":     CopyleftWeak,
	"LGPL-3.0-or-later": CopyleftWeak,
	"EPL-1.0":           CopyleftWeak,
	"EPL-2.0":           CopyleftWeak,
	"EUPL-1.2":          CopyleftWeak,
	"CDDL-1.0":          CopyleftWeak,

	// Strong copyleft — combined work must use same license
	"GPL-2.0-only":     CopyleftStrong,
	"GPL-2.0-or-later": CopyleftStrong,
	"GPL-3.0-only":     CopyleftStrong,
	"GPL-3.0-or-later": CopyleftStrong,
	"EUPL-1.1":         CopyleftStrong,

	// Network copyleft — strong copyleft + network-use trigger
	"AGPL-3.0-only":     CopyleftNetwork,
	"AGPL-3.0-or-later": CopyleftNetwork,
	"OSL-3.0":           CopyleftNetwork,

	// Proprietary / source-available — incompatible with open distribution
	"BUSL-1.1":    CopyleftStrong, // Business Source License: strong restriction, modelled as strong copyleft for compat purposes
	"SSPL-1.0":    CopyleftStrong,
	"Elastic-2.0": CopyleftStrong,
}

// permissiveTargets is the set of known target licenses that are permissive
// (CopyleftNone). A dep with any copyleft strength > CopyleftNone is
// incompatible with these targets for binary redistribution.
var permissiveTargets = map[string]struct{}{
	"Apache-2.0":   {},
	"MIT":          {},
	"BSD-2-Clause": {},
	"BSD-3-Clause": {},
	"ISC":          {},
	"0BSD":         {},
}

// CopyleftStrengthOf returns the copyleft strength for a known SPDX identifier.
// If the identifier is not in the dataset, the second return value is false.
func CopyleftStrengthOf(spdx string) (CopyleftStrength, bool) {
	s, ok := copyleftStrengths[spdx]
	return s, ok
}

// CheckPairCompatibility evaluates whether a dep licensed under depSPDX is
// compatible with distributing a combined work under targetSPDX.
//
// Per if either identifier is not in the modelled dataset the result
// is VerdictUnknownPair, never VerdictCompatible.
func CheckPairCompatibility(depSPDX, targetSPDX string) CompatibilityVerdict {
	depStrength, depKnown := CopyleftStrengthOf(depSPDX)
	_, targetKnown := CopyleftStrengthOf(targetSPDX)

	if !depKnown || !targetKnown {
		return VerdictUnknownPair
	}

	// Permissive deps are always compatible.
	if depStrength == CopyleftNone {
		return VerdictCompatible
	}

	_, targetPermissive := permissiveTargets[targetSPDX]

	// Weak copyleft (MPL, LGPL) is compatible with permissive targets via
	// dynamic linking; Go static compilation is a nuance but FSF guidance
	// treats LGPL as compatible via the "work that uses the library" clause.
	if depStrength == CopyleftWeak {
		return VerdictCompatible
	}

	// Strong and network copyleft cannot be distributed under permissive targets.
	if targetPermissive {
		return VerdictIncompatible
	}

	// Both dep and target are copyleft. Same-license is compatible; cross-family
	// pairs (other than the GPL-2→GPL-3 case below) are deliberately reported
	// as VerdictUnknownPair per — kanonarion surfaces uncertainty
	// rather than guess a legal verdict.
	if depSPDX == targetSPDX {
		return VerdictCompatible
	}
	// GPL-3 subsumes GPL-2: GPL-2-or-later code can be used under GPL-3.
	if targetSPDX == "GPL-3.0-only" || targetSPDX == "GPL-3.0-or-later" {
		if depSPDX == "GPL-2.0-or-later" {
			return VerdictCompatible
		}
	}
	// For other copyleft/copyleft pairings, flag as unknown to require review.
	return VerdictUnknownPair
}

// conflictKindFor derives the ConflictKind for a known-incompatible dep/target pair.
func conflictKindFor(depSPDX string) ConflictKind {
	strength, _ := CopyleftStrengthOf(depSPDX)
	switch strength {
	case CopyleftNetwork:
		return ConflictNetworkTrigger
	case CopyleftStrong:
		return ConflictCopyleftPropagation
	default:
		return ConflictPairIncompatible
	}
}

// CheckClosureCompatibility evaluates each module in modules against the target
// distribution license and returns a ClosureCompatibilityReport.
//
// Modules with an empty SPDX are treated as unmodelled (VerdictUnknownPair).
// The Conflicts slice in the result is sorted by ModulePath then ModuleVersion.
func CheckClosureCompatibility(modules []CompatibilityInput, targetSPDX string) ClosureCompatibilityReport {
	report := ClosureCompatibilityReport{
		TargetSPDX:  targetSPDX,
		DataVersion: CompatibilityDataVersion,
	}

	for _, m := range modules {
		spdx := m.SPDX
		if spdx == "" {
			report.Conflicts = append(report.Conflicts, CompatibilityConflict{
				ModulePath:    m.ModulePath,
				ModuleVersion: m.ModuleVersion,
				DepSPDX:       "",
				TargetSPDX:    targetSPDX,
				Verdict:       VerdictUnknownPair,
				Kind:          ConflictUnknownPair,
			})
			continue
		}

		verdict := CheckPairCompatibility(spdx, targetSPDX)
		if verdict == VerdictCompatible {
			continue
		}

		kind := ConflictUnknownPair
		if verdict == VerdictIncompatible {
			kind = conflictKindFor(spdx)
		}

		report.Conflicts = append(report.Conflicts, CompatibilityConflict{
			ModulePath:    m.ModulePath,
			ModuleVersion: m.ModuleVersion,
			DepSPDX:       spdx,
			TargetSPDX:    targetSPDX,
			Verdict:       verdict,
			Kind:          kind,
		})
	}

	sort.Slice(report.Conflicts, func(i, j int) bool {
		a, b := report.Conflicts[i], report.Conflicts[j]
		if a.ModulePath != b.ModulePath {
			return a.ModulePath < b.ModulePath
		}
		return a.ModuleVersion < b.ModuleVersion
	})

	report.Clean = len(report.Conflicts) == 0
	return report
}
