package domain

import (
	"sort"
	"strings"
)

// CompatibilityDataVersion identifies the version of the static compatibility
// dataset. Bump deliberately when a new license pair is researched and added.
const CompatibilityDataVersion = "1.1.0"

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
	// VerdictElectable means the dep is dual-licensed (a disjunctive SPDX
	// expression) and at least one arm is compatible with the target: the
	// combined work is compatible IF that arm is elected. The election is a
	// human decision recorded via the license_overrides mechanism, never
	// resolved silently by the tool, so this verdict is surfaced as an open
	// item rather than folded into compatible or incompatible.
	VerdictElectable
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
	case VerdictElectable:
		return "electable"
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
	// ConflictElectionRequired means the dep offers a licence election
	// (disjunctive expression) with at least one compatible arm; the operator
	// must record which arm is elected (license_overrides) before the answer
	// can settle to compatible.
	ConflictElectionRequired
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
	case ConflictElectionRequired:
		return "election_required"
	default:
		return "unknown"
	}
}

// LicenceOrigin says whose licence an identifier under evaluation is. A module
// contributes its own root licence AND the licences of the components it
// bundles, and both bind a redistributor — but only one of them is "the
// module's licence", which is what every other surface reports. Carrying the
// origin is what keeps a bundled component's identifier from reading as the
// module's own.
type LicenceOrigin int

const (
	// OriginModuleRoot means the identifier came from the module's own
	// root-level licence files — the licence every other surface reports for
	// the module. It is the zero value: an input carrying no component
	// attribution is the module's own licence, which is the honest reading for
	// entries built before components were distinguished.
	OriginModuleRoot LicenceOrigin = iota
	// OriginBundledComponent means the identifier came from a third-party
	// component bundled inside the module (a vendor/ tree, a
	// THIRD_PARTY_LICENSES directory). The obligation is real; the licence is
	// not the module's.
	OriginBundledComponent
)

// String returns the wire name of the origin.
func (o LicenceOrigin) String() string {
	if o == OriginBundledComponent {
		return "bundled_component"
	}
	return "module_root"
}

// CompatibilityConflict records a concrete conflict between a dep license and
// the target distribution license.
type CompatibilityConflict struct {
	ModulePath    string
	ModuleVersion string
	// DepSPDX is the identifier that was EVALUATED. It is the module's own
	// licence only when Origin is OriginModuleRoot; when the identifier was
	// attributed to a bundled component it is that component's licence, and
	// Origin/OriginPath say so. ModuleExpression always carries the module's
	// own licence, so a consumer can recover it without re-reading the record.
	DepSPDX    string
	TargetSPDX string
	Verdict    CompatibilityVerdict
	Kind       ConflictKind
	// Origin says whose licence DepSPDX is.
	Origin LicenceOrigin
	// OriginPath names the bundled component's path prefix within the module,
	// comma-separated when one identifier was found under several. Empty for
	// OriginModuleRoot.
	OriginPath string
	// ModuleExpression is the module's OWN licence expression, reported whole:
	// a conjunction such as "Apache-2.0 AND CC-BY-SA-4.0" appears in full with
	// DepSPDX naming the arm that raised this entry, never reduced to that arm.
	// Empty only when the module has no licence expression at all.
	ModuleExpression string
	// ElectableArms lists the arms of a dual-licence disjunction that are
	// individually compatible with the target. Populated only for
	// VerdictElectable, where DepSPDX carries the full disjunction.
	ElectableArms []string
}

// CompatibilityInput describes a single module's resolved license for
// compatibility checking.
type CompatibilityInput struct {
	ModulePath    string
	ModuleVersion string
	SPDX          string // empty when the module has no detected license
	// ElectiveArms carries the arms of a purely disjunctive licence expression
	// (a dual-licensed module: the consumer elects ONE arm). When it holds two
	// or more arms the engine evaluates each arm as a candidate election and
	// SPDX is ignored; otherwise SPDX is evaluated as a single licence that
	// applies unconditionally.
	ElectiveArms []string
	// Origin, OriginPath and ModuleExpression carry the attribution through to
	// the conflict entry unchanged; see CompatibilityConflict for what each
	// means.
	Origin           LicenceOrigin
	OriginPath       string
	ModuleExpression string
}

// ClosureCompatibilityReport is the result of checking all dependencies in a
// closure against a target distribution license.
type ClosureCompatibilityReport struct {
	TargetSPDX  string
	DataVersion string
	// Conflicts lists every dep whose answer is not settled compatible: pairs
	// that are incompatible, unmodelled against the target license, or awaiting
	// a dual-licence election. Sorted by ModulePath then ModuleVersion for
	// determinism.
	Conflicts []CompatibilityConflict
	// Clean reports whether the entire closure is compatible (no conflicts, no
	// unknown pairs, and no elections still open).
	Clean bool
	// CoverageHoles lists, once each, the distinct SPDX identifiers this
	// closure carries that the dataset assigns no copyleft strength. It answers
	// a different question from Conflicts: a single unmodelled identifier on
	// twelve modules is ONE dataset gap, and reading it off twelve review items
	// makes it look like twelve legal questions. Sorted by SPDX.
	CoverageHoles []CoverageHole
	// TargetModelled reports whether the target identifier itself is in the
	// dataset. When false every module in the closure comes back unmodelled for
	// one reason — the target — and the per-module rows are a consequence, not
	// twelve findings.
	TargetModelled bool
}

// CoverageHole is one SPDX identifier a closure carries that the compatibility
// dataset does not model.
type CoverageHole struct {
	SPDX string
	// Modules counts the distinct modules in the closure the identifier was
	// attributed to.
	Modules int
	// Deliberate reports whether the dataset declines to model this identifier
	// on purpose, and Reason carries why. Deliberate=false is a gap in the
	// dataset: the identifier has been neither researched nor ruled out.
	Deliberate bool
	Reason     string
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
	// BSL-1.0 (Boost) is OSI-approved and imposes no copyleft: the licence
	// notice need not even accompany a compiled binary. It is bundled by
	// numerics libraries that vendor Boost-derived routines, so its absence
	// showed up as a review item on an otherwise permissive closure.
	"BSL-1.0": CopyleftNone,
	// Python-2.0 (PSF) is permissive with a notice-retention and
	// state-changes condition; no copyleft propagation.
	"Python-2.0": CopyleftNone,
	// WTFPL grants unconditional permission — public-domain-equivalent, in the
	// same family as Unlicense and CC0-1.0.
	"WTFPL": CopyleftNone,
	// BSD-2-Clause-Views is BSD-2-Clause plus a views-are-the-authors' notice;
	// the obligations catalogue already models it, so the two datasets agreeing
	// keeps a licence from being permissive on one surface and unmodelled on
	// another.
	"BSD-2-Clause-Views": CopyleftNone,

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

// unmodelledDeliberately records the SPDX identifiers the compatibility
// dataset does NOT model on purpose, each with the reason.
//
// It exists so that "unmodelled" can be read as a decision rather than as a
// gap. An identifier in copyleftStrengths has a researched verdict; an
// identifier here has a researched reason for having none; an identifier in
// neither is a coverage hole, and CoverageHolesFor reports it as one.
//
// Every entry here is a licence whose obligations attach to material other
// than the linked Go code — documentation, media, fonts — so a single
// copyleft strength would misstate the question rather than answer it. The
// honest answer for these is that a human decides, which is exactly what
// VerdictUnknownPair asks for.
var unmodelledDeliberately = map[string]string{
	"CC-BY-4.0":    "Creative Commons attribution licence for content, not code; its obligations attach to the covered material (docs, data, media), not to a linked Go package",
	"CC-BY-SA-3.0": "Creative Commons share-alike for content; the reciprocity arm has no settled reading against software redistribution, so the pair is a legal question rather than a dataset entry",
	"CC-BY-SA-4.0": "Creative Commons share-alike for content; same reasoning as CC-BY-SA-3.0. Commonly seen on a module's LICENSE.docs alongside a permissive code licence",
	"OFL-1.1":      "SIL Open Font Licence; its reciprocity applies to the font files, not to software that merely ships them",
}

// UnmodelledReason returns the recorded reason for an identifier the dataset
// deliberately does not model, and whether such a reason exists. A false
// second return for an identifier CopyleftStrengthOf also does not know means
// the dataset has a gap, not a decision.
func UnmodelledReason(spdx string) (string, bool) {
	reason, ok := unmodelledDeliberately[CanonicalSPDXID(spdx)]
	return reason, ok
}

// ModelledSPDXIDs returns the sorted identifiers the compatibility dataset
// assigns a copyleft strength to.
func ModelledSPDXIDs() []string {
	ids := make([]string, 0, len(copyleftStrengths))
	for id := range copyleftStrengths {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	return ids
}

// DeliberatelyUnmodelledSPDXIDs returns the sorted identifiers the dataset
// declines to model on purpose.
func DeliberatelyUnmodelledSPDXIDs() []string {
	ids := make([]string, 0, len(unmodelledDeliberately))
	for id := range unmodelledDeliberately {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	return ids
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
	s, ok := copyleftStrengths[CanonicalSPDXID(spdx)]
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

// evaluateElection evaluates a dual-licensed module (a disjunctive licence
// expression) against the target by evaluating each arm as a candidate
// election. The consumer may take the module under any ONE arm, so:
//
//   - every arm compatible → settled compatible whichever arm is elected; no
//     open item (the election still matters for obligations, not for this
//     question);
//   - some arm compatible → VerdictElectable: compatible IF such an arm is
//     elected. The election is an operator decision recorded via
//     license_overrides, never resolved silently, so it stays an open item;
//   - no arm compatible, any arm unmodelled → VerdictUnknownPair (review);
//   - every arm known-incompatible → VerdictIncompatible whichever arm is
//     elected, with the kind derived from the first arm for determinism.
//
// The returned bool reports whether the entry is an open item to record.
func evaluateElection(m CompatibilityInput, targetSPDX string) (CompatibilityConflict, bool) {
	expr := strings.Join(m.ElectiveArms, " OR ")
	var compatible []string
	anyUnknown := false
	for _, arm := range m.ElectiveArms {
		switch CheckPairCompatibility(arm, targetSPDX) {
		case VerdictCompatible:
			compatible = append(compatible, arm)
		case VerdictUnknownPair:
			anyUnknown = true
		case VerdictIncompatible, VerdictElectable:
			// Incompatible arms need no tracking beyond "not compatible";
			// VerdictElectable is never returned for a single identifier.
		}
	}

	if len(compatible) == len(m.ElectiveArms) {
		return CompatibilityConflict{}, false
	}

	c := CompatibilityConflict{
		ModulePath:       m.ModulePath,
		ModuleVersion:    m.ModuleVersion,
		DepSPDX:          expr,
		TargetSPDX:       targetSPDX,
		Origin:           m.Origin,
		OriginPath:       m.OriginPath,
		ModuleExpression: m.ModuleExpression,
	}
	switch {
	case len(compatible) > 0:
		c.Verdict = VerdictElectable
		c.Kind = ConflictElectionRequired
		c.ElectableArms = compatible
	case anyUnknown:
		c.Verdict = VerdictUnknownPair
		c.Kind = ConflictUnknownPair
	default:
		c.Verdict = VerdictIncompatible
		c.Kind = conflictKindFor(m.ElectiveArms[0])
	}
	return c, true
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
	_, targetKnown := CopyleftStrengthOf(targetSPDX)
	report := ClosureCompatibilityReport{
		TargetSPDX:     targetSPDX,
		DataVersion:    CompatibilityDataVersion,
		TargetModelled: targetKnown,
	}

	holes := newCoverageHoleTally()

	for _, m := range modules {
		holes.observe(m)
		if len(m.ElectiveArms) >= 2 {
			if c, open := evaluateElection(m, targetSPDX); open {
				report.Conflicts = append(report.Conflicts, c)
			}
			continue
		}
		spdx := m.SPDX
		if spdx == "" {
			report.Conflicts = append(report.Conflicts, CompatibilityConflict{
				ModulePath:       m.ModulePath,
				ModuleVersion:    m.ModuleVersion,
				DepSPDX:          "",
				TargetSPDX:       targetSPDX,
				Verdict:          VerdictUnknownPair,
				Kind:             ConflictUnknownPair,
				Origin:           m.Origin,
				OriginPath:       m.OriginPath,
				ModuleExpression: m.ModuleExpression,
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
			ModulePath:       m.ModulePath,
			ModuleVersion:    m.ModuleVersion,
			DepSPDX:          spdx,
			TargetSPDX:       targetSPDX,
			Verdict:          verdict,
			Kind:             kind,
			Origin:           m.Origin,
			OriginPath:       m.OriginPath,
			ModuleExpression: m.ModuleExpression,
		})
	}

	sort.Slice(report.Conflicts, func(i, j int) bool {
		a, b := report.Conflicts[i], report.Conflicts[j]
		if a.ModulePath != b.ModulePath {
			return a.ModulePath < b.ModulePath
		}
		if a.ModuleVersion != b.ModuleVersion {
			return a.ModuleVersion < b.ModuleVersion
		}
		return a.DepSPDX < b.DepSPDX
	})

	report.CoverageHoles = holes.result()
	report.Clean = len(report.Conflicts) == 0
	return report
}

// coverageHoleTally counts the distinct modules each unmodelled identifier was
// seen on, so one dataset gap is reported once rather than once per module.
type coverageHoleTally struct {
	modules map[string]map[string]struct{} // SPDX → set of module@version
}

func newCoverageHoleTally() *coverageHoleTally {
	return &coverageHoleTally{modules: make(map[string]map[string]struct{})}
}

// observe records every identifier the input carries that the dataset does not
// model. An empty SPDX is NOT a coverage hole: it means the module has no
// licence record to read, which is a missing measurement rather than a gap in
// the dataset, and the per-module review item already says so.
func (t *coverageHoleTally) observe(m CompatibilityInput) {
	ids := m.ElectiveArms
	if len(ids) < 2 {
		ids = nil
		if m.SPDX != "" {
			ids = []string{m.SPDX}
		}
	}
	for _, id := range ids {
		if _, known := CopyleftStrengthOf(id); known {
			continue
		}
		if t.modules[id] == nil {
			t.modules[id] = make(map[string]struct{})
		}
		t.modules[id][m.ModulePath+"@"+m.ModuleVersion] = struct{}{}
	}
}

func (t *coverageHoleTally) result() []CoverageHole {
	if len(t.modules) == 0 {
		return nil
	}
	ids := make([]string, 0, len(t.modules))
	for id := range t.modules {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	holes := make([]CoverageHole, 0, len(ids))
	for _, id := range ids {
		reason, deliberate := UnmodelledReason(id)
		holes = append(holes, CoverageHole{
			SPDX:       id,
			Modules:    len(t.modules[id]),
			Deliberate: deliberate,
			Reason:     reason,
		})
	}
	return holes
}
