package application

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/eitanity/kanonarion/internal/coordinate"

	"github.com/eitanity/kanonarion/internal/license/domain"
	walkdomain "github.com/eitanity/kanonarion/internal/walk/domain"
	walkports "github.com/eitanity/kanonarion/internal/walk/ports"
)

// ErrRootLicenceNotAnalysed is returned when an implicit compatibility target
// was requested (empty targetSPDX) but the root has no licence record. The
// root's licence has not been analysed — distinct from "analysed, no licence"
// absence of data must not be presented as an answer.
var ErrRootLicenceNotAnalysed = errors.New("root licence not analysed")

// ErrRootLicenceNoSPDX is returned when the root's licence record exists but
// carries no SPDX identity to check the closure against (e.g. a proprietary
// root resolving to Unclassified, or no licence files at all). That record is
// a valid outcome — it just cannot serve as an implicit SPDX target.
var ErrRootLicenceNoSPDX = errors.New("root licence has no SPDX identity")

// CheckCompatibilityUseCase evaluates a module closure against a target
// distribution license using the domain compatibility engine.
type CheckCompatibilityUseCase struct {
	store licenseStoreReader
	walks walkports.WalkStore
}

// licenseStoreReader is the read-only license store interface the use case
// needs. Satisfied by licenseports.LicenseStore.
type licenseStoreReader interface {
	GetLicenseRecord(ctx context.Context, coord coordinate.ModuleCoordinate, pipelineVersion string) (domain.LicenseRecord, bool, error)
}

// NewCheckCompatibilityUseCase constructs a CheckCompatibilityUseCase.
func NewCheckCompatibilityUseCase(store licenseStoreReader, walks walkports.WalkStore) *CheckCompatibilityUseCase {
	return &CheckCompatibilityUseCase{store: store, walks: walks}
}

// CheckCompatibilityForWalk evaluates the license compatibility of the dep
// closure in walkID against targetSPDX.
//
// An empty targetSPDX adopts the root's own analysed licence record as the
// implicit target: the project's declared (outbound) licence is what the
// closure must be compatible with. When that record is absent the result is
// ErrRootLicenceNotAnalysed; when it exists but resolves to no SPDX identity
// (proprietary/unclassified root) the result is ErrRootLicenceNoSPDX and the
// caller must pass an explicit target.
//
// Per if a module's license record has not been extracted, it is
// represented as an empty SPDX (VerdictUnknownPair), not silently skipped.
// The root module (target coordinate) is excluded from the closure.
//
// overrides carries the operator's license_overrides entries. An override is
// the recorded human decision for a module — including the election of one arm
// of a dual licence — so a module it resolves is evaluated under exactly that
// SPDX instead of the scanner's record.
func (uc *CheckCompatibilityUseCase) CheckCompatibilityForWalk(
	ctx context.Context,
	walkID string,
	root coordinate.ModuleCoordinate,
	targetSPDX string,
	overrides domain.LicenseOverrideSet,
) (domain.ClosureCompatibilityReport, error) {
	if targetSPDX == "" {
		resolved, err := uc.resolveRootTarget(ctx, root)
		if err != nil {
			return domain.ClosureCompatibilityReport{}, err
		}
		targetSPDX = resolved
	}

	walk, err := uc.walks.GetWalk(ctx, walkID)
	if err != nil {
		return domain.ClosureCompatibilityReport{}, fmt.Errorf("getting walk %s: %w", walkID, err)
	}

	// Collect unique coordinates (walk graph may list a module multiple times
	// at different depths).
	seen := make(map[coordinate.ModuleCoordinate]struct{})
	var coords []coordinate.ModuleCoordinate
	// The standard-library node carries its licence on the graph node rather
	// than in a licence record, so its SPDX is collected from the walk here
	// (walkdomain.StdlibLicense: node facts first, then the published
	// BSD-3-Clause constant — the shared rule every surface applies) and
	// consulted ahead of the store lookup below.
	stdlibSPDX := make(map[coordinate.ModuleCoordinate]string, 1)
	for _, node := range walk.Graph.Nodes {
		if node.Coordinate == root {
			continue
		}
		if node.ResolutionSource == walkdomain.ResolutionStdlib {
			spdx, _ := walkdomain.StdlibLicense(node.Stdlib)
			stdlibSPDX[node.Coordinate] = spdx
		}
		if _, dup := seen[node.Coordinate]; dup {
			continue
		}
		seen[node.Coordinate] = struct{}{}
		coords = append(coords, node.Coordinate)
	}
	sort.Slice(coords, func(i, j int) bool {
		if coords[i].Path() != coords[j].Path() {
			return coords[i].Path() < coords[j].Path()
		}
		return coords[i].Version() < coords[j].Version()
	})

	// Expand each module into CompatibilityInputs. A dual-licensed root (a
	// purely disjunctive expression) becomes one elective input; embedded
	// components with their own licenses produce additional entries so a
	// bundled GPL component is caught even when the module root is permissive.
	modules := make([]domain.CompatibilityInput, 0, len(coords))
	for _, coord := range coords {
		if spdx, isStdlib := stdlibSPDX[coord]; isStdlib {
			// The stdlib's licence is the stdlib's own: module root origin.
			modules = append(modules, domain.CompatibilityInput{
				ModulePath:       coord.Path(),
				ModuleVersion:    coord.Version(),
				SPDX:             spdx,
				ModuleExpression: spdx,
			})
			continue
		}
		// An override is the operator's recorded decision (correction or
		// dual-licence election) and replaces the scanner's answer wholesale —
		// including what the module's own licence is taken to be, so the
		// reported module licence is the decision rather than the scan it
		// overrode.
		if ov, ok := overrides.Resolve(coord); ok {
			modules = append(modules, domain.CompatibilityInput{
				ModulePath:       coord.Path(),
				ModuleVersion:    coord.Version(),
				SPDX:             ov.SPDX,
				ModuleExpression: ov.SPDX,
			})
			continue
		}
		modules = append(modules, compatibilityInputsFor(ctx, uc.store, coord)...)
	}

	report := domain.CheckClosureCompatibility(modules, targetSPDX)
	return report, nil
}

// resolveRootTarget resolves the implicit compatibility target from the
// root's own licence record. The record's Expression (falling back to
// PrimarySPDX) is the project's declared outbound licence.
func (uc *CheckCompatibilityUseCase) resolveRootTarget(
	ctx context.Context,
	root coordinate.ModuleCoordinate,
) (string, error) {
	rec, found, err := uc.store.GetLicenseRecord(ctx, root, PipelineVersion)
	if err != nil {
		return "", fmt.Errorf("getting root licence record for %s: %w", root, err)
	}
	if !found {
		return "", fmt.Errorf("%w: %s", ErrRootLicenceNotAnalysed, root)
	}
	if rec.Expression != "" {
		return rec.Expression, nil
	}
	if rec.PrimarySPDX != "" {
		return rec.PrimarySPDX, nil
	}
	return "", fmt.Errorf("%w: %s resolved to status %s", ErrRootLicenceNoSPDX, root, rec.OverallStatus)
}

// compatibilityInputsFor derives the CompatibilityInputs for one module from
// its licence record.
//
// A purely disjunctive expression ("Apache-2.0 OR GPL-3.0") is a dual licence:
// the consumer elects one arm, so the module contributes a single elective
// input the engine evaluates per election rather than one input per arm —
// which would have asserted that every arm applies and turned an electable
// dual licence into a false incompatibility. Embedded components keep their
// own single-licence entries: their licences apply regardless of the root
// election.
//
// Otherwise all distinct SPDX identifiers apply (EffectiveSet: root + embedded
// components), falling back to a single expression/primary SPDX for records
// that predate the EffectiveSet. A nil result (record absent, or a read error)
// is treated as unknown by the caller.
//
// Every input carries WHERE its identifier came from — the module's own root
// licence files, or the path prefix of a component bundled inside the module —
// together with the module's own licence expression, reported whole. Without
// that a bundled component's licence reaches the report in the column every
// other surface fills with the module's own, and a reader cannot tell the two
// apart.
//
// Components under a testdata directory are excluded here rather than in
// DeriveEffectiveLicenseSet: see domain.IsTestCorpusPath for why the exclusion
// belongs to this consumer and not to the derivation.
func compatibilityInputsFor(ctx context.Context, store licenseStoreReader, coord coordinate.ModuleCoordinate) []domain.CompatibilityInput {
	// No record, or a record that could not be read: nothing has been measured
	// for this module, so extraction is still the action that can change the
	// answer. A read error is reported the same way deliberately — the fact
	// that settles the question was not obtained, and claiming the stronger
	// "measured, unclassifiable" on a failed read would be a fabrication.
	unmeasured := []domain.CompatibilityInput{{
		ModulePath:    coord.Path(),
		ModuleVersion: coord.Version(),
		SPDX:          "", // unknown — treated as VerdictUnknownPair
		Measurement:   domain.MeasurementUnmeasured,
	}}
	rec, found, err := store.GetLicenseRecord(ctx, coord, PipelineVersion)
	if err != nil || !found {
		return unmeasured
	}

	// The module's OWN licence, carried on every input so the report can always
	// name it whatever the entry's identifier turned out to belong to.
	moduleExpr := rec.Expression
	if moduleExpr == "" {
		moduleExpr = rec.PrimarySPDX
	}

	newInput := func() domain.CompatibilityInput {
		return domain.CompatibilityInput{
			ModulePath:       coord.Path(),
			ModuleVersion:    coord.Version(),
			ModuleExpression: moduleExpr,
		}
	}

	if arms := domain.DisjunctionArms(rec.Expression); len(arms) >= 2 {
		elective := newInput()
		elective.ElectiveArms = arms
		inputs := []domain.CompatibilityInput{elective}
		// Embedded component licences are not part of the election.
		for _, comp := range componentSPDXs(rec) {
			in := newInput()
			in.SPDX = comp.spdx
			in.Origin = domain.OriginBundledComponent
			in.OriginPath = comp.prefixes
			inputs = append(inputs, in)
		}
		return inputs
	}

	var inputs []domain.CompatibilityInput
	rootSeen := make(map[string]bool, len(rec.EffectiveSet.RootSPDXs))
	for _, spdx := range rec.EffectiveSet.RootSPDXs {
		rootSeen[spdx] = true
		in := newInput()
		in.SPDX = spdx
		inputs = append(inputs, in)
	}
	for _, comp := range componentSPDXs(rec) {
		// An identifier the module's own root already declares is the module's
		// licence; a component repeating it adds no distinct obligation and
		// must not be re-attributed to the component.
		if rootSeen[comp.spdx] {
			continue
		}
		in := newInput()
		in.SPDX = comp.spdx
		in.Origin = domain.OriginBundledComponent
		in.OriginPath = comp.prefixes
		inputs = append(inputs, in)
	}

	if len(inputs) == 0 {
		// Fall back for records without EffectiveSet populated (LicenseStatusNone etc.).
		if moduleExpr == "" {
			// The record EXISTS and yielded no identifier: extraction ran and
			// the shipped files did not determine one. Re-running it produces
			// this same result, so the entry must not be reported as an
			// unmeasured module.
			unclassifiable := newInput()
			unclassifiable.Measurement = domain.MeasurementUnclassifiable
			return []domain.CompatibilityInput{unclassifiable}
		}
		in := newInput()
		in.SPDX = moduleExpr
		return []domain.CompatibilityInput{in}
	}
	return inputs
}

// componentAttribution is one identifier a module bundles, with the component
// prefixes it was found under.
type componentAttribution struct {
	spdx     string
	prefixes string // comma-separated, sorted by the record's component order
}

// componentSPDXs returns the distinct identifiers contributed by the module's
// bundled components, each naming every prefix it was found under, in sorted
// identifier order. Test-corpus components are dropped: they are shipped bytes
// but never linked code.
func componentSPDXs(rec domain.LicenseRecord) []componentAttribution {
	prefixes := make(map[string][]string)
	var order []string
	for _, comp := range rec.EffectiveSet.Components {
		if domain.IsTestCorpusPath(comp.PathPrefix) {
			continue
		}
		for _, spdx := range comp.SPDXs {
			if _, seen := prefixes[spdx]; !seen {
				order = append(order, spdx)
			}
			prefixes[spdx] = append(prefixes[spdx], comp.PathPrefix)
		}
	}
	sort.Strings(order)
	out := make([]componentAttribution, 0, len(order))
	for _, spdx := range order {
		out = append(out, componentAttribution{spdx: spdx, prefixes: strings.Join(prefixes[spdx], ", ")})
	}
	return out
}
