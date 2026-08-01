package application

import (
	"context"
	"errors"
	"fmt"
	"sort"

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
			modules = append(modules, domain.CompatibilityInput{
				ModulePath:    coord.Path(),
				ModuleVersion: coord.Version(),
				SPDX:          spdx,
			})
			continue
		}
		// An override is the operator's recorded decision (correction or
		// dual-licence election) and replaces the scanner's answer wholesale.
		if ov, ok := overrides.Resolve(coord); ok {
			modules = append(modules, domain.CompatibilityInput{
				ModulePath:    coord.Path(),
				ModuleVersion: coord.Version(),
				SPDX:          ov.SPDX,
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
func compatibilityInputsFor(ctx context.Context, store licenseStoreReader, coord coordinate.ModuleCoordinate) []domain.CompatibilityInput {
	unknown := []domain.CompatibilityInput{{
		ModulePath:    coord.Path(),
		ModuleVersion: coord.Version(),
		SPDX:          "", // unknown — treated as VerdictUnknownPair
	}}
	rec, found, err := store.GetLicenseRecord(ctx, coord, PipelineVersion)
	if err != nil || !found {
		return unknown
	}

	if arms := domain.DisjunctionArms(rec.Expression); len(arms) >= 2 {
		inputs := []domain.CompatibilityInput{{
			ModulePath:    coord.Path(),
			ModuleVersion: coord.Version(),
			ElectiveArms:  arms,
		}}
		// Embedded component licences are not part of the election.
		seen := make(map[string]bool)
		for _, comp := range rec.EffectiveSet.Components {
			for _, spdx := range comp.SPDXs {
				if seen[spdx] {
					continue
				}
				seen[spdx] = true
				inputs = append(inputs, domain.CompatibilityInput{
					ModulePath:    coord.Path(),
					ModuleVersion: coord.Version(),
					SPDX:          spdx,
				})
			}
		}
		return inputs
	}

	spdxs := rec.EffectiveSet.AllSPDXs
	if len(spdxs) == 0 {
		// Fall back for records without EffectiveSet populated (LicenseStatusNone etc.).
		switch {
		case rec.Expression != "":
			spdxs = []string{rec.Expression}
		case rec.PrimarySPDX != "":
			spdxs = []string{rec.PrimarySPDX}
		default:
			return unknown
		}
	}
	inputs := make([]domain.CompatibilityInput, 0, len(spdxs))
	for _, spdx := range spdxs {
		inputs = append(inputs, domain.CompatibilityInput{
			ModulePath:    coord.Path(),
			ModuleVersion: coord.Version(),
			SPDX:          spdx,
		})
	}
	return inputs
}
