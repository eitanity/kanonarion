package application

import (
	"context"
	"errors"
	"fmt"
	"sort"

	fetchdomain "github.com/eitanity/kanonarion/internal/fetch/domain"
	"github.com/eitanity/kanonarion/internal/license/domain"
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
	GetLicenseRecord(ctx context.Context, coord fetchdomain.ModuleCoordinate, pipelineVersion string) (domain.LicenseRecord, bool, error)
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
func (uc *CheckCompatibilityUseCase) CheckCompatibilityForWalk(
	ctx context.Context,
	walkID string,
	root fetchdomain.ModuleCoordinate,
	targetSPDX string,
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
	seen := make(map[fetchdomain.ModuleCoordinate]struct{})
	var coords []fetchdomain.ModuleCoordinate
	for _, node := range walk.Graph.Nodes {
		if node.Coordinate == root {
			continue
		}
		if _, dup := seen[node.Coordinate]; dup {
			continue
		}
		seen[node.Coordinate] = struct{}{}
		coords = append(coords, node.Coordinate)
	}
	sort.Slice(coords, func(i, j int) bool {
		if coords[i].Path != coords[j].Path {
			return coords[i].Path < coords[j].Path
		}
		return coords[i].Version < coords[j].Version
	})

	// Expand each module into one CompatibilityInput per effective SPDX.
	// Embedded components with their own licenses produce additional entries so
	// a bundled GPL component is caught even when the module root is permissive.
	modules := make([]domain.CompatibilityInput, 0, len(coords))
	for _, coord := range coords {
		spdxs := resolveEffectiveSPDXs(ctx, uc.store, coord)
		if len(spdxs) == 0 {
			modules = append(modules, domain.CompatibilityInput{
				ModulePath:    coord.Path,
				ModuleVersion: coord.Version,
				SPDX:          "", // unknown — treated as VerdictUnknownPair
			})
			continue
		}
		for _, spdx := range spdxs {
			modules = append(modules, domain.CompatibilityInput{
				ModulePath:    coord.Path,
				ModuleVersion: coord.Version,
				SPDX:          spdx,
			})
		}
	}

	report := domain.CheckClosureCompatibility(modules, targetSPDX)
	return report, nil
}

// resolveRootTarget resolves the implicit compatibility target from the
// root's own licence record. The record's Expression (falling back to
// PrimarySPDX) is the project's declared outbound licence.
func (uc *CheckCompatibilityUseCase) resolveRootTarget(
	ctx context.Context,
	root fetchdomain.ModuleCoordinate,
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

// resolveEffectiveSPDXs returns all distinct SPDX identifiers for coord, drawn
// from its EffectiveSet (root + embedded components). Falls back to a single
// expression/primary SPDX for records that predate. Returns nil when
// the record is absent or an error occurs — the caller treats nil as unknown
func resolveEffectiveSPDXs(ctx context.Context, store licenseStoreReader, coord fetchdomain.ModuleCoordinate) []string {
	rec, found, err := store.GetLicenseRecord(ctx, coord, PipelineVersion)
	if err != nil || !found {
		return nil
	}
	if len(rec.EffectiveSet.AllSPDXs) > 0 {
		return rec.EffectiveSet.AllSPDXs
	}
	// Fall back for records without EffectiveSet populated (LicenseStatusNone etc.).
	if rec.Expression != "" {
		return []string{rec.Expression}
	}
	if rec.PrimarySPDX != "" {
		return []string{rec.PrimarySPDX}
	}
	return nil
}
