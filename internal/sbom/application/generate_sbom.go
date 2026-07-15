package application

import (
	"context"
	"errors"
	"fmt"
	"log/slog"

	fetchports "github.com/eitanity/kanonarion/internal/fetch/ports"
	licenseports "github.com/eitanity/kanonarion/internal/license/ports"
	"github.com/eitanity/kanonarion/internal/sbom/domain"
	"github.com/eitanity/kanonarion/internal/sbom/ports"
	vulnports "github.com/eitanity/kanonarion/internal/vuln/ports"
	walkports "github.com/eitanity/kanonarion/internal/walk/ports"

	fetchdomain "github.com/eitanity/kanonarion/internal/fetch/domain"
	licensedomain "github.com/eitanity/kanonarion/internal/license/domain"
	vulndomain "github.com/eitanity/kanonarion/internal/vuln/domain"
	walkdomain "github.com/eitanity/kanonarion/internal/walk/domain"
)

// GenerateSBOMUseCase orchestrates SBOM generation for a walk.
type GenerateSBOMUseCase struct {
	walkStore       walkports.WalkStore
	licenseStore    licenseports.LicenseStore
	vulnStore       vulnports.VulnerabilityStore
	sbomStore       ports.SBOMStore
	generator       ports.SBOMGenerator
	clock           fetchports.Clock
	pipelineVersion string
	// licensePipelineVersion is the licence extraction pipeline version under
	// which licence records are persisted. It is distinct from the SBOM's own
	// pipelineVersion; using the latter for licence lookups silently misses
	// every record once the two diverge.
	licensePipelineVersion string
	logger                 *slog.Logger
}

// NewGenerateSBOMUseCase returns a new GenerateSBOMUseCase.
// licensePipelineVersion names the licence extraction pipeline version used
// to look up licence records for the walk's modules.
func NewGenerateSBOMUseCase(
	walkStore walkports.WalkStore,
	licenseStore licenseports.LicenseStore,
	vulnStore vulnports.VulnerabilityStore,
	sbomStore ports.SBOMStore,
	generator ports.SBOMGenerator,
	clock fetchports.Clock,
	pipelineVersion string,
	licensePipelineVersion string,
	logger *slog.Logger,
) *GenerateSBOMUseCase {
	return &GenerateSBOMUseCase{
		walkStore:              walkStore,
		licenseStore:           licenseStore,
		vulnStore:              vulnStore,
		sbomStore:              sbomStore,
		generator:              generator,
		clock:                  clock,
		pipelineVersion:        pipelineVersion,
		licensePipelineVersion: licensePipelineVersion,
		logger:                 logger,
	}
}

// SBOMRequest defines the input for SBOM generation.
type SBOMRequest struct {
	WalkID        string
	WalkScanRunID *string // nil = generate without vulnerability data
	Format        domain.SBOMFormat
	Force         bool
	Operator      string
	// AllowList restricts the component list to a specific set of modules —
	// typically the import closure of a single binary (sbom --package).
	// When non-empty the result is ephemeral: cache and persistence are skipped.
	AllowList []fetchdomain.ModuleCoordinate
	// MainComponentVersion overrides the version stamped on the SBOM subject
	// (metadata.component) when it is the local main module; empty leaves the
	// synthetic "local". A release passes its tag so the subject is a resolvable
	// coordinate rather than the build-time placeholder.
	MainComponentVersion string
	// MainComponentLicense is the SPDX id/expression attached to the subject when
	// it is the local main module and carries no fetched licence record.
	MainComponentLicense string
}

// ErrWalkScanRunNotFound is returned when the requested scan run does not exist.
var ErrWalkScanRunNotFound = errors.New("walk scan run not found")

// Generate produces and persists an SBOM for the given walk.
// If a cached record exists for the same (walkID, scanRunID, format, pipelineVersion)
// and Force is false, the cached record is returned without re-generation.
// When req.AllowList is non-empty the SBOM is scoped to only those modules;
// the result is ephemeral (cache skipped, not persisted).
func (uc *GenerateSBOMUseCase) Generate(ctx context.Context, req SBOMRequest) (domain.SBOMRecord, error) {
	format := req.Format
	if format == "" {
		format = domain.CycloneDX16
	}

	// Package-scoped requests are ephemeral: skip cache entirely.
	scoped := len(req.AllowList) > 0

	// Cache lookup.
	if !req.Force && !scoped {
		if cached, ok, err := uc.sbomStore.FindSBOMRecord(ctx, req.WalkID, req.WalkScanRunID, format, uc.pipelineVersion); err != nil {
			return domain.SBOMRecord{}, fmt.Errorf("checking sbom cache: %w", err)
		} else if ok {
			uc.logger.InfoContext(ctx, "sbom.cache_hit", "walk_id", req.WalkID, "format", format)
			return cached, nil
		}
	}

	// 1. Load walk.
	walk, err := uc.walkStore.GetWalk(ctx, req.WalkID)
	if err != nil {
		return domain.SBOMRecord{}, fmt.Errorf("loading walk %q: %w", req.WalkID, err)
	}

	// 1a. Apply allowlist: restrict nodes/edges to the binary's import closure.
	if scoped {
		allowed := make(map[fetchdomain.ModuleCoordinate]bool, len(req.AllowList))
		for _, c := range req.AllowList {
			allowed[c] = true
		}
		// The synthetic stdlib node is a universal build input — every binary
		// links against it — but it is not a module `go list -deps` reports, so
		// it never appears in the package allow-list. Keep it regardless, mirroring
		// the walk resolver's injectStdlib, so a --package SBOM still records the
		// standard-library component (and its --stdlib-from-gomod-pinned version).
		keep := func(c fetchdomain.ModuleCoordinate) bool {
			return allowed[c] || c.Path == walkdomain.StdlibModulePath
		}
		filtered := make([]walkdomain.GraphNode, 0, len(req.AllowList)+1)
		for _, n := range walk.Graph.Nodes {
			if keep(n.Coordinate) {
				filtered = append(filtered, n)
			}
		}
		walk.Graph.Nodes = filtered
		filteredEdges := make([]walkdomain.GraphEdge, 0)
		for _, e := range walk.Graph.Edges {
			if keep(e.From) && keep(e.To) {
				filteredEdges = append(filteredEdges, e)
			}
		}
		walk.Graph.Edges = filteredEdges
	}

	// 2. Load licence records for all modules.
	licenses := make(map[fetchdomain.ModuleCoordinate]licensedomain.LicenseRecord, len(walk.Graph.Nodes))
	for _, node := range walk.Graph.Nodes {
		rec, ok, lerr := uc.licenseStore.GetLicenseRecord(ctx, node.Coordinate, uc.licensePipelineVersion)
		if lerr != nil {
			return domain.SBOMRecord{}, fmt.Errorf("loading license for %s: %w", node.Coordinate, lerr)
		}
		if ok {
			licenses[node.Coordinate] = rec
		}
		// Missing licence is allowed; the generator will flag LicensesIncomplete.
	}

	// 3. Optionally load vulnerability records.
	var vulnRecords []vulndomain.VulnerabilityRecord
	if req.WalkScanRunID != nil {
		run, ok, verr := uc.vulnStore.GetWalkScanRun(ctx, *req.WalkScanRunID)
		if verr != nil {
			return domain.SBOMRecord{}, fmt.Errorf("loading scan run %q: %w", *req.WalkScanRunID, verr)
		}
		if !ok {
			return domain.SBOMRecord{}, fmt.Errorf("%w: %s", ErrWalkScanRunNotFound, *req.WalkScanRunID)
		}
		vulnRecords, err = uc.vulnStore.ListVulnerabilityRecords(ctx, run.ID)
		if err != nil {
			return domain.SBOMRecord{}, fmt.Errorf("loading vulnerability records for run %q: %w", run.ID, err)
		}
	}

	// 4. Generate.
	genReq := ports.GenerateRequest{
		WalkScanRunID:        req.WalkScanRunID,
		Format:               format,
		PipelineVersion:      uc.pipelineVersion,
		Operator:             req.Operator,
		MainComponentVersion: req.MainComponentVersion,
		MainComponentLicense: req.MainComponentLicense,
	}
	record, err := uc.generator.Generate(ctx, walk, licenses, vulnRecords, genReq)
	if err != nil {
		return domain.SBOMRecord{}, fmt.Errorf("generating sbom: %w", err)
	}

	// 5. Persist — skipped for scoped (package-filtered) requests.
	if !scoped {
		if err := uc.sbomStore.PutSBOMRecord(ctx, record); err != nil {
			return domain.SBOMRecord{}, fmt.Errorf("persisting sbom record: %w", err)
		}
	}

	uc.logger.InfoContext(ctx, "sbom.generated",
		"id", record.ID,
		"walk_id", record.WalkID,
		"format", record.Format,
		"content_hash", record.ContentHash,
		"licenses_incomplete", record.LicensesIncomplete,
	)
	return record, nil
}
