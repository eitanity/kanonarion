package application

import (
	"context"
	"fmt"
	"log/slog"
	"path/filepath"
	"time"

	"github.com/eitanity/kanonarion/internal/coordinate"

	fetchports "github.com/eitanity/kanonarion/internal/fetch/ports"
	licenseports "github.com/eitanity/kanonarion/internal/license/ports"
	"github.com/eitanity/kanonarion/internal/sbom/domain"
	"github.com/eitanity/kanonarion/internal/sbom/ports"
	walkports "github.com/eitanity/kanonarion/internal/walk/ports"

	licensedomain "github.com/eitanity/kanonarion/internal/license/domain"
	vendordomain "github.com/eitanity/kanonarion/internal/vendortree/domain"
	walkdomain "github.com/eitanity/kanonarion/internal/walk/domain"
)

// GenerateSBOMUseCase orchestrates SBOM generation for a walk.
type GenerateSBOMUseCase struct {
	walkStore       walkports.WalkStore
	licenseStore    licenseports.LicenseStore
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
	// vendorTree reads the project's vendored module set so the document can
	// state its coverage of it. Optional: nil means no scope statement, which
	// is the honest answer when nothing can read the tree.
	vendorTree ports.VendorTreeReader
	// audit appends the assurance-log events a generation and a serving leave.
	// Optional; nil disables emission.
	audit ports.AuditSink
}

// WithAudit wires an audit sink so a persisted document appends one
// sbom_generated event and a document served from cache appends one
// sbom_served. A nil sink (the default) disables emission. Returns the use case
// for chaining, mirroring WithVendorTree.
func (uc *GenerateSBOMUseCase) WithAudit(sink ports.AuditSink) *GenerateSBOMUseCase {
	uc.audit = sink
	return uc
}

// WithVendorTree wires the reader that lets a generated document state how much
// of the project's vendored tree it describes. Returns the use case for
// chaining.
func (uc *GenerateSBOMUseCase) WithVendorTree(r ports.VendorTreeReader) *GenerateSBOMUseCase {
	uc.vendorTree = r
	return uc
}

// NewGenerateSBOMUseCase returns a new GenerateSBOMUseCase.
// licensePipelineVersion names the licence extraction pipeline version used
// to look up licence records for the walk's modules.
func NewGenerateSBOMUseCase(
	walkStore walkports.WalkStore,
	licenseStore licenseports.LicenseStore,
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
	WalkID   string
	Format   domain.SBOMFormat
	Force    bool
	Operator string
	// GeneratedAt is when the caller is creating this document; it becomes the
	// document's metadata timestamp. Zero means none was supplied, and the
	// document falls back to a derived timestamp it labels as derived.
	//
	// A supplied value bypasses the cache: it is not part of the cache key, so a
	// cached record would answer with another moment's timestamp under the
	// caller's request.
	GeneratedAt time.Time
	// AllowList restricts the component list to a specific set of modules —
	// typically the import closure of a single binary (sbom --package).
	// When non-empty the result is ephemeral: cache and persistence are skipped.
	AllowList []coordinate.ModuleCoordinate
	// MainComponentVersion overrides the version stamped on the SBOM subject
	// (metadata.component) when it is the local main module; empty leaves the
	// synthetic "local". A release passes its tag so the subject is a resolvable
	// coordinate rather than the build-time placeholder.
	MainComponentVersion string
	// MainComponentLicense is the SPDX id/expression attached to the subject when
	// it is the local main module and carries no fetched licence record.
	MainComponentLicense string
}

// namesSubject reports whether the caller supplied a subject stamp — a version
// or a licence for the document's metadata.component.
//
// Neither is part of the cache key, so a request that names the subject is
// answered by generating rather than by serving what is stored, and what it
// generates is not stored. Both halves are needed, and each answers one
// direction of the same defect:
//
//   - Serving a stored document under such a request would answer with another
//     run's subject, silently discarding the stamp the caller supplied. This is
//     the GeneratedAt argument above, applied to the subject's identity.
//   - Storing the result would put one caller's stamp in the slot every later
//     caller reads, so a caller who names no subject at all would be handed a
//     version that is not theirs — a plausible one, in a distributed artefact.
//     A stamped document belongs to the run that asked for it, not to the walk.
func (r SBOMRequest) namesSubject() bool {
	return r.MainComponentVersion != "" || r.MainComponentLicense != ""
}

// Generate produces and persists an SBOM for the given walk.
// If a cached record exists for the same (walkID, format, pipelineVersion) and
// none of Force, GeneratedAt or a subject stamp (MainComponentVersion,
// MainComponentLicense) is set, the cached record is returned without
// re-generation.
// When req.AllowList is non-empty the SBOM is scoped to only those modules;
// the result is ephemeral (cache skipped, not persisted). A request that names
// the subject is ephemeral for the same reason: the stored document answers for
// the walk, and a stamped one answers only for the run that asked for it.
func (uc *GenerateSBOMUseCase) Generate(ctx context.Context, req SBOMRequest) (domain.SBOMRecord, error) {
	format := req.Format
	if format == "" {
		format = domain.CycloneDX16
	}

	// Package-scoped requests are ephemeral: skip cache entirely.
	scoped := len(req.AllowList) > 0

	// A named subject is generated, never served, and never stored: see
	// SBOMRequest.namesSubject.
	stamped := req.namesSubject()

	// Cache lookup. A caller-supplied creation time is not part of the key, so
	// serving a cached document under one would date it to another generation.
	if !req.Force && !scoped && !stamped && req.GeneratedAt.IsZero() {
		if cached, ok, err := uc.sbomStore.FindSBOMRecord(ctx, req.WalkID, format, uc.pipelineVersion); err != nil {
			return domain.SBOMRecord{}, fmt.Errorf("checking sbom cache: %w", err)
		} else if ok {
			uc.logger.InfoContext(ctx, "sbom.cache_hit", "walk_id", req.WalkID, "format", format)
			// Assurance log: a stored document handed back is still a document that
			// left the building, and "when did we last produce this artefact, and how
			// often has it gone out" is unanswerable if only the first generation is
			// visible. The event names the record served and who asked for this
			// serving; it is a distinct type from the generation event, so a reader
			// never mistakes a re-serve for a fresh production.
			if err := emitSBOMServed(uc.audit, cached, req.Operator); err != nil {
				return domain.SBOMRecord{}, err
			}
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
		allowed := make(map[coordinate.ModuleCoordinate]bool, len(req.AllowList))
		for _, c := range req.AllowList {
			allowed[c] = true
		}
		// The allow-list is keyed by require/import coordinates (`go list -deps`
		// reports a replaced module at its original path@version, never the
		// replacement — that lives under .Module.Replace), so a replace-to-fork node
		// is matched via its OriginalCoordinate; FilterGraph tests both identities.
		// The synthetic stdlib node is a universal build input — every binary links
		// against it — but it is not a module `go list -deps` reports, so it never
		// appears in the allow-list. Keep it regardless, mirroring the walk
		// resolver's injectStdlib, so a --package SBOM still records the
		// standard-library component (and its --stdlib-from-gomod-pinned version).
		// The allow-list is version-sensitive, so match and key edges on the full
		// coordinate rather than the bare path.
		inScope := func(c coordinate.ModuleCoordinate) bool {
			return allowed[c] || c.Path() == walkdomain.StdlibModulePath
		}
		walk.Graph.Nodes, walk.Graph.Edges = walkdomain.FilterGraph(
			walk.Graph,
			inScope,
			func(c coordinate.ModuleCoordinate) coordinate.ModuleCoordinate { return c },
		)
	}

	// 2. Load licence records for all modules.
	licenses := make(map[coordinate.ModuleCoordinate]licensedomain.LicenseRecord, len(walk.Graph.Nodes))
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

	// 3. Generate. The document is an inventory of components and their identity,
	// hashes and licences; it carries no vulnerability list, so no scan run is
	// read here and none can be attached.
	genReq := ports.GenerateRequest{
		Format:               format,
		DocumentTimestamp:    req.GeneratedAt,
		PipelineVersion:      uc.pipelineVersion,
		Operator:             req.Operator,
		MainComponentVersion: req.MainComponentVersion,
		MainComponentLicense: req.MainComponentLicense,
		VendorScope:          uc.vendorScope(ctx, walk),
		// A package-scoped run has already filtered walk.Graph above, so the
		// scope arithmetic is measured against the components this document
		// actually carries. Flagging it lets the statement say why so much of
		// the tree falls outside a document that was asked for one binary.
		ComponentsScopedToBinary: scoped,
	}
	record, err := uc.generator.Generate(ctx, walk, licenses, genReq)
	if err != nil {
		return domain.SBOMRecord{}, fmt.Errorf("generating sbom: %w", err)
	}

	// 4. Persist — skipped for scoped (package-filtered) requests, and for a
	// request that named the subject, whose document describes that request
	// rather than the walk.
	if !scoped && !stamped {
		if err := uc.sbomStore.PutSBOMRecord(ctx, record); err != nil {
			return domain.SBOMRecord{}, fmt.Errorf("persisting sbom record: %w", err)
		}
		// Assurance log: one event per persisted document, written after the record
		// so a failed append reports an unlogged write rather than undoing it. A
		// package-scoped request persisted nothing and so appends nothing — the
		// event states that a record exists, and an ephemeral document leaves none.
		if err := emitSBOMGenerated(uc.audit, record, !req.GeneratedAt.IsZero()); err != nil {
			return domain.SBOMRecord{}, err
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

// vendorScope states this document's coverage of the vendored tree the walk was
// rooted at: how many modules the tree holds, how many the component list
// describes, and every module it does not with the reason.
//
// A tree module is covered when the graph holds a node for it under EITHER
// identity. `go mod vendor` files a replaced module's source under its ORIGINAL
// path — that is the name modules.txt uses — while a resolved build list names
// the REPLACEMENT, which is what the node's coordinate carries. Matching on the
// node coordinate alone therefore reports every replace-to-fork module as
// absent from a document that describes it perfectly well, under its fork name.
//
// Returns nil when there is nothing to measure against: no reader wired, a walk
// with no recorded project root, or a project with no vendored tree. A read
// failure is logged and yields nil rather than failing generation — the
// document is still true, it just cannot state this scope.
func (uc *GenerateSBOMUseCase) vendorScope(ctx context.Context, walk walkdomain.WalkRecord) *vendordomain.VendorScope {
	if uc.vendorTree == nil || walk.ProjectDir == "" {
		return nil
	}
	mods, err := uc.vendorTree.VendorTree(ctx, filepath.Join(walk.ProjectDir, "go.mod"))
	if err != nil {
		uc.logger.WarnContext(ctx, "sbom.vendor_scope.unavailable",
			"walk_id", walk.ID, "project_dir", walk.ProjectDir, "error", err)
		return nil
	}
	if len(mods) == 0 {
		return nil
	}
	described := make(map[string]bool, len(walk.Graph.Nodes)*2)
	for _, n := range walk.Graph.Nodes {
		described[n.Coordinate.Path()] = true
		if p := n.OriginalCoordinate.Path(); p != "" {
			described[p] = true
		}
	}
	scope := vendordomain.ScopeOverTree(mods, func(m vendordomain.VendoredModule) bool {
		return described[m.Path]
	})
	return &scope
}
