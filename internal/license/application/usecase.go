package application

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"sort"
	"strings"

	"github.com/eitanity/kanonarion/internal/adapters/ziparchive"
	"github.com/eitanity/kanonarion/internal/audit"
	"github.com/eitanity/kanonarion/internal/coordinate"
	"github.com/eitanity/kanonarion/internal/fetch/domain"
	fetchports "github.com/eitanity/kanonarion/internal/fetch/ports"
	domain2 "github.com/eitanity/kanonarion/internal/license/domain"
	"github.com/eitanity/kanonarion/internal/license/ports"
)

// PipelineVersion identifies this release of the license extraction pipeline.
// Bump this constant whenever extraction logic changes to ensure old records
// are not confused with new ones.
const PipelineVersion = "1.1.0"

// ExtractLicenseUseCase extracts and persists license information for a
// single Go module at a pinned version.
type ExtractLicenseUseCase struct {
	facts                     fetchports.FactStore
	blobs                     fetchports.BlobStore
	licenses                  ports.LicenseStore
	detector                  ports.LicenseDetector
	clock                     fetchports.Clock
	stopwatch                 fetchports.Stopwatch
	pipelineVersion           string
	fetchPipelineVersion      string // pipeline version used when the module was fetched
	localFetchPipelineVersion string // pipeline version used when the module was ingested from a local tree
	logger                    *slog.Logger
	hasher                    domain2.LicenseRecordHasher
	audit                     ports.AuditSink // optional; nil disables audit emission
}

// Config holds all construction parameters for ExtractLicenseUseCase.
type Config struct {
	Facts                fetchports.FactStore
	Blobs                fetchports.BlobStore
	Licenses             ports.LicenseStore
	Detector             ports.LicenseDetector
	Clock                fetchports.Clock
	Stopwatch            fetchports.Stopwatch
	PipelineVersion      string // defaults to PipelineVersion constant
	FetchPipelineVersion string // pipeline version used when modules were fetched
	// LocalFetchPipelineVersion is the pipeline version under which locally
	// ingested modules (local-replace targets and the project-walk root)
	// persist their FactRecord. Empty disables the local fallback.
	LocalFetchPipelineVersion string
	Logger                    *slog.Logger
}

// NewExtractLicenseUseCase constructs an ExtractLicenseUseCase from a Config.
func NewExtractLicenseUseCase(cfg Config) *ExtractLicenseUseCase {
	if cfg.PipelineVersion == "" {
		cfg.PipelineVersion = PipelineVersion
	}
	return &ExtractLicenseUseCase{
		facts:                     cfg.Facts,
		blobs:                     cfg.Blobs,
		licenses:                  cfg.Licenses,
		detector:                  cfg.Detector,
		clock:                     cfg.Clock,
		stopwatch:                 cfg.Stopwatch,
		pipelineVersion:           cfg.PipelineVersion,
		fetchPipelineVersion:      cfg.FetchPipelineVersion,
		localFetchPipelineVersion: cfg.LocalFetchPipelineVersion,
		logger:                    cfg.Logger,
	}
}

// WithAudit wires an audit sink so each fresh extraction appends one
// license_extracted assurance-log event carrying the resolved SPDX and status.
// It is optional — a nil sink (the default) disables emission — and returns the
// receiver for chaining, mirroring the other optional-dependency builders. A
// cache hit re-serves an existing record without re-extracting, so it emits
// nothing; the event marks the moment the facts were computed and persisted.
func (uc *ExtractLicenseUseCase) WithAudit(sink ports.AuditSink) *ExtractLicenseUseCase {
	uc.audit = sink
	return uc
}

// sampling limits for the per-file source scan (Pass 2).
const (
	perFileMaxFiles      = 20       // maximum root-level .go files to inspect
	perFileMaxTotalBytes = 1 << 20  // 1 MB across all sampled files
	perFileMaxFileBytes  = 64 << 10 // 64 KB per file fed to the full detector
	perFileSPDXScanBytes = 4 << 10  // 4 KB prefix scan for SPDX-License-Identifier
	perFileConfThreshold = 0.85     // minimum detector confidence to record a match
)

// copyrightMaxFiles bounds the copyright header backfill, which walks the whole
// module tree rather than just its root. It is deliberately separate from
// perFileMaxFiles: that limit governs the full-detector scan, which is orders of
// magnitude more expensive per file than reading a 4 KB prefix and running a
// handful of regexes.
const copyrightMaxFiles = 200

// ExtractRequest is the input to Execute.
type ExtractRequest struct {
	Coordinate coordinate.ModuleCoordinate
	// Force re-extracts even if a record for this pipeline version exists.
	Force bool
	// PerFile enables a second-pass scan of root-level.go source files when
	// no dedicated license file is found (Pass 1). It detects SPDX-License-Identifier
	// headers and high-confidence copyright blocks embedded in source.
	PerFile bool
}

// ExtractResult is the output of Execute.
type ExtractResult struct {
	Record    domain2.LicenseRecord
	FromCache bool
}

func (uc *ExtractLicenseUseCase) GetLicenseStore() ports.LicenseStore {
	return uc.licenses
}

// Execute runs the license extraction pipeline for the given module.
//
// The module must have been fetched first (a FactRecord must exist). If not,
// ErrModuleNotFetched is returned.
//
// Extraction failures (unreadable zip, zip parse errors) are recorded in the
// LicenceRecord with status ExtractionFailed — they do not make Execute return
// an error. Only infrastructure errors (store access, blob I/O) return errors.
func (uc *ExtractLicenseUseCase) Execute(ctx context.Context, req ExtractRequest) (_ ExtractResult, retErr error) {
	log := uc.logger.With(
		slog.String("extraction.module.path", req.Coordinate.Path),
		slog.String("extraction.module.version", req.Coordinate.Version),
		slog.String("extraction.stage", "license"),
		slog.String("pipeline_version", uc.pipelineVersion),
	)
	lap := uc.stopwatch.Start()
	log.InfoContext(ctx, "licence_extract_start")

	defer func() {
		log.InfoContext(ctx, "licence_extract_end",
			slog.Int64("extraction.duration_ms", lap.Elapsed().Milliseconds()),
		)
	}()

	// Step 1: verify the module has been fetched.
	factRecord, err := uc.requireFetchRecord(ctx, req.Coordinate)
	if err != nil {
		return ExtractResult{}, err
	}

	// Step 2: check for an existing extraction record. A local coordinate
	// (the project-walk root) is never served from cache: the working tree
	// mutates between runs, so its records are recomputed fresh every time.
	if !req.Force && !req.Coordinate.IsLocal() {
		existing, found, cerr := uc.licenses.GetLicenseRecord(ctx, req.Coordinate, uc.pipelineVersion)
		if cerr != nil && !errors.Is(cerr, ports.ErrLicenceIntegrity) {
			return ExtractResult{}, fmt.Errorf("checking license store: %w", cerr)
		}
		if found {
			log.InfoContext(ctx, "licence_cache_hit")
			return ExtractResult{Record: existing, FromCache: true}, nil
		}
	}

	// Step 3: open the module zip.
	blobHandle := fetchports.BlobHandle(factRecord.ContentLocation)
	zipReader, err := uc.blobs.Get(ctx, blobHandle)
	if err != nil {
		return ExtractResult{}, fmt.Errorf("opening blob %s: %w", factRecord.ContentLocation, err)
	}
	defer func() {
		if cerr := zipReader.Close(); cerr != nil && retErr == nil {
			retErr = fmt.Errorf("closing blob reader: %w", cerr)
		}
	}()

	zipData, err := io.ReadAll(zipReader)
	if err != nil {
		return ExtractResult{}, fmt.Errorf("reading blob: %w", err)
	}
	log.InfoContext(ctx, "blob_read", slog.Int("zip_bytes", len(zipData)))

	// Steps 4–7: extract license files, run detection, derive status.
	record, extractErr := uc.extractFromZip(ctx, log, req.Coordinate, zipData, req.PerFile)
	if extractErr != nil {
		record = domain2.LicenseRecord{
			SchemaVersion:   domain2.LicenseSchemaVersion,
			Ecosystem:       domain.EcosystemGo,
			Coordinate:      req.Coordinate,
			OverallStatus:   domain2.LicenseStatusExtractionFailed,
			CopyrightStatus: domain2.CopyrightStatusExtractionFailed,
			FailureDetail:   extractErr.Error(),
			ExtractedAt:     uc.clock.Now().UTC(),
			PipelineVersion: uc.pipelineVersion,
		}
		log.InfoContext(ctx, "license_extraction_failed", slog.String("error", extractErr.Error()))
	}

	// Step 7.5: a local coordinate is the project-walk root, so the extracted
	// facts are the project's own outbound declaration (the licence it grants,
	// the copyright it asserts), not an inbound dependency obligation. Mark
	// the role so consumers (license-compat, sbom, notice) treat the record
	// as the target rather than a constraint to satisfy.
	if req.Coordinate.IsLocal() {
		record.Role = domain2.LicenseRoleRootDeclaration
	}

	// Step 8: compute content hash.
	record, err = uc.hasher.SetContentHash(record)
	if err != nil {
		return ExtractResult{}, fmt.Errorf("computing content hash: %w", err)
	}

	// Step 9: persist.
	if err := uc.licenses.PutLicenseRecord(ctx, record); err != nil {
		return ExtractResult{}, fmt.Errorf("persisting license record: %w", err)
	}
	log.InfoContext(ctx, "license_record_persisted",
		slog.String("overall_status", record.OverallStatus.String()),
		slog.String("primary_spdx", record.PrimarySPDX),
		slog.String("content_hash", record.ContentHash),
	)

	// Step 10: assurance log. One license_extracted event per extracted record
	// anchors the resolved SPDX and status in the tamper-resistant append-only
	// log, so a licence that later drives a compliance decision is visible there
	// and not only in the mutable licence record.
	if err := uc.emitLicenseExtracted(record); err != nil {
		return ExtractResult{}, err
	}

	return ExtractResult{Record: record, FromCache: false}, nil
}

// emitLicenseExtracted appends one license_extracted event for a freshly
// extracted record. A nil audit sink disables emission. The source is always
// the scanner: this use case extracts licence facts from module content;
// operator overrides resolve later, at query/compat time, never here.
func (uc *ExtractLicenseUseCase) emitLicenseExtracted(record domain2.LicenseRecord) error {
	if uc.audit == nil {
		return nil
	}
	if err := uc.audit.RecordEvent(licenseExtractedEvent(record)); err != nil {
		return fmt.Errorf("recording license extraction audit event: %w", err)
	}
	return nil
}

// licenseExtractedEvent builds the assurance-log envelope for one extracted
// licence record.
func licenseExtractedEvent(record domain2.LicenseRecord) audit.Event {
	return audit.Event{
		Type: audit.EventLicenseExtracted,
		Payload: map[string]any{
			"module":         record.Coordinate.Path,
			"version":        record.Coordinate.Version,
			"primary_spdx":   record.PrimarySPDX,
			"overall_status": record.OverallStatus.String(),
			"source":         "scanner",
		},
	}
}

// requireFetchRecord looks up the FactRecord for coord. It tries the
// configured fetch pipeline version first (a proxy-verified record always
// wins), then the local-ingest pipeline version (modules ingested from a
// local working tree), then falls back to the extraction pipeline version.
// Returns ErrModuleNotFetched if no record is found.
func (uc *ExtractLicenseUseCase) requireFetchRecord(
	ctx context.Context,
	coord coordinate.ModuleCoordinate,
) (domain.FactRecord, error) {
	versions := []string{uc.fetchPipelineVersion, uc.localFetchPipelineVersion, uc.pipelineVersion}
	seen := map[string]bool{}
	for _, v := range versions {
		if v == "" || seen[v] {
			continue
		}
		seen[v] = true
		r, ok, err := uc.facts.GetFetchRecord(ctx, coord, v)
		if err != nil {
			return domain.FactRecord{}, fmt.Errorf("checking fetch record (pipeline %s): %w", v, err)
		}
		if ok {
			return r, nil
		}
	}
	return domain.FactRecord{}, fmt.Errorf("%w: %s", ports.ErrModuleNotFetched, coord)
}

// extractFromZip parses the module zip and runs license detection on every
// license-named file (Pass 1). When perFile is true and Pass 1 finds nothing,
// a second pass scans root-level.go files for SPDX headers and embedded
// copyright blocks.
func (uc *ExtractLicenseUseCase) extractFromZip(
	ctx context.Context,
	log *slog.Logger,
	coord coordinate.ModuleCoordinate,
	zipData []byte,
	perFile bool,
) (domain2.LicenseRecord, error) {
	archive, err := ziparchive.New(zipData)
	if err != nil {
		return domain2.LicenseRecord{}, fmt.Errorf("parsing zip: %w", err)
	}

	modulePrefix := coord.Path + "@" + coord.Version + "/"
	var entries []domain2.LicenseFileEntry

	for _, name := range archive.Names() {
		if !strings.HasPrefix(name, modulePrefix) {
			continue
		}
		relPath := strings.TrimPrefix(name, modulePrefix)
		if !isLicenceFilename(relPath) {
			continue
		}
		if ctxErr := ctx.Err(); ctxErr != nil {
			return domain2.LicenseRecord{}, fmt.Errorf("license extraction cancelled: %w", ctxErr)
		}

		entry, entryErr := uc.processFile(ctx, archive, name, relPath)
		if entryErr != nil {
			log.InfoContext(ctx, "licence_file_skipped",
				slog.String("path", relPath),
				slog.String("error", entryErr.Error()),
			)
			entries = append(entries, domain2.LicenseFileEntry{
				Path:       relPath,
				IsVendored: isVendored(relPath),
			})
			continue
		}
		entries = append(entries, entry)
	}

	// Pass 2: if no license files were found and per-file mode is enabled,
	// sample root-level.go files for embedded SPDX headers / copyright blocks.
	if len(entries) == 0 && perFile {
		entries = uc.scanSourceFiles(ctx, log, coord, archive)
	}

	// Pass 3: if license files were found but yielded no copyright (common
	// when a project puts only the Apache/MIT boilerplate in LICENSE and keeps
	// copyright headers in source files — e.g. cobra), scan root-level.go
	// files for copyright-only statements and attach them to entries.
	if len(entries) > 0 && deriveCopyrightStatus(entries) == domain2.CopyrightStatusNoneFound {
		uc.backfillCopyrightFromSource(ctx, coord, archive, entries)
	}

	// Sort for determinism.
	sort.Slice(entries, func(i, j int) bool {
		return entries[i].Path < entries[j].Path
	})
	for i := range entries {
		sort.Slice(entries[i].AltMatches, func(a, b int) bool {
			return entries[i].AltMatches[a].Confidence > entries[i].AltMatches[b].Confidence
		})
		sort.Slice(entries[i].CopyrightStatements, func(a, b int) bool {
			return entries[i].CopyrightStatements[a].Verbatim < entries[i].CopyrightStatements[b].Verbatim
		})
	}

	primarySPDX, primaryConf, status := deriveStatus(entries)
	expression := domain2.DeriveExpression(entries)
	copyrightStatus := deriveCopyrightStatus(entries)

	provenance := domain2.ExtractProvenance(modulePrefix, archive.Names(), func(name string) ([]byte, bool, error) {
		return archive.ReadFile(name)
	})
	provenance.Confidence = domain2.DeriveProvenanceConfidence(provenance, copyrightStatus)

	return domain2.LicenseRecord{
		SchemaVersion:     domain2.LicenseSchemaVersion,
		Ecosystem:         domain.EcosystemGo,
		Coordinate:        coord,
		PrimarySPDX:       primarySPDX,
		Expression:        expression,
		PrimaryConfidence: primaryConf,
		LicenseFiles:      entries,
		EffectiveSet:      domain2.DeriveEffectiveLicenseSet(entries),
		PackageLicenses:   domain2.DerivePackageLicenses(entries),
		OverallStatus:     status,
		CopyrightStatus:   copyrightStatus,
		Provenance:        provenance,
		ExtractedAt:       uc.clock.Now().UTC(),
		PipelineVersion:   uc.pipelineVersion,
	}, nil
}

// processFile reads one zip entry, hashes its content, and runs the detector.
func (uc *ExtractLicenseUseCase) processFile(
	ctx context.Context,
	archive *ziparchive.Archive,
	name, relPath string,
) (domain2.LicenseFileEntry, error) {
	content, found, err := archive.ReadFile(name)
	if err != nil {
		return domain2.LicenseFileEntry{}, fmt.Errorf("reading zip entry: %w", err)
	}
	if !found {
		return domain2.LicenseFileEntry{}, fmt.Errorf("zip entry %q not found", name)
	}

	sum := sha256.Sum256(content)
	fileHash := "sha256:" + hex.EncodeToString(sum[:])

	match, err := uc.detector.Detect(ctx, content)
	if err != nil {
		return domain2.LicenseFileEntry{}, fmt.Errorf("detecting license: %w", err)
	}

	var alts []domain2.AltMatch
	for _, a := range match.AltMatches {
		if a.SPDX != "" {
			alts = append(alts, domain2.AltMatch{SPDX: a.SPDX, Confidence: a.Confidence})
		}
	}

	// Phase 1: extract copyright from root-level non-vendored files only.
	var stmts []domain2.CopyrightStatement
	if !isVendored(relPath) && isRootLevel(relPath) {
		stmts = domain2.ExtractCopyright(relPath, content)
	}

	return domain2.LicenseFileEntry{
		Path:                  relPath,
		SPDX:                  match.SPDX,
		Confidence:            match.Confidence,
		FileHash:              fileHash,
		FileSize:              int64(len(content)),
		IsVendored:            isVendored(relPath),
		AltMatches:            alts,
		CopyrightStatements:   stmts,
		LowConfidenceSPDX:     match.LowConfidenceSPDX,
		LowConfidenceCoverage: match.LowConfidenceCoverage,
	}, nil
}

// compoundConfDelta is the maximum confidence difference that identifies a
// compound LICENSE file (one file intentionally containing multiple full
// license texts). When the best alternative is within this tiny margin the
// licensecheck library has found multiple complete license texts in the same
// file — e.g. yaml.v3's "MIT and Apache" LICENSE or klauspost/compress's
// combined BSD-3-Clause + Apache-2.0 file. Treat as Multiple so the verbatim
// text (which contains all licences) satisfies attribution automatically.
const compoundConfDelta = 0.005

// ambiguousConfDelta is the maximum difference in confidence between the
// primary match and its best alternative before the result is called
// Ambiguous. A primary at 0.99 with an alt at 0.50 is clearly Detected;
// a primary at 0.85 with an alt at 0.82 is genuinely Ambiguous.
const ambiguousConfDelta = 0.10

// deriveStatus determines the primary SPDX, confidence, and overall status
// from the extracted license file entries.
func deriveStatus(entries []domain2.LicenseFileEntry) (primarySPDX string, primaryConf float64, status domain2.LicenseStatus) {
	// Only root-level, non-vendored, non-notice files determine the primary
	// license. NOTICE files are collected for reproduction (Apache §4(d)) but
	// do not define the module's SPDX identity.
	var roots []domain2.LicenseFileEntry
	for _, e := range entries {
		if !e.IsVendored && isRootLevel(e.Path) && !isNoticeName(e.Path) {
			roots = append(roots, e)
		}
	}

	if len(roots) == 0 {
		return "", 0, domain2.LicenseStatusNone
	}

	// Sort root files by Confidence descending for primary selection.
	sort.Slice(roots, func(i, j int) bool {
		return roots[i].Confidence > roots[j].Confidence
	})

	primary := roots[0]
	if primary.SPDX == "" {
		// Root-level license files exist but none matched a known SPDX identifier.
		// Common causes: custom commercial text, "All rights reserved" notices,
		// proprietary agreements. Distinct from None (no license files at all).
		return "", 0, domain2.LicenseStatusUnclassified
	}

	// When every root entry came from a source-file header rather than a
	// dedicated license file, reflect that in the status.
	allPerFile := true
	for _, r := range roots {
		if !r.IsPerFile {
			allPerFile = false
			break
		}
	}
	if allPerFile {
		return primary.SPDX, primary.Confidence, domain2.LicenseStatusPerFile
	}

	if len(roots) == 1 {
		if len(primary.AltMatches) > 0 {
			delta := primary.Confidence - primary.AltMatches[0].Confidence
			// Compound file: multiple full license texts present at essentially
			// equal coverage (e.g. yaml.v3 "MIT and Apache", klauspost/compress
			// BSD-3-Clause + Apache-2.0). The verbatim text already satisfies
			// all license obligations, so surface as Multiple rather than Ambiguous.
			if delta <= compoundConfDelta {
				return primary.SPDX, primary.Confidence, domain2.LicenseStatusMultiple
			}
			// Ambiguous: one genuine candidate with a close competitor.
			if delta <= ambiguousConfDelta {
				return primary.SPDX, primary.Confidence, domain2.LicenceStatusAmbiguous
			}
		}
		return primary.SPDX, primary.Confidence, domain2.LicenseStatusDetected
	}

	// Multiple root-level files: if all identified licences are the same
	// SPDX identifier, still report Detected (e.g., two copies of MIT).
	for _, r := range roots[1:] {
		if r.SPDX != "" && r.SPDX != primary.SPDX {
			return primary.SPDX, primary.Confidence, domain2.LicenseStatusMultiple
		}
	}
	return primary.SPDX, primary.Confidence, domain2.LicenseStatusDetected
}

// deriveCopyrightStatus determines the overall copyright status from the
// extracted entries. Returns Found if any root-level non-vendored file
// contains copyright statements, NoneFound otherwise.
func deriveCopyrightStatus(entries []domain2.LicenseFileEntry) domain2.CopyrightStatus {
	for _, e := range entries {
		if !e.IsVendored && isRootLevel(e.Path) && len(e.CopyrightStatements) > 0 {
			return domain2.CopyrightStatusFound
		}
	}
	return domain2.CopyrightStatusNoneFound
}

// scanSourceFiles samples root-level.go files from the archive, looking for
// SPDX-License-Identifier headers (fast path) and high-confidence license text
// detected by the full scanner (slow path). It returns at most perFileMaxFiles
// entries and stops once it has read perFileMaxTotalBytes of content.
func (uc *ExtractLicenseUseCase) scanSourceFiles(
	ctx context.Context,
	log *slog.Logger,
	coord coordinate.ModuleCoordinate,
	archive *ziparchive.Archive,
) []domain2.LicenseFileEntry {
	modulePrefix := coord.Path + "@" + coord.Version + "/"
	var entries []domain2.LicenseFileEntry
	totalBytes := 0
	fileCount := 0

	for _, name := range archive.Names() {
		if !strings.HasPrefix(name, modulePrefix) {
			continue
		}
		relPath := strings.TrimPrefix(name, modulePrefix)
		if !isRootLevel(relPath) || !strings.HasSuffix(relPath, ".go") {
			continue
		}
		if fileCount >= perFileMaxFiles || totalBytes >= perFileMaxTotalBytes {
			break
		}
		if ctxErr := ctx.Err(); ctxErr != nil {
			break
		}

		content, found, err := archive.ReadFile(name)
		if err != nil || !found {
			log.InfoContext(ctx, "per_file_read_skipped", slog.String("path", relPath))
			continue
		}
		if len(content) > perFileMaxFileBytes {
			content = content[:perFileMaxFileBytes]
		}
		totalBytes += len(content)
		fileCount++

		// Fast path: look for SPDX-License-Identifier in the first 4 KB.
		scanLen := perFileSPDXScanBytes
		if len(content) < scanLen {
			scanLen = len(content)
		}
		if spdx := parseSPDXHeader(content[:scanLen]); spdx != "" {
			sum := sha256.Sum256(content)
			entries = append(entries, domain2.LicenseFileEntry{
				Path:       relPath,
				SPDX:       spdx,
				Confidence: 1.0,
				FileHash:   "sha256:" + hex.EncodeToString(sum[:]),
				FileSize:   int64(len(content)),
				IsPerFile:  true,
			})
			continue
		}

		// Slow path: run the full detector and record confident matches.
		match, err := uc.detector.Detect(ctx, content)
		if err != nil || match.SPDX == "" || match.Confidence < perFileConfThreshold {
			continue
		}
		sum := sha256.Sum256(content)
		entries = append(entries, domain2.LicenseFileEntry{
			Path:       relPath,
			SPDX:       match.SPDX,
			Confidence: match.Confidence,
			FileHash:   "sha256:" + hex.EncodeToString(sum[:]),
			FileSize:   int64(len(content)),
			IsPerFile:  true,
		})
	}
	return entries
}

// backfillCopyrightFromSource scans .go files for copyright headers and appends
// found statements to the first non-vendored root license entry. This handles
// modules that carry copyright only in source file headers (e.g. cobra, which
// puts "Copyright 2013-2023 The Cobra Authors" in every .go file but not in
// LICENSE.txt).
//
// The whole module tree is walked, not just its root: nested layouts are the
// norm, and restricting to root-level files reported "none found" for any module
// whose packages all live under subdirectories. Vendored paths are excluded —
// their copyright belongs to the vendored dependency, not to this module.
//
// Statements are deduplicated across files; only unique Verbatim lines are kept.
// At most copyrightMaxFiles .go files are read to bound the cost. Names are
// walked in sorted order so that which files fall inside that bound is
// deterministic across runs rather than dependent on archive ordering.
func (uc *ExtractLicenseUseCase) backfillCopyrightFromSource(
	ctx context.Context,
	coord coordinate.ModuleCoordinate,
	archive *ziparchive.Archive,
	entries []domain2.LicenseFileEntry,
) {
	modulePrefix := coord.Path + "@" + coord.Version + "/"
	seen := make(map[string]bool)
	var collected []domain2.CopyrightStatement
	fileCount := 0

	names := append([]string(nil), archive.Names()...)
	sort.Strings(names)

	for _, name := range names {
		if fileCount >= copyrightMaxFiles {
			break
		}
		if !strings.HasPrefix(name, modulePrefix) {
			continue
		}
		relPath := strings.TrimPrefix(name, modulePrefix)
		if !strings.HasSuffix(relPath, ".go") || isVendored(relPath) {
			continue
		}
		if ctxErr := ctx.Err(); ctxErr != nil {
			return
		}

		content, found, err := archive.ReadFile(name)
		if err != nil || !found {
			continue
		}
		// Only scan the first 4 KB — copyright headers appear at the top.
		scanLen := 4096
		if len(content) < scanLen {
			scanLen = len(content)
		}
		fileCount++

		for _, stmt := range domain2.ExtractCopyright(relPath, content[:scanLen]) {
			if !seen[stmt.Verbatim] {
				seen[stmt.Verbatim] = true
				// Source field: use a canonical marker so consumers know these
				// came from source headers, not a root license file.
				stmt.Source = "<source-headers>"
				collected = append(collected, stmt)
			}
		}
	}

	if len(collected) == 0 {
		return
	}

	// Attach to the first non-vendored root license entry so
	// deriveCopyrightStatus picks them up.
	for i := range entries {
		if !entries[i].IsVendored && isRootLevel(entries[i].Path) {
			entries[i].CopyrightStatements = append(entries[i].CopyrightStatements, collected...)
			sort.Slice(entries[i].CopyrightStatements, func(a, b int) bool {
				return entries[i].CopyrightStatements[a].Verbatim < entries[i].CopyrightStatements[b].Verbatim
			})
			return
		}
	}
}

// parseSPDXHeader scans content for an SPDX-License-Identifier comment line
// and returns the identifier, or an empty string if none is found.
// It handles //, #, and /* comment styles.
func parseSPDXHeader(content []byte) string {
	const marker = "SPDX-License-Identifier:"
	remaining := content
	for len(remaining) > 0 {
		var line []byte
		if idx := bytes.IndexByte(remaining, '\n'); idx >= 0 {
			line = remaining[:idx]
			remaining = remaining[idx+1:]
		} else {
			line = remaining
			remaining = nil
		}
		// Strip comment prefix characters and surrounding whitespace.
		s := strings.TrimSpace(string(line))
		s = strings.TrimLeft(s, "/*#")
		s = strings.TrimSpace(s)
		// Handle trailing */ for block comments.
		s = strings.TrimRight(s, "/ *")
		s = strings.TrimSpace(s)
		if after, ok := strings.CutPrefix(s, marker); ok {
			id := strings.TrimSpace(after)
			if id != "" {
				return id
			}
		}
	}
	return ""
}

// isLicenceFilename reports whether the base name of relPath is a recognised
// license filename. Comparison is case-insensitive.
//
// The common license stems (LICENSE, LICENCE, COPYING, UNLICENSE) are matched
// when they stand alone, carry a hyphenated variant suffix (LICENSE-MIT), or
// carry a dotted suffix of any form (LICENSE.txt, LICENSE.MIT, LICENSE.MPL-2.0,
// LICENSE.code, COPYING.md). The dotted form covers both file extensions and
// the per-license naming (LICENSE.<spdx>) used by dual-licensed modules such
// as go-errors/errors (LICENSE.MIT) and spdx/tools-golang (LICENSE.code,
// LICENSE.docs). COPYRIGHT, NOTICE, and the GPLv2/GPLv3 shorthands are matched
// verbatim only.
//
// The dotted suffix is rejected when it is a known source-code extension
// (e.g. LICENSE.go): a Go source file is never the license grant for a
// module, even when its base name happens to start with a license stem
// (github.com/google/licensecheck's license.go is such a file).
func isLicenceFilename(relPath string) bool {
	base := relPath
	if idx := strings.LastIndex(relPath, "/"); idx >= 0 {
		base = relPath[idx+1:]
	}
	upper := strings.ToUpper(base)
	switch upper {
	case "COPYRIGHT", "NOTICE", "GPLV2", "GPLV3":
		return true
	}
	for _, stem := range []string{"LICENSE", "LICENCE", "COPYING", "UNLICENSE"} {
		if upper == stem || strings.HasPrefix(upper, stem+"-") {
			return true
		}
		if strings.HasPrefix(upper, stem+".") {
			return upper[len(stem)+1:] != "GO"
		}
	}
	return false
}

// isNoticeName reports whether the base name of relPath is a NOTICE file.
// NOTICE files must be reproduced for Apache §4(d) compliance but do not
// define the module's SPDX license identity.
func isNoticeName(relPath string) bool {
	base := relPath
	if idx := strings.LastIndex(relPath, "/"); idx >= 0 {
		base = relPath[idx+1:]
	}
	return strings.EqualFold(base, "NOTICE") || strings.EqualFold(base, "NOTICE.txt") || strings.EqualFold(base, "NOTICE.md")
}

// isVendored reports whether a module-root-relative path lives under vendor/.
func isVendored(relPath string) bool {
	return strings.HasPrefix(relPath, "vendor/") || strings.Contains(relPath, "/vendor/")
}

// isRootLevel reports whether relPath has no directory separator (sits at the
// module root).
func isRootLevel(relPath string) bool {
	return !strings.Contains(relPath, "/")
}
