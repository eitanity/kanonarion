package application

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"

	"github.com/eitanity/kanonarion/internal/coordinate"

	domain2 "github.com/eitanity/kanonarion/internal/fetch/domain"
	"github.com/eitanity/kanonarion/internal/fetch/ports"

	"github.com/oklog/ulid/v2"
)

// ErrGoSumVerification marks a hard go.sum verification failure. It is raised
// in two places, both tamper-evidence:
//   - --from-modcache mode, where go.sum is the sole anchor: a module whose
//     computed h1 does not match its go.sum entry, OR which is absent from
//     go.sum entirely (see verifyAgainstGoSum).
//   - the normal network path, where a project go.sum is an additional anchor
//     layered onto network sumdb verification: a module present in go.sum whose
//     computed zip/go.mod h1 disagrees (see checkProjectGoSum). Absence from
//     go.sum is NOT a failure there — it falls through to network sumdb.
//
// Callers match it with errors.Is to distinguish a tamper failure from an
// ordinary fetch error.
var ErrGoSumVerification = errors.New("go.sum verification failed")

// WithModcacheMode switches the use case into --from-modcache mode. In this mode
// Execute reads module bytes from the module-cache-backed proxy and verifies each
// module's h1 against the local go.sum (a mismatch or missing entry is a hard
// ErrGoSumVerification failure) instead of consulting the network checksum
// database. Returns uc for chaining.
//
// It used to take a handle deriver, which produced "modcache:zip:<coord>"
// addresses from the coordinate and wrote them into records instead of calling
// blobs.Put. Those addresses were mode-locked: only the module-cache adapter
// resolved them, so a record written here was unreadable by a later ordinary
// run, and the same artefact measured both ways yielded two irreconcilable
// records. The mode now stores bytes under the artefact identity it measured,
// exactly like every other path, so nothing about the record betrays which mode
// wrote it beyond the acquisition-mode provenance field.
func (uc *FetchModuleUseCase) WithModcacheMode() *FetchModuleUseCase {
	uc.modcache = true
	return uc
}

// executeModcache runs the fetch-verify-persist pipeline against the module
// cache. It is the --from-modcache counterpart to Execute: no network proxy and
// no checksum-database round-trip. The bytes it reads are still stored, under the
// artefact identity it measured, so a later ordinary run finds them.
//
// The local go.sum is the sole anchor and no transparency-log query is made, so
// the record states exactly that: VerifiedByGoSum, and no checksum-database
// validation leg. Recording the log's status here would have an air-gapped run
// report an anchor it never reached, and rank it level with a run that did.
func (uc *FetchModuleUseCase) executeModcache(ctx context.Context, req FetchRequest) (_ FetchResult, retErr error) {
	return uc.executeFromCache(ctx, req, cacheRoute{
		anchor:      uc.sumdb,
		detail:      "verified against local go.sum (modcache mode); VCS cross-verification skipped",
		goModDetail: "go.mod-only fetch (modcache); go.mod verified against local go.sum; zip not read",
	})
}

// cacheRoute is how a measurement read from the module cache is anchored and
// described: --from-modcache for every module, or one private module.
type cacheRoute struct {
	anchor      ports.SumDBClient
	detail      string
	goModDetail string
	vcs         domain2.LegProvenance
}

// executeFromCache is executeModcache over an explicit anchor and description.
func (uc *FetchModuleUseCase) executeFromCache(ctx context.Context, req FetchRequest, route cacheRoute) (_ FetchResult, retErr error) {
	if req.GoModOnly {
		return uc.executeGoModOnlyModcache(ctx, req, route)
	}

	traceID := ulid.Make().String()
	lap := uc.stopwatch.Start()

	log := uc.logger.With(
		slog.String("module_path", req.Coordinate.Path()),
		slog.String("module_version", req.Coordinate.Version()),
		slog.String("pipeline_version", uc.pipelineVersion),
		slog.String("trace_id", traceID),
		slog.Bool("from_modcache", true),
	)
	log.InfoContext(ctx, "fetch_start")
	defer func() {
		log.InfoContext(ctx, "fetch_end", slog.Duration("duration", lap.Elapsed()))
	}()

	// Step 1: cache check — identical to the network path. A go.mod-only record
	// does not satisfy the full path; re-fetch over it so PutFetchRecord upgrades
	// it in place.
	if !req.Force {
		if res, hit, cerr := uc.cachedModcache(ctx, log, req); cerr != nil || hit {
			return res, cerr
		}
	}

	// Step 2: read bytes from the module cache (the proxy fetches into the cache
	// via `go mod download` on a miss). Hashes are computed from the bytes.
	dl, err := uc.proxy.Download(ctx, req.Coordinate)
	if err != nil {
		return FetchResult{}, fmt.Errorf("module-cache download: %w", err)
	}
	defer func() {
		if cerr := dl.Zip.Close(); cerr != nil && retErr == nil {
			retErr = fmt.Errorf("closing zip reader: %w", cerr)
		}
	}()
	defer func() {
		if cerr := dl.GoMod.Close(); cerr != nil && retErr == nil {
			retErr = fmt.Errorf("closing go.mod reader: %w", cerr)
		}
	}()

	zipData, goModData, err := readDownload(dl)
	if err != nil {
		return FetchResult{}, err
	}
	log.InfoContext(ctx, "download_ok", slog.Int("zip_bytes", len(zipData)))

	// Step 3: verify against the local go.sum. A missing entry or a hash
	// mismatch is a hard failure — no blob is stored and no record is written.
	if verr := verifyAgainstGoSum(ctx, route.anchor, req.Coordinate, req.OriginalCoordinate, dl); verr != nil {
		return FetchResult{}, verr
	}
	log.InfoContext(ctx, "gosum_verified", slog.String("zip_hash", dl.ZipHash.String()))

	// Sign-on-process call site 1: fetch-receive.
	if serr := uc.sign(ctx, log, req.Coordinate, domain2.SubjectBlob, domain2.ContentDigest(zipData)); serr != nil {
		return FetchResult{}, serr
	}

	// Step 4: store the bytes under the identities just measured. The module-cache
	// blob adapter populates its address space by hard link where it can, so this
	// costs no duplication, and the resulting record names the same address a
	// network measurement of the same artefact would.
	zipIdentity, goModIdentity, err := uc.putModcacheBlobs(ctx, dl, zipData, goModData)
	if err != nil {
		return FetchResult{}, err
	}

	// Step 5: construct the record. Retraction is still parsed from go.mod; VCS
	// cross-verification is skipped, so the status reflects go.sum only.
	retracted := parseRetracted(goModData, req.Coordinate.Version())
	if retracted {
		log.InfoContext(ctx, "retracted_version_detected")
	}
	m := domain2.FetchedModule{
		Coordinate:         req.Coordinate,
		ModuleHash:         dl.ZipHash,
		GoModHash:          dl.GoModHash,
		Digests:            dl.Digests,
		VerificationStatus: domain2.VerifiedByGoSum,
		VerificationDetail: route.detail,
		FetchedAt:          uc.clock.Now().UTC(),
		PipelineVersion:    uc.pipelineVersion,
		ContentLocation:    zipIdentity.String(),
		GoModLocation:      goModIdentity.String(),
		Retracted:          retracted,
		AcquisitionMode:    domain2.AcquisitionModcache,
		MeasurementKind:    domain2.MeasurementAcquired,
		VCSCheck:           route.vcs,
	}

	// Step 6: seal and append. This mode's anchor is the local go.sum alone, so it
	// can never beat a network run's transparency-log record; the composed read
	// serves the stronger measurement and this run adds evidence, replacing none.
	// Sign-on-process call site 2: fact-produce.
	return uc.persistAndSign(ctx, log, req, m)
}

// executeGoModOnlyModcache is the go.mod-only counterpart to executeModcache:
// it reads only the module's go.mod from the cache, verifies its h1 against the
// local go.sum, and records a go.mod-only fact (GoModLocation set,
// ContentLocation empty) — no zip is read. It anchors and records exactly as
// executeModcache does. It is the --from-modcache analogue of executeGoModOnly.
func (uc *FetchModuleUseCase) executeGoModOnlyModcache(ctx context.Context, req FetchRequest, route cacheRoute) (_ FetchResult, retErr error) {
	traceID := ulid.Make().String()
	lap := uc.stopwatch.Start()

	log := uc.logger.With(
		slog.String("module_path", req.Coordinate.Path()),
		slog.String("module_version", req.Coordinate.Version()),
		slog.String("pipeline_version", uc.pipelineVersion),
		slog.String("trace_id", traceID),
		slog.Bool("from_modcache", true),
		slog.Bool("go_mod_only", true),
	)
	log.InfoContext(ctx, "fetch_start")
	defer func() {
		log.InfoContext(ctx, "fetch_end", slog.Duration("duration", lap.Elapsed()))
	}()

	// Step 1: cache check. Any existing record already carries a verified go.mod.
	if !req.Force {
		if res, hit, cerr := uc.cachedGoModOnlyModcache(ctx, log, req); cerr != nil || hit {
			return res, cerr
		}
	}

	// Step 2: read only the go.mod from the cache.
	dl, err := uc.proxy.DownloadGoMod(ctx, req.Coordinate)
	if err != nil {
		return FetchResult{}, fmt.Errorf("module-cache download go.mod: %w", err)
	}
	defer func() {
		if cerr := dl.GoMod.Close(); cerr != nil && retErr == nil {
			retErr = fmt.Errorf("closing go.mod reader: %w", cerr)
		}
	}()
	goModData, err := io.ReadAll(dl.GoMod)
	if err != nil {
		return FetchResult{}, fmt.Errorf("reading go.mod: %w", err)
	}

	// Step 3: verify the go.mod h1 against the local go.sum. A missing entry or a
	// mismatch is a hard failure — no record is written.
	if verr := verifyGoModAgainstGoSum(ctx, route.anchor, req.Coordinate, req.OriginalCoordinate, dl); verr != nil {
		return FetchResult{}, verr
	}
	log.InfoContext(ctx, "gosum_verified", slog.String("go_mod_hash", dl.GoModHash.String()))

	if serr := uc.sign(ctx, log, req.Coordinate, domain2.SubjectBlob, domain2.ContentDigest(goModData)); serr != nil {
		return FetchResult{}, serr
	}

	// Step 4: store the go.mod alone — there is no zip in a go.mod-only fetch.
	goModIdentity, err := ports.NewBlobIdentity(ports.BlobKindGoMod, dl.GoModHash)
	if err != nil {
		return FetchResult{}, fmt.Errorf("addressing go.mod blob: %w", err)
	}
	if perr := uc.blobs.Put(ctx, goModIdentity, newReader(goModData)); perr != nil {
		return FetchResult{}, fmt.Errorf("storing go.mod blob: %w", perr)
	}

	retracted := parseRetracted(goModData, req.Coordinate.Version())
	if retracted {
		log.InfoContext(ctx, "retracted_version_detected")
	}
	m := domain2.FetchedModule{
		Coordinate:         req.Coordinate,
		GoModHash:          dl.GoModHash,
		VerificationStatus: domain2.VerifiedByGoSum,
		VerificationDetail: route.goModDetail,
		FetchedAt:          uc.clock.Now().UTC(),
		PipelineVersion:    uc.pipelineVersion,
		GoModLocation:      goModIdentity.String(),
		Retracted:          retracted,
		AcquisitionMode:    domain2.AcquisitionModcache,
		MeasurementKind:    domain2.MeasurementAcquired,
	}

	stored, err := uc.persistRecord(ctx, log, req, m)
	if err != nil {
		return FetchResult{}, err
	}

	if err := uc.sign(ctx, log, req.Coordinate, domain2.SubjectFact, stored.ContentHash); err != nil {
		return FetchResult{}, err
	}

	return FetchResult{Record: stored, FromCache: false}, nil
}

// cachedModcache serves the stored record when it has a zip and this run can
// read its artefacts; hit reports that it did.
func (uc *FetchModuleUseCase) cachedModcache(ctx context.Context, log *slog.Logger, req FetchRequest) (FetchResult, bool, error) {
	existing, ok, err := ports.AbsentIfNothingServable(uc.facts.GetFetchRecord(ctx, req.Coordinate, uc.pipelineVersion))
	if err != nil {
		return FetchResult{}, false, fmt.Errorf("checking cache: %w", err)
	}
	switch {
	case ok && !uc.cachedArtefactsReadable(ctx, log, existing.FactRecord):
		// A record written by the network path points at content-addressed blobs
		// this mode can still read through the delegate — unless the blob is gone.
		// Re-fetch rather than serve a handle that resolves to nothing.
	case ok && !existing.IsGoModOnly():
		log.InfoContext(ctx, "cache_hit")
		return FetchResult{Record: existing, FromCache: true}, true, nil
	case ok:
		log.InfoContext(ctx, "cache_upgrade_gomod_only_to_full")
	}
	return FetchResult{}, false, nil
}

// putModcacheBlobs stores the zip and go.mod under the identities just measured.
func (uc *FetchModuleUseCase) putModcacheBlobs(ctx context.Context, dl ports.ModuleDownload, zipData, goModData []byte) (ports.BlobIdentity, ports.BlobIdentity, error) {
	zipIdentity, goModIdentity, err := blobIdentities(dl)
	if err != nil {
		return ports.BlobIdentity{}, ports.BlobIdentity{}, err
	}
	if perr := uc.blobs.Put(ctx, zipIdentity, newReader(zipData)); perr != nil {
		return ports.BlobIdentity{}, ports.BlobIdentity{}, fmt.Errorf("storing zip blob: %w", perr)
	}
	if perr := uc.blobs.Put(ctx, goModIdentity, newReader(goModData)); perr != nil {
		return ports.BlobIdentity{}, ports.BlobIdentity{}, fmt.Errorf("storing go.mod blob: %w", perr)
	}
	return zipIdentity, goModIdentity, nil
}

// cachedGoModOnlyModcache serves any stored record whose artefacts this run
// can read; hit reports that it did.
func (uc *FetchModuleUseCase) cachedGoModOnlyModcache(ctx context.Context, log *slog.Logger, req FetchRequest) (FetchResult, bool, error) {
	existing, ok, err := ports.AbsentIfNothingServable(uc.facts.GetFetchRecord(ctx, req.Coordinate, uc.pipelineVersion))
	if err != nil {
		return FetchResult{}, false, fmt.Errorf("checking cache: %w", err)
	}
	if ok && uc.cachedArtefactsReadable(ctx, log, existing.FactRecord) {
		log.InfoContext(ctx, "cache_hit")
		return FetchResult{Record: existing, FromCache: true}, true, nil
	}
	return FetchResult{}, false, nil
}

// verifyGoModAgainstGoSum checks a go.mod-only fetch's go.mod h1 against the
// local go.sum entry surfaced by the SumDBClient. A module absent from go.sum,
// or whose go.mod hash disagrees, yields ErrGoSumVerification. It is the
// go.mod-only analogue of verifyAgainstGoSum.
func verifyGoModAgainstGoSum(ctx context.Context, anchor ports.SumDBClient, coord, original coordinate.ModuleCoordinate, dl ports.GoModDownload) error {
	res := anchor.Lookup(ctx, coord)
	if !res.Available {
		if isReplaced(coord, original) && !res.LookupFailed() {
			return errReplacedModuleNotInGoSum(coord, original, res.Reason)
		}
		return fmt.Errorf("%w: %s: %s", ErrGoSumVerification, coord, res.Reason)
	}
	if !res.GoModHash.IsZero() && !res.GoModHash.Equal(dl.GoModHash) {
		return fmt.Errorf("%w: %s: go.sum expects go.mod %s but module cache has %s",
			ErrGoSumVerification, goSumAnchor(coord, original), res.GoModHash, dl.GoModHash)
	}
	return nil
}

// verifyAgainstGoSum checks the module's computed h1 hashes against the local
// go.sum entries surfaced by the SumDBClient. A module absent from go.sum, or
// whose zip/go.mod hash disagrees, yields ErrGoSumVerification.
func verifyAgainstGoSum(ctx context.Context, anchor ports.SumDBClient, coord, original coordinate.ModuleCoordinate, dl ports.ModuleDownload) error {
	res := anchor.Lookup(ctx, coord)
	if !res.Available {
		if isReplaced(coord, original) && !res.LookupFailed() {
			return errReplacedModuleNotInGoSum(coord, original, res.Reason)
		}
		return fmt.Errorf("%w: %s: %s", ErrGoSumVerification, coord, res.Reason)
	}
	if !res.ZipHash.Equal(dl.ZipHash) {
		return fmt.Errorf("%w: %s: go.sum expects zip %s but module cache has %s",
			ErrGoSumVerification, goSumAnchor(coord, original), res.ZipHash, dl.ZipHash)
	}
	// The go.mod hash is verified only when go.sum records one (it always does
	// for module-era dependencies). A zero recorded hash means go.sum has no
	// /go.mod line — do not manufacture a mismatch from its absence.
	if !res.GoModHash.IsZero() && !res.GoModHash.Equal(dl.GoModHash) {
		return fmt.Errorf("%w: %s: go.sum expects go.mod %s but module cache has %s",
			ErrGoSumVerification, goSumAnchor(coord, original), res.GoModHash, dl.GoModHash)
	}
	return nil
}
