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

// ModcacheHandleDeriver derives deterministic blob handles for a coordinate so
// the fetch pipeline can record a module's location without copying its bytes
// into the blob store. It is the seam that puts the use case in
// --from-modcache mode: set it via WithModcache. Both methods are pure — they
// never touch the filesystem — so a handle can be recorded before (or without)
// the corresponding bytes being read.
type ModcacheHandleDeriver interface {
	ZipHandle(coord coordinate.ModuleCoordinate) (ports.BlobHandle, error)
	GoModHandle(coord coordinate.ModuleCoordinate) (ports.BlobHandle, error)
}

// WithModcache switches the use case into --from-modcache mode. In this mode
// Execute reads module bytes from the module-cache-backed proxy, verifies each
// module's h1 against the local go.sum (a mismatch or missing entry is a hard
// ErrGoSumVerification failure), and records ContentLocation/GoModLocation as
// deterministic module-cache handles derived from the coordinate — never
// calling blobs.Put. A nil deriver (the default) leaves the network+blobstore
// path untouched. Returns uc for chaining.
func (uc *FetchModuleUseCase) WithModcache(deriver ModcacheHandleDeriver) *FetchModuleUseCase {
	uc.modcache = deriver
	return uc
}

// executeModcache runs the fetch-verify-persist pipeline against the module
// cache. It is the --from-modcache counterpart to Execute: no network proxy, no
// checksum-database round-trip, no blob writes. Verification is against the
// local go.sum only and VCS cross-verification is skipped, so the recorded
// status is VerifiedBySumDBOnly.
func (uc *FetchModuleUseCase) executeModcache(ctx context.Context, req FetchRequest) (_ FetchResult, retErr error) {
	if req.GoModOnly {
		return uc.executeGoModOnlyModcache(ctx, req)
	}

	traceID := ulid.Make().String()
	lap := uc.stopwatch.Start()

	log := uc.logger.With(
		slog.String("module_path", req.Coordinate.Path),
		slog.String("module_version", req.Coordinate.Version),
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
		existing, ok, err := uc.facts.GetFetchRecord(ctx, req.Coordinate, uc.pipelineVersion)
		if err != nil {
			return FetchResult{}, fmt.Errorf("checking cache: %w", err)
		}
		if ok && !existing.IsGoModOnly() {
			log.InfoContext(ctx, "cache_hit")
			return FetchResult{Record: existing, FromCache: true}, nil
		}
		if ok {
			log.InfoContext(ctx, "cache_upgrade_gomod_only_to_full")
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

	zipData, err := io.ReadAll(dl.Zip)
	if err != nil {
		return FetchResult{}, fmt.Errorf("reading zip: %w", err)
	}
	goModData, err := io.ReadAll(dl.GoMod)
	if err != nil {
		return FetchResult{}, fmt.Errorf("reading go.mod: %w", err)
	}
	log.InfoContext(ctx, "download_ok", slog.Int("zip_bytes", len(zipData)))

	// Step 3: verify against the local go.sum. A missing entry or a hash
	// mismatch is a hard failure — no blob is stored and no record is written.
	if err := uc.verifyAgainstGoSum(ctx, req.Coordinate, dl); err != nil {
		return FetchResult{}, err
	}
	log.InfoContext(ctx, "gosum_verified", slog.String("zip_hash", dl.ZipHash.String()))

	// Sign-on-process call site 1: fetch-receive.
	if err := uc.sign(ctx, log, req.Coordinate, domain2.SubjectBlob, domain2.ContentDigest(zipData)); err != nil {
		return FetchResult{}, err
	}

	// Step 4: derive module-cache handles from the coordinate — no blobs.Put.
	contentLocation, err := uc.modcache.ZipHandle(req.Coordinate)
	if err != nil {
		return FetchResult{}, fmt.Errorf("deriving zip handle: %w", err)
	}
	goModLocation, err := uc.modcache.GoModHandle(req.Coordinate)
	if err != nil {
		return FetchResult{}, fmt.Errorf("deriving go.mod handle: %w", err)
	}

	// Step 5: construct the record. Retraction is still parsed from go.mod; VCS
	// cross-verification is skipped, so the status reflects go.sum only.
	retracted := parseRetracted(goModData, req.Coordinate.Version)
	if retracted {
		log.InfoContext(ctx, "retracted_version_detected")
	}
	m := domain2.FetchedModule{
		Coordinate:         req.Coordinate,
		ModuleHash:         dl.ZipHash,
		GoModHash:          dl.GoModHash,
		Digests:            dl.Digests,
		VerificationStatus: domain2.VerifiedBySumDBOnly,
		VerificationDetail: "verified against local go.sum (modcache mode); VCS cross-verification skipped",
		FetchedAt:          uc.clock.Now().UTC(),
		PipelineVersion:    uc.pipelineVersion,
		ContentLocation:    string(contentLocation),
		GoModLocation:      string(goModLocation),
		Retracted:          retracted,
	}
	record := domain2.NewFactRecord(m)

	record, err = uc.hasher.SetContentHash(record)
	if err != nil {
		return FetchResult{}, fmt.Errorf("computing content hash: %w", err)
	}

	// Step 6: persist.
	if err := uc.facts.PutFetchRecord(ctx, record); err != nil {
		return FetchResult{}, fmt.Errorf("persisting fact record: %w", err)
	}
	log.InfoContext(ctx, "record_persisted",
		slog.String("verification_status", string(domain2.VerifiedBySumDBOnly)),
		slog.String("content_hash", record.ContentHash),
	)

	// Sign-on-process call site 2: fact-produce.
	if err := uc.sign(ctx, log, req.Coordinate, domain2.SubjectFact, record.ContentHash); err != nil {
		return FetchResult{}, err
	}

	return FetchResult{Record: record, FromCache: false}, nil
}

// executeGoModOnlyModcache is the go.mod-only counterpart to executeModcache:
// it reads only the module's go.mod from the cache, verifies its h1 against the
// local go.sum, and records a go.mod-only fact (GoModLocation set,
// ContentLocation empty) using the module-cache handle deriver — no zip read,
// no blob write. It is the --from-modcache analogue of executeGoModOnly.
func (uc *FetchModuleUseCase) executeGoModOnlyModcache(ctx context.Context, req FetchRequest) (_ FetchResult, retErr error) {
	traceID := ulid.Make().String()
	lap := uc.stopwatch.Start()

	log := uc.logger.With(
		slog.String("module_path", req.Coordinate.Path),
		slog.String("module_version", req.Coordinate.Version),
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
		existing, ok, err := uc.facts.GetFetchRecord(ctx, req.Coordinate, uc.pipelineVersion)
		if err != nil {
			return FetchResult{}, fmt.Errorf("checking cache: %w", err)
		}
		if ok {
			log.InfoContext(ctx, "cache_hit")
			return FetchResult{Record: existing, FromCache: true}, nil
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
	if err := uc.verifyGoModAgainstGoSum(ctx, req.Coordinate, dl); err != nil {
		return FetchResult{}, err
	}
	log.InfoContext(ctx, "gosum_verified", slog.String("go_mod_hash", dl.GoModHash.String()))

	if err := uc.sign(ctx, log, req.Coordinate, domain2.SubjectBlob, domain2.ContentDigest(goModData)); err != nil {
		return FetchResult{}, err
	}

	// Step 4: derive the go.mod handle only — no zip handle, no blobs.Put.
	goModLocation, err := uc.modcache.GoModHandle(req.Coordinate)
	if err != nil {
		return FetchResult{}, fmt.Errorf("deriving go.mod handle: %w", err)
	}

	retracted := parseRetracted(goModData, req.Coordinate.Version)
	if retracted {
		log.InfoContext(ctx, "retracted_version_detected")
	}
	m := domain2.FetchedModule{
		Coordinate:         req.Coordinate,
		GoModHash:          dl.GoModHash,
		VerificationStatus: domain2.VerifiedBySumDBOnly,
		VerificationDetail: "go.mod-only fetch (modcache); go.mod verified against local go.sum; zip not read",
		FetchedAt:          uc.clock.Now().UTC(),
		PipelineVersion:    uc.pipelineVersion,
		GoModLocation:      string(goModLocation),
		Retracted:          retracted,
	}
	record := domain2.NewFactRecord(m)

	record, err = uc.hasher.SetContentHash(record)
	if err != nil {
		return FetchResult{}, fmt.Errorf("computing content hash: %w", err)
	}

	if err := uc.facts.PutFetchRecord(ctx, record); err != nil {
		return FetchResult{}, fmt.Errorf("persisting fact record: %w", err)
	}
	log.InfoContext(ctx, "record_persisted",
		slog.String("verification_status", string(domain2.VerifiedBySumDBOnly)),
		slog.String("content_hash", record.ContentHash),
	)

	if err := uc.sign(ctx, log, req.Coordinate, domain2.SubjectFact, record.ContentHash); err != nil {
		return FetchResult{}, err
	}

	return FetchResult{Record: record, FromCache: false}, nil
}

// verifyGoModAgainstGoSum checks a go.mod-only fetch's go.mod h1 against the
// local go.sum entry surfaced by the SumDBClient. A module absent from go.sum,
// or whose go.mod hash disagrees, yields ErrGoSumVerification. It is the
// go.mod-only analogue of verifyAgainstGoSum.
func (uc *FetchModuleUseCase) verifyGoModAgainstGoSum(ctx context.Context, coord coordinate.ModuleCoordinate, dl ports.GoModDownload) error {
	res := uc.sumdb.Lookup(ctx, coord)
	if !res.Available {
		return fmt.Errorf("%w: %s: %s", ErrGoSumVerification, coord, res.Reason)
	}
	if !res.GoModHash.IsZero() && !res.GoModHash.Equal(dl.GoModHash) {
		return fmt.Errorf("%w: %s: go.sum expects go.mod %s but module cache has %s",
			ErrGoSumVerification, coord, res.GoModHash, dl.GoModHash)
	}
	return nil
}

// verifyAgainstGoSum checks the module's computed h1 hashes against the local
// go.sum entries surfaced by the SumDBClient. A module absent from go.sum, or
// whose zip/go.mod hash disagrees, yields ErrGoSumVerification.
func (uc *FetchModuleUseCase) verifyAgainstGoSum(ctx context.Context, coord coordinate.ModuleCoordinate, dl ports.ModuleDownload) error {
	res := uc.sumdb.Lookup(ctx, coord)
	if !res.Available {
		return fmt.Errorf("%w: %s: %s", ErrGoSumVerification, coord, res.Reason)
	}
	if !res.ZipHash.Equal(dl.ZipHash) {
		return fmt.Errorf("%w: %s: go.sum expects zip %s but module cache has %s",
			ErrGoSumVerification, coord, res.ZipHash, dl.ZipHash)
	}
	// The go.mod hash is verified only when go.sum records one (it always does
	// for module-era dependencies). A zero recorded hash means go.sum has no
	// /go.mod line — do not manufacture a mismatch from its absence.
	if !res.GoModHash.IsZero() && !res.GoModHash.Equal(dl.GoModHash) {
		return fmt.Errorf("%w: %s: go.sum expects go.mod %s but module cache has %s",
			ErrGoSumVerification, coord, res.GoModHash, dl.GoModHash)
	}
	return nil
}
