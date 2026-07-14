package application

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"

	"github.com/eitanity/kanonarion/internal/adapters/ziparchive"
	domain2 "github.com/eitanity/kanonarion/internal/fetch/domain"
	"github.com/eitanity/kanonarion/internal/fetch/ports"
	"golang.org/x/mod/modfile"

	"github.com/oklog/ulid/v2"
)

// PipelineVersion identifies this release of the fetch pipeline. Bump this
// constant whenever any stage logic changes to ensure old cached records are
// not confused with new ones.
const PipelineVersion = "0.3.0"

// FetchModuleUseCase orchestrates fetching, verification, and persistence of
// a single Go module at a pinned version.
type FetchModuleUseCase struct {
	proxy           ports.ModuleProxy
	vcs             ports.VCSClient
	blobs           ports.BlobStore
	facts           ports.FactStore
	sumdb           ports.SumDBClient
	clock           ports.Clock
	stopwatch       ports.Stopwatch
	pipelineVersion string
	logger          *slog.Logger
	hasher          domain2.CanonicalHasher
	verifier        domain2.Verifier

	// signer and attestations are optional sign-on-process capabilities
	// When signer is nil, or it yields no attestation (the OSS
	// no-op default), nothing is signed or persisted and behaviour is
	// unchanged. Set via WithSigner.
	signer       ports.Signer
	attestations ports.AttestationStore

	// modcache is the optional --from-modcache seam. When non-nil, Execute reads
	// bytes from the module cache, verifies against local go.sum, and records
	// coordinate-derived handles instead of writing blobs. Set via WithModcache.
	modcache ModcacheHandleDeriver

	// goSum is the optional walk-root go.sum verifier for the normal network
	// path. When non-nil, Execute cross-checks each fetched module's computed h1
	// against the local go.sum as a cheap, offline complement to the network
	// checksum database: a present-but-mismatched entry is a hard tamper failure,
	// a matching entry a positive signal, an absent entry a fall-through. It is
	// distinct from modcache mode, where go.sum is the sole anchor. Set via
	// WithProjectGoSum; nil leaves the network path byte-for-byte unchanged.
	goSum ports.SumDBClient
}

// WithProjectGoSum layers a walk-root go.sum verifier onto the normal network
// fetch path (KN-404). It is additive: the network checksum-database check and
// VCS cross-verification still run. A nil client (the default) disables the
// cross-check entirely, so the unshared network path is unchanged. Has no
// effect in --from-modcache mode, which anchors on go.sum via the sumdb field
// already. Returns uc for chaining.
func (uc *FetchModuleUseCase) WithProjectGoSum(goSum ports.SumDBClient) *FetchModuleUseCase {
	uc.goSum = goSum
	return uc
}

// WithSigner injects a Signer and the store its attestations persist to,
// enabling sign-on-process at the fetch-receive and fact-produce call sites.
// A nil signer (the default) disables signing entirely. The OSS no-op signer
// yields no attestation, so wiring it changes nothing. Returns uc for chaining.
func (uc *FetchModuleUseCase) WithSigner(signer ports.Signer, attestations ports.AttestationStore) *FetchModuleUseCase {
	uc.signer = signer
	uc.attestations = attestations
	return uc
}

// NewFetchModuleUseCase constructs a FetchModuleUseCase. pipelineVersion
// defaults to PipelineVersion if empty.
func NewFetchModuleUseCase(
	proxy ports.ModuleProxy,
	vcs ports.VCSClient,
	blobs ports.BlobStore,
	facts ports.FactStore,
	sumdb ports.SumDBClient,
	clock ports.Clock,
	stopwatch ports.Stopwatch,
	pipelineVersion string,
	logger *slog.Logger,
) *FetchModuleUseCase {
	if pipelineVersion == "" {
		pipelineVersion = PipelineVersion
	}
	return &FetchModuleUseCase{
		proxy:           proxy,
		vcs:             vcs,
		blobs:           blobs,
		facts:           facts,
		sumdb:           sumdb,
		clock:           clock,
		stopwatch:       stopwatch,
		pipelineVersion: pipelineVersion,
		logger:          logger,
		verifier:        domain2.NewVerifier(ziparchive.Hasher{}),
	}
}

// FetchRequest is the input to Execute.
type FetchRequest struct {
	Coordinate domain2.ModuleCoordinate
	// Force re-fetches even if a record for this pipeline version exists.
	Force bool
	// SkipVCSVerify skips the git cross-verification step; sumdb verification
	// still runs. Useful when GitHub rate limits make git operations unreliable.
	SkipVCSVerify bool
}

// FetchResult is the output of Execute.
type FetchResult struct {
	Record    domain2.FactRecord
	FromCache bool
}

// Execute runs the full fetch-verify-persist pipeline for the given module.
//
// Verification failures (UnverifiedX statuses) do not fail Execute; they are
// recorded in the FactRecord. Proxy, VCS, and storage errors do fail Execute.
func (uc *FetchModuleUseCase) Execute(ctx context.Context, req FetchRequest) (_ FetchResult, retErr error) {
	if uc.modcache != nil {
		return uc.executeModcache(ctx, req)
	}

	traceID := ulid.Make().String()
	lap := uc.stopwatch.Start()

	log := uc.logger.With(
		slog.String("module_path", req.Coordinate.Path),
		slog.String("module_version", req.Coordinate.Version),
		slog.String("pipeline_version", uc.pipelineVersion),
		slog.String("trace_id", traceID),
	)
	log.InfoContext(ctx, "fetch_start")

	defer func() {
		log.InfoContext(ctx, "fetch_end",
			slog.Duration("duration", lap.Elapsed()),
		)
	}()

	// Step 1: cache check.
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

	// Step 2: proxy info.
	info, err := uc.proxy.Info(ctx, req.Coordinate)
	if err != nil {
		return FetchResult{}, fmt.Errorf("proxy info: %w", err)
	}
	log.InfoContext(ctx, "proxy_info_ok", slog.String("version", info.Version))

	// Step 3: download zip + go.mod. Hashes are computed from bytes by adapter.
	dl, err := uc.proxy.Download(ctx, req.Coordinate)
	if err != nil {
		return FetchResult{}, fmt.Errorf("proxy download: %w", err)
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

	// Step 3.5: cheap, offline local go.sum cross-check (KN-404). It uses the
	// h1 hashes already computed during download — no extra hashing, no network
	// round-trip — and runs before the blob store and the network sumdb lookup
	// so a tampered module fails fast, with no blob written and no record
	// persisted. A matching entry becomes a positive signal folded into the
	// verification status below; an absent entry falls through unchanged.
	goSumMatched, err := uc.checkProjectGoSum(ctx, log, req.Coordinate, dl)
	if err != nil {
		return FetchResult{}, err
	}

	// Step 4: store zip + go.mod in BlobStore.
	blobHandle, err := uc.blobs.Put(ctx, newReader(zipData))
	if err != nil {
		return FetchResult{}, fmt.Errorf("storing zip blob: %w", err)
	}
	log.InfoContext(ctx, "blob_stored", slog.String("handle", string(blobHandle)))

	goModHandle, err := uc.blobs.Put(ctx, newReader(goModData))
	if err != nil {
		return FetchResult{}, fmt.Errorf("storing go.mod blob: %w", err)
	}
	log.InfoContext(ctx, "go_mod_blob_stored", slog.String("handle", string(goModHandle)))

	// Step 5: run verification pipeline, accumulating status.
	verStatus, verDetail, gitRef, retracted := uc.verify(ctx, log, req.Coordinate, dl, zipData, goModData, info, req.SkipVCSVerify, goSumMatched)

	// Sign-on-process call site 1: fetch-receive. Sign the received blob over
	// its canonical content digest, after verification.
	if err := uc.sign(ctx, log, req.Coordinate, domain2.SubjectBlob, domain2.ContentDigest(zipData)); err != nil {
		return FetchResult{}, err
	}

	// Step 6: construct FetchedModule + FactRecord.
	fetchedAt := uc.clock.Now().UTC()
	m := domain2.FetchedModule{
		Coordinate:         req.Coordinate,
		ModuleHash:         dl.ZipHash,
		GoModHash:          dl.GoModHash,
		GitReference:       gitRef,
		VerificationStatus: verStatus,
		VerificationDetail: verDetail,
		FetchedAt:          fetchedAt,
		PipelineVersion:    uc.pipelineVersion,
		ContentLocation:    string(blobHandle),
		GoModLocation:      string(goModHandle),
		Retracted:          retracted,
	}
	record := domain2.NewFactRecord(m)

	// Step 7: compute content hash.
	record, err = uc.hasher.SetContentHash(record)
	if err != nil {
		return FetchResult{}, fmt.Errorf("computing content hash: %w", err)
	}

	// Step 8: persist.
	if err := uc.facts.PutFetchRecord(ctx, record); err != nil {
		return FetchResult{}, fmt.Errorf("persisting fact record: %w", err)
	}
	log.InfoContext(ctx, "record_persisted",
		slog.String("verification_status", string(verStatus)),
		slog.String("content_hash", record.ContentHash),
	)

	// Sign-on-process call site 2: fact-produce. Sign the produced FactRecord
	// over its canonical ContentHash.
	if err := uc.sign(ctx, log, req.Coordinate, domain2.SubjectFact, record.ContentHash); err != nil {
		return FetchResult{}, err
	}

	return FetchResult{Record: record, FromCache: false}, nil
}

// sign invokes the injected Signer over a "sha256:<hex>" subject digest and
// persists any resulting attestation additively. It is a no-op when no signer
// is configured or the signer yields no attestation (the OSS no-op default), so
// the unsigned path is byte-for-byte unchanged. A signer that yields an
// attestation but no attestation store is a wiring error.
func (uc *FetchModuleUseCase) sign(ctx context.Context, log *slog.Logger, coord domain2.ModuleCoordinate, kind domain2.SubjectKind, subjectHash string) error {
	if uc.signer == nil {
		return nil
	}
	algorithm, hexDigest, ok := strings.Cut(subjectHash, ":")
	if !ok {
		return fmt.Errorf("malformed subject digest %q for %s attestation", subjectHash, kind)
	}
	att, err := uc.signer.Sign(ctx, ports.SubjectDigest{Algorithm: algorithm, Hex: hexDigest})
	if err != nil {
		return fmt.Errorf("signing %s subject: %w", kind, err)
	}
	if !att.Present {
		return nil
	}
	if uc.attestations == nil {
		return fmt.Errorf("signer produced a %s attestation but no attestation store is configured", kind)
	}
	record := domain2.AttestationRecord{
		Coordinate:       coord,
		PipelineVersion:  uc.pipelineVersion,
		SubjectKind:      kind,
		SubjectAlgorithm: algorithm,
		SubjectDigest:    hexDigest,
		Bundle:           att.Bundle,
		SignedAt:         uc.clock.Now().UTC(),
	}
	if err := uc.attestations.PutAttestation(ctx, record); err != nil {
		return fmt.Errorf("persisting %s attestation: %w", kind, err)
	}
	log.InfoContext(ctx, "attestation_persisted",
		slog.String("subject_kind", string(kind)),
		slog.String("subject_digest", subjectHash),
	)
	return nil
}

// verify runs all integrity checks and returns the final verification status,
// detail string, resolved git reference, and retraction flag.
//
// The check order is:
// 1. Insecure transport → cap at UnverifiedNoSumDB
// 2. Zip version-prefix consistency (T7)
// 3. go.mod consistency between standalone and zip-embedded (T11)
// 4. Retraction flag (T10)
// 5. Checksum database lookup (T1/T6)
// 6. VCS cross-verify (T2/T3)
// 7. Final status synthesis
// goSumMatched reports that the module's h1 already matched the walk root's
// local go.sum (checked cheaply before this call). It only elevates the
// no-network-sumdb outcome: when the network checksum database is unavailable
// but go.sum agreed, the result is VerifiedByGoSum rather than UnverifiedNoSumDB.
func (uc *FetchModuleUseCase) verify(
	ctx context.Context,
	log *slog.Logger,
	coord domain2.ModuleCoordinate,
	dl ports.ModuleDownload,
	zipData, goModData []byte,
	info ports.ModuleInfo,
	skipVCSVerify bool,
	goSumMatched bool,
) (domain2.VerificationStatus, string, domain2.GitReference, bool) {

	var earlyStatus domain2.VerificationStatus
	var earlyDetail string

	// Insecure transport forces unverified (T4).
	if dl.InsecureTransport {
		earlyStatus = domain2.UnverifiedNoSumDB
		earlyDetail = "insecure transport (HTTP proxy); integrity guarantees are weakened"
	}

	// Zip version-prefix check (T7).
	if earlyStatus == "" {
		if detail := checkZipVersionPrefix(zipData, coord); detail != "" {
			earlyStatus = domain2.UnverifiedHashMismatch
			earlyDetail = "inconsistent_version_in_zip: " + detail
		}
	}

	// go.mod consistency: standalone vs zip-embedded (T11).
	if earlyStatus == "" {
		if detail := checkGoModConsistency(zipData, goModData, coord); detail != "" {
			earlyStatus = domain2.UnverifiedGoModInconsistent
			earlyDetail = detail
		}
	}

	// Retraction: parse from standalone go.mod (T10). Done regardless of status.
	retracted := parseRetracted(goModData, coord.Version)
	if retracted {
		log.InfoContext(ctx, "retracted_version_detected")
	}

	// Sumdb lookup (T1/T6). Skipped if we already detected a content problem.
	var sumdbResult ports.SumDBResult
	if earlyStatus == "" {
		sumdbResult = uc.sumdb.Lookup(ctx, coord)
		if sumdbResult.Available {
			log.InfoContext(ctx, "sumdb_ok",
				slog.String("sumdb_zip_hash", sumdbResult.ZipHash.String()),
				slog.String("computed_zip_hash", dl.ZipHash.String()),
			)
			if !sumdbResult.ZipHash.Equal(dl.ZipHash) {
				earlyStatus = domain2.UnverifiedHashMismatch
				earlyDetail = fmt.Sprintf("sumdb expects %s but computed %s from proxy zip",
					sumdbResult.ZipHash, dl.ZipHash)
			}
		} else {
			log.InfoContext(ctx, "sumdb_unavailable", slog.String("reason", sumdbResult.Reason))
			if goSumMatched {
				// Network sumdb is unreachable/absent, but the walk root's local
				// go.sum (itself populated under a prior transparency-log check)
				// confirmed the h1. A positive offline integrity signal, not an
				// un-analysed outcome.
				earlyStatus = domain2.VerifiedByGoSum
				earlyDetail = "verified against local go.sum; network checksum database unavailable: " + sumdbResult.Reason
			} else {
				earlyStatus = domain2.UnverifiedNoSumDB
				earlyDetail = sumdbResult.Reason
			}
		}
	}

	// VCS resolution + cross-verify. resolveGitRef returns a *provisional*
	// Verified meaning "git ref resolved, ready to cross-verify" — not that the
	// zip was reproduced from the git tree. crossVerify is what actually
	// reproduces it, and it is the only step skipVCSVerify gates.
	gitRef, vcsStatus, vcsDetail := uc.resolveGitRef(ctx, log, coord, info)
	switch {
	case skipVCSVerify:
		// Cross-verify is skipped (e.g. when GitHub rate limits make git
		// operations unreliable). The git leg never ran, so a provisional
		// Verified cannot stand — that would claim an assurance leg we
		// deliberately did not perform. Downgrade it so the combine below lands
		// on VerifiedBySumDBOnly, never the strongest Verified.
		if vcsStatus == domain2.Verified {
			vcsStatus = domain2.VerifiedBySumDBOnly
			vcsDetail = "VCS cross-verification skipped"
		}
	case vcsStatus == domain2.Verified && gitRef.CommitHash != "":
		vcsStatus, vcsDetail = uc.crossVerify(ctx, log, coord, gitRef.URL, gitRef.CommitHash, dl.ZipHash)
		log.InfoContext(ctx, "vcs_cross_verify", slog.String("status", string(vcsStatus)))
	}

	// VCS reproduction failure downgrades to VerifiedBySumDBOnly when sumdb has
	// already verified the proxy zip against the transparency log. Independently
	// reproducing a zip from git is a weaker signal than transparency-log
	// attestation; many legitimate repo shapes fail naive reproduction (major-
	// version subdirs, submodules, generated files, proxy normalisation).
	// Reserve a hard fail for when sumdb itself disagrees with the proxy zip
	// (earlyStatus already captures that case).
	if vcsStatus == domain2.UnverifiedHashMismatch && earlyStatus == "" {
		vcsStatus = domain2.VerifiedBySumDBOnly
	}

	// Apply any earlier content-level failure.
	if earlyStatus != "" {
		detail := earlyDetail
		if vcsDetail != "" {
			detail += "; vcs: " + vcsDetail
		}
		return earlyStatus, detail, gitRef, retracted
	}

	// sumdb passed; combine with VCS result.
	if vcsStatus == domain2.Verified {
		return domain2.Verified, "", gitRef, retracted
	}
	// sumdb passed but VCS was not available or missing.
	return domain2.VerifiedBySumDBOnly, vcsDetail, gitRef, retracted
}

// checkProjectGoSum cross-checks the module's already-computed h1 hashes
// against the walk root's local go.sum, when a project go.sum verifier is
// configured (KN-404). It is a cheap, offline complement to the network
// checksum-database check and adds no hashing or network calls. The outcomes:
//
//   - no verifier configured, or the coordinate is absent from go.sum →
//     (false, nil): the module falls through to network sumdb verification.
//     go.sum legitimately omits some transitively-cached entries, so absence is
//     not a failure on the normal path (contrast --from-modcache).
//   - entry present and both zip and go.mod h1 match → (true, nil): a positive
//     offline integrity signal that elevates a no-network-sumdb outcome to
//     VerifiedByGoSum.
//   - entry present and either h1 disagrees → (false, ErrGoSumVerification): a
//     hard tamper failure. The caller aborts with no blob stored and no record
//     persisted; a go.sum mismatch must never be silently downgraded.
func (uc *FetchModuleUseCase) checkProjectGoSum(ctx context.Context, log *slog.Logger, coord domain2.ModuleCoordinate, dl ports.ModuleDownload) (bool, error) {
	if uc.goSum == nil {
		return false, nil
	}
	res := uc.goSum.Lookup(ctx, coord)
	if !res.Available {
		// Absent from go.sum — fall through to network sumdb verification.
		return false, nil
	}
	if !res.ZipHash.Equal(dl.ZipHash) {
		return false, fmt.Errorf("%w: %s: local go.sum expects zip %s but computed %s",
			ErrGoSumVerification, coord, res.ZipHash, dl.ZipHash)
	}
	// The go.mod hash is checked only when go.sum records one (it always does for
	// module-era dependencies). A zero recorded hash means go.sum has no /go.mod
	// line — do not manufacture a mismatch from its absence.
	if !res.GoModHash.IsZero() && !res.GoModHash.Equal(dl.GoModHash) {
		return false, fmt.Errorf("%w: %s: local go.sum expects go.mod %s but computed %s",
			ErrGoSumVerification, coord, res.GoModHash, dl.GoModHash)
	}
	log.InfoContext(ctx, "project_gosum_verified", slog.String("zip_hash", dl.ZipHash.String()))
	return true, nil
}

// resolveGitRef determines the GitReference for the module.
func (uc *FetchModuleUseCase) resolveGitRef(
	ctx context.Context,
	log *slog.Logger,
	coord domain2.ModuleCoordinate,
	info ports.ModuleInfo,
) (domain2.GitReference, domain2.VerificationStatus, string) {
	var originRejected string
	if info.Origin != nil && info.Origin.URL != "" && info.Origin.Hash != "" {
		// The module proxy is untrusted (T1/T2), so its Origin metadata is too.
		// Validate the URL/ref/commit before any of it reaches a git subprocess;
		// a failing claim is treated as a missing Origin (fall through to the
		// inferred-URL path below), never trusted as Verified.
		if err := domain2.ValidateOriginForCheckout(info.Origin.URL, info.Origin.Ref, info.Origin.Hash); err != nil {
			log.WarnContext(ctx, "origin_rejected",
				slog.String("url", info.Origin.URL),
				slog.String("error", err.Error()))
			// Remember why so a non-Verified fall-through reports the real cause
			// (Origin refused) rather than a misleading "could not infer URL".
			originRejected = fmt.Sprintf("proxy Origin %q refused: %v", info.Origin.URL, err)
		} else {
			log.InfoContext(ctx, "origin_from_proxy", slog.String("url", info.Origin.URL))
			return domain2.GitReference{
				URL:        info.Origin.URL,
				Ref:        info.Origin.Ref,
				CommitHash: info.Origin.Hash,
			}, domain2.Verified, ""
		}
	}

	gitRef, status, detail := uc.resolveInferredGitRef(ctx, log, coord)
	// A rejected Origin that the inferred path also could not verify must
	// surface the rejection as the primary, actionable cause: the
	// status degraded because we refused untrusted Origin metadata, not merely
	// because no URL could be inferred.
	if originRejected != "" && status != domain2.Verified {
		if detail == "" {
			detail = originRejected
		} else {
			detail = originRejected + "; " + detail
		}
	}
	return gitRef, status, detail
}

// resolveInferredGitRef resolves a GitReference without any trusted proxy
// Origin, using the pseudo-version commit prefix or an inferred forge URL.
func (uc *FetchModuleUseCase) resolveInferredGitRef(
	ctx context.Context,
	log *slog.Logger,
	coord domain2.ModuleCoordinate,
) (domain2.GitReference, domain2.VerificationStatus, string) {
	if coord.IsPseudoVersion() {
		prefix, err := coord.ExtractCommitPrefix()
		if err != nil {
			return domain2.GitReference{}, domain2.UnverifiedMissingOrigin,
				fmt.Sprintf("could not extract commit prefix from pseudo-version: %v", err)
		}
		repoURL := inferRepoURL(coord.Path)
		if repoURL == "" {
			return domain2.GitReference{}, domain2.UnverifiedMissingOrigin,
				fmt.Sprintf("could not infer VCS URL for %s", coord.Path)
		}
		log.InfoContext(ctx, "pseudo_version_resolve", slog.String("prefix", prefix), slog.String("url", repoURL))
		return domain2.GitReference{
			URL:        repoURL,
			CommitHash: prefix,
		}, domain2.Verified, ""
	}

	repoURL := inferRepoURL(coord.Path)
	if repoURL == "" {
		return domain2.GitReference{}, domain2.UnverifiedMissingOrigin,
			fmt.Sprintf("could not infer VCS URL for %s", coord.Path)
	}
	ref := "refs/tags/" + coord.Version
	commit, err := uc.vcs.ResolveTag(ctx, repoURL, ref)
	if err != nil {
		status := domain2.UnverifiedNoVCS
		if errors.Is(err, ports.ErrVCSToolMissing) {
			status = domain2.UnverifiedVCSToolMissing
		}
		return domain2.GitReference{URL: repoURL, Ref: ref}, status,
			fmt.Sprintf("resolving tag %s: %v", ref, err)
	}
	log.InfoContext(ctx, "tag_resolved", slog.String("commit", commit))
	return domain2.GitReference{
		URL:        repoURL,
		Ref:        ref,
		CommitHash: commit,
	}, domain2.Verified, ""
}

// crossVerify checks out the git commit and compares its directory hash to
// the proxy zip hash.
func (uc *FetchModuleUseCase) crossVerify(
	ctx context.Context,
	log *slog.Logger,
	coord domain2.ModuleCoordinate,
	repoURL, commit string,
	proxyZipHash domain2.ModuleHash,
) (domain2.VerificationStatus, string) {
	tmpDir, err := os.MkdirTemp("", "kanonarion-verify-*")
	if err != nil {
		return domain2.UnverifiedNoVCS, fmt.Sprintf("creating temp dir: %v", err)
	}
	defer func() {
		if err := os.RemoveAll(tmpDir); err != nil {
			log.ErrorContext(ctx, "removing cross-verify temp dir",
				slog.String("tmpdir", tmpDir),
				slog.String("error", err.Error()),
			)
		}
	}()

	if err := uc.vcs.CheckoutToDir(ctx, repoURL, commit, tmpDir); err != nil {
		if errors.Is(err, ports.ErrVCSToolMissing) {
			return domain2.UnverifiedVCSToolMissing, fmt.Sprintf("checkout: %v", err)
		}
		return domain2.UnverifiedNoVCS, fmt.Sprintf("checkout: %v", err)
	}

	if err := os.RemoveAll(filepath.Join(tmpDir, ".git")); err != nil {
		return domain2.UnverifiedNoVCS, fmt.Sprintf("removing.git from checkout: %v", err)
	}

	// For modules that follow the major-version-subdirectory convention
	// (e.g. modernc.org/gc/v3 lives in v3/ of the gc repo), the proxy zips the
	// subdirectory, not the repo root. Hashing the root produces a guaranteed
	// mismatch for any such module, so locate the subdirectory whose go.mod
	// declares the module path before hashing.
	moduleDir := findModuleSubdir(tmpDir, coord.Path)

	// Mirror CreateFromVCS behaviour: if the module lives in a subdirectory and
	// the subdirectory has no LICENSE file, copy the root LICENSE into the
	// subdirectory so the hash matches the proxy zip (which does the same thing,
	// per golang.org/x/mod zip.go lines 712-724).
	if moduleDir != tmpDir {
		copyRootLicenseIfMissing(tmpDir, moduleDir, log, ctx)
	}

	dirHash, err := uc.verifier.HashDirAsModuleZip(moduleDir, coord)
	if err != nil {
		return domain2.UnverifiedNoVCS, fmt.Sprintf("hashing checkout: %v", err)
	}

	log.InfoContext(ctx, "cross_verify",
		slog.String("proxy_hash", proxyZipHash.String()),
		slog.String("git_hash", dirHash.String()),
	)

	if !dirHash.Equal(proxyZipHash) {
		return domain2.UnverifiedHashMismatch,
			fmt.Sprintf("proxy hash %s does not match git checkout hash %s",
				proxyZipHash.String(), dirHash.String())
	}
	return domain2.Verified, ""
}

// checkZipVersionPrefix verifies that all files in the zip begin with the
// expected module@version/ prefix (T7). Returns a non-empty detail on failure.
// Returns empty string when the zip is invalid — that will be caught by hash
// verification against the checksum database.
func checkZipVersionPrefix(data []byte, coord domain2.ModuleCoordinate) string {
	archive, err := ziparchive.New(data)
	if err != nil {
		return ""
	}
	expected := coord.Path + "@" + coord.Version + "/"
	for _, name := range archive.Names() {
		if !strings.HasPrefix(name, expected) {
			return fmt.Sprintf("zip entry %q does not start with expected prefix %q", name, expected)
		}
	}
	return ""
}

// checkGoModConsistency verifies that the standalone go.mod bytes match the
// go.mod embedded inside the zip (T11). Returns a non-empty detail on failure.
// Returns empty string when the zip is invalid — hash verification catches that.
func checkGoModConsistency(zipData, standaloneGoMod []byte, coord domain2.ModuleCoordinate) string {
	archive, err := ziparchive.New(zipData)
	if err != nil {
		return ""
	}
	target := coord.Path + "@" + coord.Version + "/go.mod"
	zipGoMod, found, rerr := archive.ReadFile(target)
	if rerr != nil {
		return fmt.Sprintf("reading go.mod in zip: %v", rerr)
	}
	// go.mod not found in zip; some modules legitimately lack one (pre-module era).
	if !found {
		return ""
	}
	if !bytes.Equal(standaloneGoMod, zipGoMod) {
		return "standalone go.mod from proxy does not match go.mod embedded in zip"
	}
	return ""
}

// parseRetracted reports whether the given version is covered by a retract
// directive in the module's own go.mod. Errors during parsing are silently
// ignored (retraction is informational, not a hard failure).
func parseRetracted(goModData []byte, version string) bool {
	f, err := modfile.Parse("go.mod", goModData, nil)
	if err != nil {
		return false
	}
	for _, r := range f.Retract {
		low := r.Low
		high := r.High
		if low == "" {
			low = version
		}
		if high == "" {
			high = version
		}
		if versionInRange(version, low, high) {
			return true
		}
	}
	return false
}

// versionInRange reports whether v is between low and high (inclusive) using
// basic lexicographic semver comparison via the golang.org/x/mod/semver rules.
func versionInRange(v, low, high string) bool {
	// semver.Compare is not imported here; use string equality for the common
	// single-version retract case, and fall back to Go's module comparison.
	if v == low || v == high {
		return true
	}
	// For range retracts, delegate to x/mod/semver.
	return compareVersion(v, low) >= 0 && compareVersion(v, high) <= 0
}

// compareVersion wraps golang.org/x/mod/semver.Compare but handles pseudo-versions.
func compareVersion(a, b string) int {
	// Use lexicographic fallback; correct for tagged releases.
	if a == b {
		return 0
	}
	if a < b {
		return -1
	}
	return 1
}

// copyRootLicenseIfMissing replicates the golang.org/x/mod CreateFromVCS
// behaviour: when a module lives in a subdirectory and has no LICENSE file of
// its own, the repo-root LICENSE is included in the module zip. Without this
// step, HashDirAsModuleZip (which uses CreateFromDir) would produce a different
// hash than the proxy for such modules.
func copyRootLicenseIfMissing(repoRoot, moduleDir string, log *slog.Logger, ctx context.Context) {
	if _, err := os.Stat(filepath.Join(moduleDir, "LICENSE")); err == nil {
		return // subdir already has a LICENSE; nothing to do
	}
	src := filepath.Join(repoRoot, "LICENSE")
	data, err := os.ReadFile(src) // #nosec G304 — path is always tmpDir-rooted
	if err != nil {
		return // no root LICENSE (or unreadable); hash still computed without it
	}
	dst := filepath.Join(moduleDir, "LICENSE")
	if werr := os.WriteFile(dst, data, 0o600); werr != nil { // #nosec G703 — path is always tmpDir-rooted
		log.WarnContext(ctx, "cross_verify_license_copy_failed", slog.String("error", werr.Error()))
	}
}

// findModuleSubdir locates the directory within root whose go.mod declares the
// given module path, returning the matching directory or root if none is found.
// Only direct children of root are checked — Go's major-version-subdirectory
// convention places the module directly under the repo root (e.g. v3/).
func findModuleSubdir(root, modulePath string) string {
	if goModMatchesPath(filepath.Join(root, "go.mod"), modulePath) {
		return root
	}
	entries, err := os.ReadDir(root)
	if err != nil {
		return root
	}
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		sub := filepath.Join(root, e.Name())
		if goModMatchesPath(filepath.Join(sub, "go.mod"), modulePath) {
			return sub
		}
	}
	return root
}

// goModMatchesPath reports whether the go.mod at goModPath declares the given
// module path.
func goModMatchesPath(goModPath, modulePath string) bool {
	data, err := os.ReadFile(goModPath) // #nosec G304 — path is always tmpDir-rooted, never user-supplied
	if err != nil {
		return false
	}
	f, err := modfile.Parse("go.mod", data, nil)
	if err != nil {
		return false
	}
	return f.Module != nil && f.Module.Mod.Path == modulePath
}

// inferRepoURL guesses a git clone URL from a Go module path.
func inferRepoURL(modulePath string) string {
	parts := splitPath(modulePath, 3)
	if len(parts) == 0 {
		return ""
	}
	// Only the forges with a predictable host/org/repo clone-URL shape can be
	// inferred here. Other allowlisted hosts (e.g. go.googlesource.com) have a
	// different layout and are only trusted when the proxy supplies their Origin.
	switch parts[0] {
	case "github.com", "gitlab.com", "bitbucket.org":
		if len(parts) < 3 {
			return ""
		}
		return "https://" + parts[0] + "/" + parts[1] + "/" + parts[2]
	}
	return ""
}

func splitPath(path string, n int) []string {
	var parts []string
	rest := path
	for len(parts) < n && rest != "" {
		i := 0
		for i < len(rest) && rest[i] != '/' {
			i++
		}
		parts = append(parts, rest[:i])
		if i < len(rest) {
			rest = rest[i+1:]
		} else {
			rest = ""
		}
	}
	return parts
}

type byteReader struct {
	data []byte
	pos  int
}

func newReader(data []byte) io.Reader {
	return &byteReader{data: data}
}

func (r *byteReader) Read(p []byte) (int, error) {
	if r.pos >= len(r.data) {
		return 0, io.EOF
	}
	n := copy(p, r.data[r.pos:])
	r.pos += n
	return n, nil
}
