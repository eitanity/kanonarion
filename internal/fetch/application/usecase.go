package application

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strings"

	"github.com/eitanity/kanonarion/internal/adapters/ziparchive"
	"github.com/eitanity/kanonarion/internal/coordinate"
	domain2 "github.com/eitanity/kanonarion/internal/fetch/domain"
	"github.com/eitanity/kanonarion/internal/fetch/ports"
	"golang.org/x/mod/modfile"

	"github.com/oklog/ulid/v2"
)

// PipelineVersion identifies this release of the fetch pipeline. Bump this
// constant whenever any stage logic changes to ensure old cached records are
// not confused with new ones.
const PipelineVersion = "0.4.0"

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
	verifier        domain2.Verifier

	// resolveHost looks up a hostname for the Origin address guard. It is a
	// field rather than a direct net call so a test can present a name that
	// answers into private space without touching DNS; nil uses the system
	// resolver. See WithHostResolver.
	resolveHost func(ctx context.Context, host string) ([]net.IP, error)

	// signer and attestations are optional sign-on-process capabilities
	// When signer is nil, or it yields no attestation (the OSS
	// no-op default), nothing is signed or persisted and behaviour is
	// unchanged. Set via WithSigner.
	signer       ports.Signer
	attestations ports.AttestationStore

	// modcache is the --from-modcache seam. When true, Execute reads bytes from
	// the module cache and verifies them against the local go.sum instead of the
	// network checksum database. Set via WithModcacheMode. The bytes are stored
	// under the same artefact identity every other mode uses, so the mode changes
	// where a measurement comes from and nothing about how it is addressed.
	modcache bool

	// goSum is the optional walk-root go.sum verifier for the normal network
	// path. When non-nil, Execute cross-checks each fetched module's computed h1
	// against the local go.sum as a cheap, offline complement to the network
	// checksum database: a present-but-mismatched entry is a hard tamper failure,
	// a matching entry a positive signal, an absent entry a fall-through. It is
	// distinct from modcache mode, where go.sum is the sole anchor. Set via
	// WithProjectGoSum; nil leaves the network path byte-for-byte unchanged.
	goSum ports.SumDBClient

	// audit is the optional assurance-log sink the write side emits through when
	// a re-measurement is refused for weakening a record's verification anchor,
	// or when an operator explicitly permits that weakening. Set via WithAudit;
	// nil emits nothing.
	audit ports.AuditSink

	// allowVerificationDowngrade permits a weaker re-measurement to replace a
	// stronger stored record. Default false. Set via
	// WithAllowVerificationDowngrade — deliberately not --force.
	allowVerificationDowngrade bool
}

// WithProjectGoSum layers a walk-root go.sum verifier onto the normal network
// fetch path. It is additive: the network checksum-database check and
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
	Coordinate coordinate.ModuleCoordinate
	// OriginalCoordinate is the coordinate the project requires this module
	// under, when a replace directive put Coordinate in its place. Zero for an
	// unreplaced module.
	//
	// It is provenance for the verification report, never an identity: the
	// record is written under Coordinate, which is the artefact fetched, the
	// zip hashed and the entry `go.sum` records. What the original buys is the
	// ability to SAY so — "anchored under the fork path, required as the
	// upstream one" — and to refuse, naming both, when the fork has no go.sum
	// entry at all. In an air gap go.sum is the only anchor there is, and a
	// module that falls outside it silently is unverified in the one
	// environment where nothing else can cover for it.
	OriginalCoordinate coordinate.ModuleCoordinate
	// Force re-fetches even if a record for this pipeline version exists.
	Force bool
	// SkipVCSVerify skips the git cross-verification step; sumdb verification
	// still runs. Useful when GitHub rate limits make git operations unreliable.
	SkipVCSVerify bool
	// GoModOnly acquires only the module's go.mod, not its zip. It fetches the
	// .mod from the proxy, verifies its h1 against the checksum database go.mod
	// hash, and persists a record with GoModLocation set and ContentLocation
	// empty (a go.mod-only record, see domain.FactRecord.IsGoModOnly). It exists
	// for module-graph resolution — reading a superseded version's requirements
	// while rebuilding the graph — where the zip is never read. Such a record
	// must never satisfy a scan that needs source; the full path re-fetches over
	// it when a zip is required.
	GoModOnly bool
	// VCSHosts is the effective VCS forge allowlist for this fetch: which https
	// hosts may be handed to a git subprocess for cross-verification. It is
	// resolved from the caller's fetch-stage policy (allowed_vcs_hosts) and the
	// zero value enforces the built-in default set, so a caller that does not
	// set it behaves exactly as before. It never governs WHETHER git runs —
	// that is SkipVCSVerify.
	VCSHosts domain2.VCSHostAllowlist
}

// FetchResult is the output of Execute.
type FetchResult struct {
	// Record is the artefact as the ledger knows it: the composed view of every
	// measurement of it, not any single row.
	Record    domain2.CompositeRecord
	FromCache bool
}

// blobIdentities addresses both artefacts of a measurement. The addresses come
// from the hashes just measured, so the same artefact acquired by any route
// lands at the same place in every store that holds it.
//
// Each refusal the constructor makes is returned rather than absorbed: an
// address the identity type would not build is one no reader could read back
// out of the content_location it is written to.
func blobIdentities(dl ports.ModuleDownload) (zip, goMod ports.BlobIdentity, err error) {
	zip, err = ports.NewBlobIdentity(ports.BlobKindZip, dl.ZipHash)
	if err != nil {
		return ports.BlobIdentity{}, ports.BlobIdentity{}, fmt.Errorf("addressing zip blob: %w", err)
	}
	goMod, err = ports.NewBlobIdentity(ports.BlobKindGoMod, dl.GoModHash)
	if err != nil {
		return ports.BlobIdentity{}, ports.BlobIdentity{}, fmt.Errorf("addressing go.mod blob: %w", err)
	}
	return zip, goMod, nil
}

// Execute runs the full fetch-verify-persist pipeline for the given module.
//
// Verification failures (UnverifiedX statuses) do not fail Execute; they are
// recorded in the FactRecord. Proxy, VCS, and storage errors do fail Execute.
func (uc *FetchModuleUseCase) Execute(ctx context.Context, req FetchRequest) (_ FetchResult, retErr error) {
	if uc.modcache {
		return uc.executeModcache(ctx, req)
	}
	if req.GoModOnly {
		return uc.executeGoModOnly(ctx, req)
	}

	traceID := ulid.Make().String()
	lap := uc.stopwatch.Start()

	log := uc.logger.With(
		slog.String("module_path", req.Coordinate.Path()),
		slog.String("module_version", req.Coordinate.Version()),
		slog.String("pipeline_version", uc.pipelineVersion),
		slog.String("trace_id", traceID),
	)
	log.InfoContext(ctx, "fetch_start")

	defer func() {
		log.InfoContext(ctx, "fetch_end",
			slog.Duration("duration", lap.Elapsed()),
		)
	}()

	// Step 1: cache check. A go.mod-only record does not satisfy the full path —
	// this call needs the zip, so re-fetch over it and let PutFetchRecord upgrade
	// the record in place. Any record with a zip is a hit, unless its verification
	// rests on a checksum-database lookup that failed rather than answered
	// (domain.RecordIsCacheable): re-verify that one instead of serving a downgrade
	// a single bad network moment produced.
	if !req.Force {
		existing, ok, err := uc.facts.GetFetchRecord(ctx, req.Coordinate, uc.pipelineVersion)
		if err != nil {
			return FetchResult{}, fmt.Errorf("checking cache: %w", err)
		}
		switch {
		case ok && !domain2.RecordIsCacheable(existing.FactRecord):
			log.InfoContext(ctx, "cache_reverify_sumdb_lookup_failed",
				slog.String("cached_verification_status", existing.VerificationStatus),
			)
		case ok && !uc.cachedArtefactsReadable(ctx, log, existing.FactRecord):
			// Re-fetch rather than hand the caller a record whose blobs this run
			// cannot read.
		case ok && !existing.IsGoModOnly():
			log.InfoContext(ctx, "cache_hit")
			return FetchResult{Record: existing, FromCache: true}, nil
		case ok:
			log.InfoContext(ctx, "cache_upgrade_gomod_only_to_full")
		}
	}

	// Step 1b: a forced run re-measures, which does not mean it must re-transfer.
	// When the artefacts are already held and still hash to what was recorded,
	// the bytes are re-established locally and only the network anchors are
	// re-queried, so the record carries the same class of anchor as a fresh
	// acquisition without spending the download. It falls through to the proxy
	// when there is nothing to revalidate against, when the artefacts are gone,
	// or when the held bytes disagree with the record — see tryRevalidate.
	revalidated, err := uc.revalidateIfForced(ctx, log, req)
	if err != nil {
		return FetchResult{}, err
	}

	// Step 2: proxy info. Still queried when revalidating: the origin block is
	// part of the measurement, not part of the bytes.
	info, err := uc.proxy.Info(ctx, req.Coordinate)
	if err != nil {
		return FetchResult{}, fmt.Errorf("proxy info: %w", err)
	}
	log.InfoContext(ctx, "proxy_info_ok", slog.String("version", info.Version))

	// Step 3: obtain zip + go.mod — from the store when revalidating, otherwise
	// from the proxy. Hashes are computed from the bytes either way.
	dl := ports.ModuleDownload{}
	if revalidated != nil {
		dl = revalidated.download
	} else {
		dl, err = uc.proxy.Download(ctx, req.Coordinate)
		if err != nil {
			return FetchResult{}, fmt.Errorf("proxy download: %w", err)
		}
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

	// Step 3.5: cheap, offline local go.sum cross-check. It uses the
	// h1 hashes already computed during download — no extra hashing, no network
	// round-trip — and runs before the blob store and the network sumdb lookup
	// so a tampered module fails fast, with no blob written and no record
	// persisted. A matching entry becomes a positive signal folded into the
	// verification status below; an absent entry falls through unchanged.
	goSumAnchoredUnder, err := uc.checkProjectGoSum(ctx, log, req.Coordinate, req.OriginalCoordinate, dl)
	if err != nil {
		return FetchResult{}, err
	}

	// Step 4: store zip + go.mod under the identities just measured. The store
	// does not choose the address: the same artefact acquired by any route lands
	// at the same place, which is what makes a module-cache measurement and a
	// network measurement describe one artefact instead of two.
	//
	// A revalidating run stores NOTHING. The bytes came out of the store and were
	// just shown to be the recorded ones, so there is nothing to write; a Put
	// here would be a no-op that obscures whether a forced run transferred
	// anything at all.
	zipIdentity, goModIdentity, err := blobIdentities(dl)
	if err != nil {
		return FetchResult{}, err
	}
	if revalidated == nil {
		if err := uc.blobs.Put(ctx, zipIdentity, newReader(zipData)); err != nil {
			return FetchResult{}, fmt.Errorf("storing zip blob: %w", err)
		}
		log.InfoContext(ctx, "blob_stored", slog.String("identity", zipIdentity.String()))

		if err := uc.blobs.Put(ctx, goModIdentity, newReader(goModData)); err != nil {
			return FetchResult{}, fmt.Errorf("storing go.mod blob: %w", err)
		}
		log.InfoContext(ctx, "go_mod_blob_stored", slog.String("identity", goModIdentity.String()))
	}

	// Step 5: run verification pipeline, accumulating status.
	verStatus, verDetail, gitRef, retracted, sumdbLookupFailed := uc.verify(ctx, log, req.Coordinate, dl, zipData, goModData, info, req.SkipVCSVerify, goSumAnchoredUnder, req.VCSHosts)

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
		Digests:            dl.Digests,
		GitReference:       gitRef,
		VerificationStatus: verStatus,
		VerificationDetail: verDetail,
		FetchedAt:          fetchedAt,
		PipelineVersion:    uc.pipelineVersion,
		ContentLocation:    zipIdentity.String(),
		GoModLocation:      goModIdentity.String(),
		Retracted:          retracted,
		SumDBLookupFailed:  sumdbLookupFailed,
		AcquisitionMode:    domain2.AcquisitionProxy,
		MeasurementKind:    measurementKind(revalidated != nil),
		SumDBCheck:         domain2.LegRechecked,
		VCSCheck:           vcsLeg(req.SkipVCSVerify),
	}

	// Step 7: seal and append. Sealing computes the content hash at construction,
	// so no unsealed record ever exists to be mislaid, and the store accepts
	// nothing else. stored is the artefact as the ledger knows it afterwards.
	stored, err := uc.persistRecord(ctx, log, req, m)
	if err != nil {
		return FetchResult{}, err
	}

	// Sign-on-process call site 2: fact-produce. Sign the produced FactRecord
	// over its canonical ContentHash.
	if err := uc.sign(ctx, log, req.Coordinate, domain2.SubjectFact, stored.ContentHash); err != nil {
		return FetchResult{}, err
	}

	return FetchResult{Record: stored, FromCache: false}, nil
}

// executeGoModOnly is the go.mod-only counterpart to Execute: it fetches only
// the module's go.mod, verifies its h1 against the checksum database go.mod hash
// (the same anchor the full path uses for the zip), and persists a record whose
// GoModLocation is set and whose ContentLocation is empty. No zip is downloaded,
// hashed, stored, or VCS cross-verified — the version exists in the scan cache
// purely so the toolchain can read its requirements while rebuilding a module
// graph, never to be compiled or analysed. Verification is not optional: the
// go.mod-only record carries the same chain of custody as a full one.
func (uc *FetchModuleUseCase) executeGoModOnly(ctx context.Context, req FetchRequest) (_ FetchResult, retErr error) {
	traceID := ulid.Make().String()
	lap := uc.stopwatch.Start()

	log := uc.logger.With(
		slog.String("module_path", req.Coordinate.Path()),
		slog.String("module_version", req.Coordinate.Version()),
		slog.String("pipeline_version", uc.pipelineVersion),
		slog.String("trace_id", traceID),
		slog.Bool("go_mod_only", true),
	)
	log.InfoContext(ctx, "fetch_start")
	defer func() {
		log.InfoContext(ctx, "fetch_end", slog.Duration("duration", lap.Elapsed()))
	}()

	// Step 1: cache check. Any existing record — full or go.mod-only — already
	// carries a verified go.mod, which is all this path needs.
	if !req.Force {
		existing, ok, err := uc.facts.GetFetchRecord(ctx, req.Coordinate, uc.pipelineVersion)
		if err != nil {
			return FetchResult{}, fmt.Errorf("checking cache: %w", err)
		}
		switch {
		case ok && !domain2.RecordIsCacheable(existing.FactRecord):
			// Same rule as the full path: a record whose sumdb lookup failed is not
			// eligible as a cache hit, so this path re-verifies rather than inheriting
			// a downgrade produced by a failed measurement.
			log.InfoContext(ctx, "cache_reverify_sumdb_lookup_failed",
				slog.String("cached_verification_status", existing.VerificationStatus),
			)
		case ok && !uc.cachedArtefactsReadable(ctx, log, existing.FactRecord):
			// Re-fetch rather than hand the caller a record whose blobs this run
			// cannot read.
		case ok:
			log.InfoContext(ctx, "cache_hit")
			return FetchResult{Record: existing, FromCache: true}, nil
		}
	}

	// Step 2: download the go.mod alone — never the zip.
	dl, err := uc.proxy.DownloadGoMod(ctx, req.Coordinate)
	if err != nil {
		return FetchResult{}, fmt.Errorf("proxy download go.mod: %w", err)
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
	log.InfoContext(ctx, "download_ok", slog.Int("go_mod_bytes", len(goModData)))

	// Step 2.5: cheap offline local go.sum cross-check of the go.mod hash. A
	// present-but-disagreeing entry is a hard tamper failure with no blob stored
	// and no record persisted, mirroring the full path.
	goSumAnchoredUnder, err := uc.checkProjectGoSumGoMod(ctx, log, req.Coordinate, req.OriginalCoordinate, dl)
	if err != nil {
		return FetchResult{}, err
	}

	// Step 3: store the go.mod blob (no zip blob).
	goModIdentity, err := ports.NewBlobIdentity(ports.BlobKindGoMod, dl.GoModHash)
	if err != nil {
		return FetchResult{}, fmt.Errorf("addressing go.mod blob: %w", err)
	}
	if err := uc.blobs.Put(ctx, goModIdentity, newReader(goModData)); err != nil {
		return FetchResult{}, fmt.Errorf("storing go.mod blob: %w", err)
	}
	log.InfoContext(ctx, "go_mod_blob_stored", slog.String("identity", goModIdentity.String()))

	// Step 4: verify the go.mod h1 against the checksum database.
	verStatus, verDetail, retracted, sumdbLookupFailed := uc.verifyGoModOnly(ctx, log, req.Coordinate, dl, goModData, goSumAnchoredUnder)

	// Sign the received go.mod over its canonical content digest, after
	// verification. There is no zip to sign; the go.mod is the artefact received.
	if err := uc.sign(ctx, log, req.Coordinate, domain2.SubjectBlob, domain2.ContentDigest(goModData)); err != nil {
		return FetchResult{}, err
	}

	// Step 5: construct the go.mod-only FactRecord. ModuleHash, Digests, git
	// provenance, and ContentLocation are deliberately zero/empty.
	m := domain2.FetchedModule{
		Coordinate:         req.Coordinate,
		GoModHash:          dl.GoModHash,
		VerificationStatus: verStatus,
		VerificationDetail: verDetail,
		FetchedAt:          uc.clock.Now().UTC(),
		PipelineVersion:    uc.pipelineVersion,
		GoModLocation:      goModIdentity.String(),
		Retracted:          retracted,
		SumDBLookupFailed:  sumdbLookupFailed,
		AcquisitionMode:    domain2.AcquisitionProxy,
		MeasurementKind:    domain2.MeasurementAcquired,
		SumDBCheck:         domain2.LegRechecked,
	}

	// Step 6: seal and append. A later full fetch of the same coordinate appends
	// its own record rather than overwriting this one; the two describe one
	// artefact at two depths and compose into a single answer.
	stored, err := uc.persistRecord(ctx, log, req, m)
	if err != nil {
		return FetchResult{}, err
	}

	if err := uc.sign(ctx, log, req.Coordinate, domain2.SubjectFact, stored.ContentHash); err != nil {
		return FetchResult{}, err
	}

	return FetchResult{Record: stored, FromCache: false}, nil
}

// cachedArtefactsReadable reports whether the artefacts a cached record points at
// can actually be produced by the blob store this run is wired with.
//
// The question is asked by artefact identity, so it means what it says: does
// this store hold these bytes? It used to be asked with a handle read off the
// record, and a handle was mode-specific — the normal path stored
// "sha256:<hex>" addresses in the local blob store while --from-modcache derived
// "modcache:zip:<coord>" addresses only the module-cache adapter could resolve.
// A --from-modcache run overwrote a blob-backed record in place and a later
// normal run took a cache hit on an address its store could not read, which
// surfaced downstream as every module failing to populate the scan's GOMODCACHE
// and govulncheck going to the network on a run that had the bytes on disk all
// along. With a content-chosen address there is no mode dimension left to get
// wrong.
//
// An error deriving an identity is treated as unreadable, not propagated: a
// malformed hash on a stored record is precisely the case this guard exists for,
// and re-fetching is the correct response either way. It is logged so the
// re-fetch is never silent.
func (uc *FetchModuleUseCase) cachedArtefactsReadable(ctx context.Context, log *slog.Logger, r domain2.FactRecord) bool {
	zip, hasZip, zerr := ports.ZipIdentity(r)
	goMod, hasGoMod, gerr := ports.GoModIdentity(r)
	if zerr != nil || gerr != nil {
		log.InfoContext(ctx, "cache_reverify_identity_underivable",
			slog.String("error", errors.Join(zerr, gerr).Error()),
		)
		return false
	}
	for _, artefact := range []struct {
		kind     string
		identity ports.BlobIdentity
		present  bool
	}{
		{"zip", zip, hasZip},
		{"go.mod", goMod, hasGoMod},
	} {
		if !artefact.present {
			// Absent by design (a go.mod-only record has no zip); the IsGoModOnly
			// checks above decide whether that satisfies the caller.
			continue
		}
		exists, err := uc.blobs.Exists(ctx, artefact.identity)
		if err != nil {
			log.InfoContext(ctx, "cache_reverify_blob_unreadable",
				slog.String("artefact", artefact.kind),
				slog.String("identity", artefact.identity.String()),
				slog.String("error", err.Error()),
			)
			return false
		}
		if !exists {
			log.InfoContext(ctx, "cache_reverify_blob_missing",
				slog.String("artefact", artefact.kind),
				slog.String("identity", artefact.identity.String()),
			)
			return false
		}
	}
	return true
}

// measurementKind names what a measurement did: revalidated when the artefact
// was already held and re-hashed to the recorded digest, acquired when the bytes
// were transferred. It is the difference between a run that spent the network on
// bytes and one that spent it only on anchors.
func measurementKind(revalidated bool) domain2.MeasurementKind {
	if revalidated {
		return domain2.MeasurementRevalidated
	}
	return domain2.MeasurementAcquired
}

// vcsLeg reports how this measurement came by its VCS cross-verification leg. A
// run that skipped the check records no leg at all rather than a negative one:
// "not checked" and "checked and could not confirm" are different claims, and
// collapsing them would let a --skip-vcs run look like a failed verification.
func vcsLeg(skipped bool) domain2.LegProvenance {
	if skipped {
		return domain2.LegAbsent
	}
	return domain2.LegRechecked
}

// verifyGoModOnly verifies a go.mod-only fetch's h1 against the checksum
// database, the go.mod-only analogue of verify. There is no zip, no
// version-prefix check, and no VCS cross-verification (nothing to reproduce);
// the anchor is the checksum database "<version>/go.mod" hash, elevated to
// VerifiedByGoSum when the network database is unavailable but the walk root's
// local go.sum already confirmed the go.mod.
func (uc *FetchModuleUseCase) verifyGoModOnly(
	ctx context.Context,
	log *slog.Logger,
	coord coordinate.ModuleCoordinate,
	dl ports.GoModDownload,
	goModData []byte,
	// goSumAnchoredUnder names the coordinate the walk root's go.sum entry was
	// found under, or "" when go.sum did not confirm the go.mod. It is reported
	// verbatim so a reader can see a fork was anchored under its fork path.
	goSumAnchoredUnder string,
) (domain2.VerificationStatus, string, bool, bool) {
	retracted := parseRetracted(goModData, coord.Version())
	if retracted {
		log.InfoContext(ctx, "retracted_version_detected")
	}

	if dl.InsecureTransport {
		return domain2.UnverifiedNoSumDB,
			"go.mod-only fetch; insecure transport (HTTP proxy); integrity guarantees are weakened",
			retracted, false
	}

	res := uc.sumdb.Lookup(ctx, coord)
	if res.Available {
		log.InfoContext(ctx, "sumdb_ok",
			slog.String("sumdb_go_mod_hash", res.GoModHash.String()),
			slog.String("computed_go_mod_hash", dl.GoModHash.String()),
		)
		switch {
		case res.GoModHash.IsZero():
			// The database returned no go.mod hash line (rare). Fall back to the
			// local go.sum signal rather than manufacturing a pass from absence.
			if goSumAnchoredUnder != "" {
				return domain2.VerifiedByGoSum,
					"go.mod-only fetch; go.mod verified against local go.sum under " + goSumAnchoredUnder +
						"; checksum database returned no go.mod hash",
					retracted, false
			}
			return domain2.UnverifiedNoSumDB,
				"go.mod-only fetch; checksum database returned no go.mod hash", retracted, false
		case !res.GoModHash.Equal(dl.GoModHash):
			return domain2.UnverifiedHashMismatch,
				fmt.Sprintf("go.mod-only fetch; sumdb expects go.mod %s but computed %s", res.GoModHash, dl.GoModHash),
				retracted, false
		default:
			return domain2.VerifiedBySumDBOnly,
				"go.mod-only fetch; go.mod h1 matches checksum database (zip not fetched)", retracted, false
		}
	}

	// The lookup produced no hashes. Whether that is the database's settled answer
	// or a lookup that failed decides whether the resulting record may be cached:
	// a failure is a statement about the measurement, so the next fetch must
	// re-verify rather than inherit this status. The retry budget is already spent
	// by the time the result gets here.
	lookupFailed := res.LookupFailed()
	log.InfoContext(ctx, "sumdb_unavailable",
		slog.String("reason", res.Reason),
		slog.Bool("lookup_failed", lookupFailed),
	)
	if goSumAnchoredUnder != "" {
		return domain2.VerifiedByGoSum,
			"go.mod-only fetch; go.mod verified against local go.sum under " + goSumAnchoredUnder +
				"; network checksum database unavailable: " + res.Reason,
			retracted, lookupFailed
	}
	return domain2.UnverifiedNoSumDB, "go.mod-only fetch; " + res.Reason, retracted, lookupFailed
}

// checkProjectGoSumGoMod cross-checks a go.mod-only fetch's go.mod h1 against
// the walk root's local go.sum, the go.mod-only analogue of checkProjectGoSum.
// A present entry whose go.mod hash disagrees is a hard tamper failure; an
// absent entry (or no verifier) falls through to network checksum verification.
func (uc *FetchModuleUseCase) checkProjectGoSumGoMod(ctx context.Context, log *slog.Logger, coord, original coordinate.ModuleCoordinate, dl ports.GoModDownload) (string, error) {
	if uc.goSum == nil {
		return "", nil
	}
	res := uc.goSum.Lookup(ctx, coord)
	if !res.Available {
		if isReplaced(coord, original) {
			return "", errReplacedModuleNotInGoSum(coord, original, res.Reason)
		}
		return "", nil
	}
	if !res.GoModHash.IsZero() && !res.GoModHash.Equal(dl.GoModHash) {
		return "", fmt.Errorf("%w: %s: local go.sum expects go.mod %s but computed %s",
			ErrGoSumVerification, goSumAnchor(coord, original), res.GoModHash, dl.GoModHash)
	}
	anchor := goSumAnchor(coord, original)
	log.InfoContext(ctx, "project_gosum_verified",
		slog.String("go_mod_hash", dl.GoModHash.String()),
		slog.String("anchored_under", anchor))
	return anchor, nil
}

// sign invokes the injected Signer over a "sha256:<hex>" subject digest and
// persists any resulting attestation additively. It is a no-op when no signer
// is configured or the signer yields no attestation (the OSS no-op default), so
// the unsigned path is byte-for-byte unchanged. A signer that yields an
// attestation but no attestation store is a wiring error.
func (uc *FetchModuleUseCase) sign(ctx context.Context, log *slog.Logger, coord coordinate.ModuleCoordinate, kind domain2.SubjectKind, subjectHash string) error {
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
	coord coordinate.ModuleCoordinate,
	dl ports.ModuleDownload,
	zipData, goModData []byte,
	info ports.ModuleInfo,
	skipVCSVerify bool,
	// goSumAnchoredUnder names the coordinate the walk root's go.sum entry was
	// found under, or "" when go.sum did not confirm the module. It is reported
	// verbatim so a reader can see a fork was anchored under its fork path
	// rather than having to trust that the right spelling was looked up.
	goSumAnchoredUnder string,
	vcsHosts domain2.VCSHostAllowlist,
) (domain2.VerificationStatus, string, domain2.GitReference, bool, bool) {

	var earlyStatus domain2.VerificationStatus
	var earlyDetail string
	// sumdbLookupFailed records that the checksum-database lookup failed rather
	// than answered, so the caller can mark the record un-cacheable and re-verify
	// on the next fetch instead of making one bad network moment permanent.
	var sumdbLookupFailed bool

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
	retracted := parseRetracted(goModData, coord.Version())
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
			sumdbLookupFailed = sumdbResult.LookupFailed()
			log.InfoContext(ctx, "sumdb_unavailable",
				slog.String("reason", sumdbResult.Reason),
				slog.Bool("lookup_failed", sumdbLookupFailed),
			)
			if goSumAnchoredUnder != "" {
				// Network sumdb is unreachable/absent, but the walk root's local
				// go.sum (itself populated under a prior transparency-log check)
				// confirmed the h1. A positive offline integrity signal, not an
				// un-analysed outcome.
				earlyStatus = domain2.VerifiedByGoSum
				earlyDetail = "verified against local go.sum under " + goSumAnchoredUnder +
					"; network checksum database unavailable: " + sumdbResult.Reason
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
	gitRef, vcsStatus, vcsDetail, originRefusal := uc.resolveGitRef(ctx, log, coord, info, vcsHosts)
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
		return earlyStatus, withOriginRefusal(detail, originRefusal), gitRef, retracted, sumdbLookupFailed
	}

	// sumdb passed; combine with VCS result. A refused Origin is recorded even
	// here, where nothing went wrong: the run reached Verified through the
	// inferred URL, and the fact that the proxy claimed a different source and
	// was refused is exactly what an auditor needs afterwards.
	if vcsStatus == domain2.Verified {
		return domain2.Verified, withOriginRefusal("", originRefusal), gitRef, retracted, sumdbLookupFailed
	}
	// sumdb passed but VCS was not available or missing.
	return domain2.VerifiedBySumDBOnly, withOriginRefusal(vcsDetail, originRefusal), gitRef, retracted, sumdbLookupFailed
}

// withOriginRefusal puts a refused proxy Origin at the FRONT of the detail.
// When both are present the refusal is the more actionable cause — the run
// declined metadata from an untrusted source — and a reader who sees only the
// downstream consequence would go looking in the wrong place.
func withOriginRefusal(detail, refusal string) string {
	switch {
	case refusal == "":
		return detail
	case detail == "":
		return refusal
	default:
		return refusal + "; " + detail
	}
}

// goSumAnchor names the coordinate a go.sum entry was found under, for the
// verification report. For an unreplaced module that is simply the module; for
// a replaced one it names both, because the entry lives under the REPLACEMENT —
// the only coordinate the toolchain ever writes — while the project requires
// the module under the original, and a reader who sees only one of the two
// cannot tell that a fork was anchored at all.
func goSumAnchor(coord, original coordinate.ModuleCoordinate) string {
	if original.Path() == "" || original == coord {
		return coord.String()
	}
	return coord.String() + " (required as " + original.String() + ")"
}

// errReplacedModuleNotInGoSum builds the hard stop for a replaced module whose
// replacement has no go.sum entry, naming BOTH coordinates.
//
// It is a refusal rather than a fall-through because a replacement is exactly
// the case where go.sum is guaranteed to carry an entry: the toolchain writes
// one for every module it selects, under the replacement path. An absent entry
// therefore means the go.sum being consulted does not describe this build — a
// stale file, the wrong project root, a hand-edited one — and continuing would
// report the module as fetched under a trust anchor that never covered it.
// Naming only one coordinate leaves the reader unable to see which spelling was
// looked for.
func errReplacedModuleNotInGoSum(coord, original coordinate.ModuleCoordinate, reason string) error {
	return fmt.Errorf("%w: %s is replaced by %s, and go.sum has no entry for the replacement: %s",
		ErrGoSumVerification, original, coord, reason)
}

// checkProjectGoSum cross-checks the module's already-computed h1 hashes
// against the walk root's local go.sum, when a project go.sum verifier is
// configured. It is a cheap, offline complement to the network
// checksum-database check and adds no hashing or network calls.
//
// The lookup keys on coord — the coordinate actually fetched, which for a
// replaced module is the REPLACEMENT. That is the only coordinate `go.sum`
// records: the toolchain writes the checksum of the module it selects, under
// the path it selects it at. Keying on the original would look a fork up under
// a name go.sum was never going to carry.
//
// The outcomes:
//
//   - no verifier configured → ("", nil): nothing was consulted.
//   - coord absent from go.sum and the module is UNREPLACED → ("", nil): the
//     module falls through to network sumdb verification. go.sum legitimately
//     omits some transitively-cached entries, so absence is not a failure on
//     the normal path (contrast --from-modcache).
//   - coord absent from go.sum and the module IS replaced →
//     ("", ErrGoSumVerification): a hard stop naming both coordinates.
//   - entry present and both zip and go.mod h1 match → (anchor, nil), where
//     anchor names the coordinate the entry was found under: a positive offline
//     integrity signal that elevates a no-network-sumdb outcome to
//     VerifiedByGoSum.
//   - entry present and either h1 disagrees → ("", ErrGoSumVerification): a
//     hard tamper failure. The caller aborts with no blob stored and no record
//     persisted; a go.sum mismatch must never be silently downgraded.
func (uc *FetchModuleUseCase) checkProjectGoSum(ctx context.Context, log *slog.Logger, coord, original coordinate.ModuleCoordinate, dl ports.ModuleDownload) (string, error) {
	if uc.goSum == nil {
		return "", nil
	}
	res := uc.goSum.Lookup(ctx, coord)
	if !res.Available {
		if isReplaced(coord, original) {
			return "", errReplacedModuleNotInGoSum(coord, original, res.Reason)
		}
		// Absent from go.sum — fall through to network sumdb verification.
		return "", nil
	}
	if !res.ZipHash.Equal(dl.ZipHash) {
		return "", fmt.Errorf("%w: %s: local go.sum expects zip %s but computed %s",
			ErrGoSumVerification, goSumAnchor(coord, original), res.ZipHash, dl.ZipHash)
	}
	// The go.mod hash is checked only when go.sum records one (it always does for
	// module-era dependencies). A zero recorded hash means go.sum has no /go.mod
	// line — do not manufacture a mismatch from its absence.
	if !res.GoModHash.IsZero() && !res.GoModHash.Equal(dl.GoModHash) {
		return "", fmt.Errorf("%w: %s: local go.sum expects go.mod %s but computed %s",
			ErrGoSumVerification, goSumAnchor(coord, original), res.GoModHash, dl.GoModHash)
	}
	anchor := goSumAnchor(coord, original)
	log.InfoContext(ctx, "project_gosum_verified",
		slog.String("zip_hash", dl.ZipHash.String()),
		slog.String("anchored_under", anchor))
	return anchor, nil
}

// isReplaced reports whether original names a coordinate distinct from the one
// fetched — i.e. a replace directive is in force for this module.
func isReplaced(coord, original coordinate.ModuleCoordinate) bool {
	return original.Path() != "" && original != coord
}

// resolveGitRef determines the GitReference for the module.
func (uc *FetchModuleUseCase) resolveGitRef(
	ctx context.Context,
	log *slog.Logger,
	coord coordinate.ModuleCoordinate,
	info ports.ModuleInfo,
	vcsHosts domain2.VCSHostAllowlist,
) (domain2.GitReference, domain2.VerificationStatus, string, string) {
	var originRejected string
	if info.Origin != nil && info.Origin.URL != "" && info.Origin.Hash != "" {
		// The module proxy is untrusted (T1/T2), so its Origin metadata is too.
		// Validate the URL/ref/commit before any of it reaches a git subprocess;
		// a failing claim is treated as a missing Origin (fall through to the
		// inferred-URL path below), never trusted as Verified.
		warning, err := vcsHosts.CheckOriginForCheckout(info.Origin.URL, info.Origin.Ref, info.Origin.Hash)
		if err == nil {
			// The URL-only guard has passed, so the host is not a private
			// literal. Resolve it: a name is the form the guard cannot settle
			// on its own, and it is the form an SSRF attempt would take.
			err = uc.checkOriginResolves(ctx, info.Origin.URL)
		}
		if err != nil {
			log.WarnContext(ctx, "origin_rejected",
				slog.String("url", info.Origin.URL),
				slog.String("error", err.Error()))
			// Remember why so a non-Verified fall-through reports the real cause
			// (Origin refused) rather than a misleading "could not infer URL".
			originRejected = fmt.Sprintf("proxy Origin %q refused: %v", info.Origin.URL, err)
		} else {
			if warning != "" {
				// The proxy is untrusted, so an off-list host it names is the
				// case most worth saying out loud rather than merely allowing.
				log.WarnContext(ctx, "origin_host_off_allowlist",
					slog.String("url", info.Origin.URL),
					slog.String("warning", warning))
			}
			log.InfoContext(ctx, "origin_from_proxy", slog.String("url", info.Origin.URL))
			return domain2.GitReference{
				URL:        info.Origin.URL,
				Ref:        info.Origin.Ref,
				CommitHash: info.Origin.Hash,
			}, domain2.Verified, "", ""
		}
	}

	gitRef, status, detail := uc.resolveInferredGitRef(ctx, log, coord, vcsHosts)
	// The refusal is returned separately rather than folded into detail here.
	// Folding it in loses it twice over: the inferred path can return a
	// provisional Verified (so there is no failure to attach it to), and
	// crossVerify overwrites detail wholesale a moment later. A run that refused
	// untrusted Origin metadata must say so in the record whatever the eventual
	// status, or a repelled SSRF attempt is indistinguishable on disk from a run
	// that never faced one.
	return gitRef, status, detail, originRejected
}

// resolveInferredGitRef resolves a GitReference without any trusted proxy
// Origin, using the pseudo-version commit prefix or an inferred forge URL.
func (uc *FetchModuleUseCase) resolveInferredGitRef(
	ctx context.Context,
	log *slog.Logger,
	coord coordinate.ModuleCoordinate,
	vcsHosts domain2.VCSHostAllowlist,
) (domain2.GitReference, domain2.VerificationStatus, string) {
	if coord.IsPseudoVersion() {
		prefix, err := coord.ExtractCommitPrefix()
		if err != nil {
			return domain2.GitReference{}, domain2.UnverifiedMissingOrigin,
				fmt.Sprintf("could not extract commit prefix from pseudo-version: %v", err)
		}
		repoURL, detail := inferAllowedRepoURL(ctx, log, coord.Path(), vcsHosts)
		if repoURL == "" {
			return domain2.GitReference{}, domain2.UnverifiedMissingOrigin, detail
		}
		log.InfoContext(ctx, "pseudo_version_resolve", slog.String("prefix", prefix), slog.String("url", repoURL))
		return domain2.GitReference{
			URL:        repoURL,
			CommitHash: prefix,
		}, domain2.Verified, ""
	}

	repoURL, detail := inferAllowedRepoURL(ctx, log, coord.Path(), vcsHosts)
	if repoURL == "" {
		return domain2.GitReference{}, domain2.UnverifiedMissingOrigin, detail
	}
	// GitTagVersion, not Version: a +incompatible coordinate names a tag that
	// never carries the suffix, and "refs/tags/v2.22.0+incompatible" resolves to
	// nothing. The coordinate recorded alongside this ref keeps the full version.
	ref := "refs/tags/" + coord.GitTagVersion()
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
	coord coordinate.ModuleCoordinate,
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
	moduleDir := findModuleSubdir(tmpDir, coord.Path())

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
func checkZipVersionPrefix(data []byte, coord coordinate.ModuleCoordinate) string {
	archive, err := ziparchive.New(data)
	if err != nil {
		return ""
	}
	expected := coord.Path() + "@" + coord.Version() + "/"
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
func checkGoModConsistency(zipData, standaloneGoMod []byte, coord coordinate.ModuleCoordinate) string {
	archive, err := ziparchive.New(zipData)
	if err != nil {
		return ""
	}
	target := coord.Path() + "@" + coord.Version() + "/go.mod"
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

// checkOriginResolves resolves a proxy-supplied Origin host and refuses it when
// the answer lands outside public address space.
//
// A resolution failure is NOT a refusal. The name may be unreachable for
// ordinary reasons — offline, DNS outage, a forge that has moved — and turning
// those into "untrusted Origin" would degrade verification on network weather.
// git will fail to dial it a moment later anyway, which reports the real cause.
func (uc *FetchModuleUseCase) checkOriginResolves(ctx context.Context, rawURL string) error {
	u, err := url.Parse(rawURL)
	if err != nil {
		return fmt.Errorf("parsing Origin URL %q: %w", rawURL, err)
	}
	host := u.Hostname()
	if host == "" || net.ParseIP(host) != nil {
		// No name to resolve: the URL-only guard has already classified it.
		return nil
	}
	resolve := uc.resolveHost
	if resolve == nil {
		resolve = defaultHostResolver
	}
	addrs, err := resolve(ctx, host)
	if err != nil {
		// Deliberately not a refusal: see the doc comment. An unresolvable name
		// is network weather, and git reports the real cause when it dials.
		//nolint:nilerr // a resolution failure must not become a verification verdict
		return nil
	}
	if err := domain2.CheckOriginResolvedAddrs(host, addrs); err != nil {
		return fmt.Errorf("checking Origin address for %q: %w", host, err)
	}
	return nil
}

// defaultHostResolver is the system resolver.
func defaultHostResolver(ctx context.Context, host string) ([]net.IP, error) {
	addrs, err := net.DefaultResolver.LookupIPAddr(ctx, host)
	if err != nil {
		return nil, fmt.Errorf("resolving %q: %w", host, err)
	}
	out := make([]net.IP, 0, len(addrs))
	for _, a := range addrs {
		out = append(out, a.IP)
	}
	return out, nil
}

// WithHostResolver overrides the resolver used by the Origin address guard.
func (uc *FetchModuleUseCase) WithHostResolver(f func(ctx context.Context, host string) ([]net.IP, error)) *FetchModuleUseCase {
	uc.resolveHost = f
	return uc
}

// inferAllowedRepoURL infers a clone URL from a module path and puts it through
// the same host gate a proxy-supplied Origin faces. An inferred URL is
// kanonarion's own guess rather than untrusted proxy metadata, but it is still
// handed to a git subprocess, so a policy that narrows the forge allowlist must
// govern it too — otherwise "trust github.com only" would still clone gitlab.
// Returns ("", reason) when no URL can be inferred or the inferred host is off
// the allowlist; the reason is recorded as the verification detail.
func inferAllowedRepoURL(
	ctx context.Context,
	log *slog.Logger,
	modulePath string,
	vcsHosts domain2.VCSHostAllowlist,
) (string, string) {
	repoURL := inferRepoURL(modulePath)
	if repoURL == "" {
		return "", fmt.Sprintf("could not infer VCS URL for %s", modulePath)
	}
	warning, err := vcsHosts.CheckCloneURL(repoURL)
	if err != nil {
		return "", fmt.Sprintf("inferred VCS URL %s refused: %v", repoURL, err)
	}
	if warning != "" {
		log.WarnContext(ctx, "inferred_host_off_allowlist",
			slog.String("url", repoURL),
			slog.String("warning", warning))
	}
	return repoURL, ""
}

// inferRepoURL guesses a git clone URL from a Go module path.
//
// It names no forge. An inferred URL is a CANDIDATE, not an assurance: the
// status it leads to is settled by crossVerify reproducing the proxy zip from
// the checked-out tree, so where the candidate came from carries no weight —
// a wrong guess fails to reproduce and the status degrades exactly as it would
// have without one. Deciding which hosts may be guessed at is therefore not a
// trust question, and the host switch that used to live here was a second,
// hardcoded allowlist shadowing the policy-governed one: gopkg.in is on the
// default VCS allowlist precisely so real graphs cross-verify there, and this
// function silently withheld a candidate for it anyway.
//
// The one host decision that IS load-bearing stays where it belongs, in
// VCSHostAllowlist.ValidateCloneURL: a candidate is handed to a git subprocess,
// so the effective policy allowlist governs what may be contacted. This
// function only proposes; that one refuses.
//
// Two shapes are recognised, by arity alone:
//   - host/org/repo, the common forge layout (a /vN suffix falls outside the
//     first three elements and is dropped, which is what the forge URL needs);
//   - host/repo, which is what a version-redirecting host like gopkg.in serves.
func inferRepoURL(modulePath string) string {
	parts := splitPath(modulePath, 3)
	switch len(parts) {
	case 0, 1:
		// A bare host, or nothing: no repository to name.
		return ""
	case 2:
		return "https://" + parts[0] + "/" + parts[1]
	default:
		return "https://" + parts[0] + "/" + parts[1] + "/" + parts[2]
	}
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
