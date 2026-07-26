package application

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"

	"github.com/eitanity/kanonarion/internal/adapters/ziparchive"
	"github.com/eitanity/kanonarion/internal/audit"
	domain2 "github.com/eitanity/kanonarion/internal/fetch/domain"
	"github.com/eitanity/kanonarion/internal/fetch/ports"
	"golang.org/x/mod/sumdb/dirhash"
)

// revalidation is the outcome of trying to re-measure a module from the bytes
// already held, rather than by downloading them again.
type revalidation struct {
	// download carries the held bytes in the shape the verification pipeline
	// expects, so revalidating and acquiring run through exactly the same
	// verification code rather than through a second, weaker path.
	download  ports.ModuleDownload
	zipData   []byte
	goModData []byte
}

// revalidateIfForced attempts a revalidation when the request is forced,
// returning nil when the run must obtain the bytes from the proxy instead.
//
// An unforced run never reaches here: it either takes the cache and writes
// nothing, or it has no record to revalidate against.
func (uc *FetchModuleUseCase) revalidateIfForced(
	ctx context.Context,
	log *slog.Logger,
	req FetchRequest,
) (*revalidation, error) {
	if !req.Force {
		return nil, nil
	}
	existing, ok, err := uc.facts.GetFetchRecord(ctx, req.Coordinate, uc.pipelineVersion)
	if err != nil {
		return nil, fmt.Errorf("reading the record to revalidate: %w", err)
	}
	if !ok {
		return nil, nil
	}
	rv, valid, err := uc.tryRevalidate(ctx, log, existing.FactRecord)
	if err != nil {
		return nil, err
	}
	if !valid {
		return nil, nil
	}
	return &rv, nil
}

// tryRevalidate re-measures a module from the artefacts already in the blob
// store, returning ok=false when the run must download instead.
//
// A forced run means "re-measure this module now", and the expensive, decisive
// parts of a measurement are the network anchors: the checksum database and the
// VCS cross-check. Those are re-queried either way. Re-downloading bytes that
// are already held and still hash to what was recorded adds nothing to the
// measurement — it re-establishes a fact the store can establish locally — so a
// revalidated record carries the same class of anchor as a freshly acquired one
// without spending the transfer.
//
// It declines, and the caller downloads, when:
//
//   - no record exists, so there is nothing to revalidate against;
//   - the record names no zip, or the blob store does not hold the artefacts —
//     an evicted blob is an absence, not a contradiction, so it is re-acquired
//     silently exactly as before;
//   - the held bytes do NOT re-hash to the recorded digest. That is a tamper
//     finding rather than a cache miss: it is audited and the run downloads a
//     clean copy, so the contradiction is recorded rather than quietly repaired.
//
// Nothing is written to the blob store on the revalidating path. The bytes were
// already there and were just shown to be the right ones, so there is nothing to
// store; a Put would be a no-op that obscures whether a forced run transferred
// anything.
func (uc *FetchModuleUseCase) tryRevalidate(
	ctx context.Context,
	log *slog.Logger,
	existing domain2.FactRecord,
) (revalidation, bool, error) {
	zipIdentity, hasZip, err := ports.ZipIdentity(existing)
	if err != nil || !hasZip {
		return revalidation{}, false, nil //nolint:nilerr // an underivable identity is a re-acquisition, not a failure
	}
	goModIdentity, hasGoMod, err := ports.GoModIdentity(existing)
	if err != nil || !hasGoMod {
		return revalidation{}, false, nil //nolint:nilerr // as above
	}

	zipData, ok, err := uc.readHeldArtefact(ctx, zipIdentity)
	if err != nil {
		return revalidation{}, false, err
	}
	if !ok {
		log.InfoContext(ctx, "revalidate_declined_artefact_absent",
			slog.String("artefact", "zip"), slog.String("identity", zipIdentity.String()))
		return revalidation{}, false, nil
	}
	goModData, ok, err := uc.readHeldArtefact(ctx, goModIdentity)
	if err != nil {
		return revalidation{}, false, err
	}
	if !ok {
		log.InfoContext(ctx, "revalidate_declined_artefact_absent",
			slog.String("artefact", "go.mod"), slog.String("identity", goModIdentity.String()))
		return revalidation{}, false, nil
	}

	// Re-hash the held bytes. This is the whole basis for not downloading: the
	// bytes are only trusted because they were just shown to be the recorded
	// ones.
	//
	// Bytes that cannot be hashed at all — not readable as a module zip, say —
	// are treated exactly as bytes that hash to the wrong thing. Both mean the
	// store holds something other than what its record describes, so both are a
	// finding and both fall through to a clean download. Failing the run instead
	// would turn a recoverable contradiction into an outage.
	zipHashStr, zerr := ziparchive.HashModuleZip(zipData)
	goModHashStr, gerr := dirhash.Hash1([]string{"go.mod"}, func(string) (io.ReadCloser, error) {
		return io.NopCloser(newReader(goModData)), nil
	})

	if zerr != nil || gerr != nil || zipHashStr != existing.ModuleHash || goModHashStr != existing.GoModHash {
		// The store holds bytes that are not the bytes it recorded. That is a
		// finding, not a miss: it is audited and the run downloads a clean copy
		// rather than silently overwriting the evidence of the disagreement.
		attrs := []slog.Attr{
			slog.String("recorded_module_hash", existing.ModuleHash),
			slog.String("computed_module_hash", zipHashStr),
			slog.String("recorded_go_mod_hash", existing.GoModHash),
			slog.String("computed_go_mod_hash", goModHashStr),
		}
		if rerr := errors.Join(zerr, gerr); rerr != nil {
			attrs = append(attrs, slog.String("hash_error", rerr.Error()))
		}
		log.LogAttrs(ctx, slog.LevelWarn, "held_artefact_disagrees_with_record", attrs...)
		if aerr := uc.recordTamperEvent(existing, zipHashStr, goModHashStr); aerr != nil {
			return revalidation{}, false, aerr
		}
		return revalidation{}, false, nil
	}

	zipHash, err := domain2.ParseModuleHash(zipHashStr)
	if err != nil {
		return revalidation{}, false, fmt.Errorf("parsing re-computed zip hash for %s: %w", existing.Coordinate(), err)
	}
	goModHash, err := domain2.ParseModuleHash(goModHashStr)
	if err != nil {
		return revalidation{}, false, fmt.Errorf("parsing re-computed go.mod hash for %s: %w", existing.Coordinate(), err)
	}

	log.InfoContext(ctx, "revalidating_held_artefacts",
		slog.String("module_hash", zipHashStr),
		slog.String("identity", zipIdentity.String()),
	)
	return revalidation{
		download: ports.ModuleDownload{
			Zip:       io.NopCloser(newReader(zipData)),
			GoMod:     io.NopCloser(newReader(goModData)),
			ZipHash:   zipHash,
			GoModHash: goModHash,
			Digests:   domain2.ComputeArtifactDigests(zipData),
		},
		zipData:   zipData,
		goModData: goModData,
	}, true, nil
}

// readHeldArtefact returns the bytes the blob store holds for identity. ok is
// false when the store does not hold it, which is an absence rather than an
// error: an evicted artefact is re-acquired exactly as it always was.
func (uc *FetchModuleUseCase) readHeldArtefact(ctx context.Context, identity ports.BlobIdentity) (_ []byte, _ bool, retErr error) {
	exists, err := uc.blobs.Exists(ctx, identity)
	if err != nil || !exists {
		return nil, false, nil //nolint:nilerr // an unreadable store is a re-acquisition, not a failure
	}
	rc, err := uc.blobs.Get(ctx, identity)
	if err != nil {
		return nil, false, nil //nolint:nilerr // as above
	}
	defer func() {
		if cerr := rc.Close(); cerr != nil && retErr == nil {
			retErr = fmt.Errorf("closing held artefact %s: %w", identity, cerr)
		}
	}()
	data, err := io.ReadAll(rc)
	if err != nil {
		return nil, false, fmt.Errorf("reading held artefact %s: %w", identity, err)
	}
	return data, true, nil
}

// recordTamperEvent appends the assurance-log entry for held bytes that do not
// match the record describing them. A nil sink is a no-op; an emit failure is
// returned rather than swallowed, because the one event that says the store
// contradicted itself must never be lost silently.
func (uc *FetchModuleUseCase) recordTamperEvent(existing domain2.FactRecord, computedZip, computedGoMod string) error {
	if uc.audit == nil {
		return nil
	}
	e := audit.Event{Type: audit.EventVerificationFailed, Payload: map[string]any{
		"module":               existing.ModulePath,
		"version":              existing.ModuleVersion,
		"pipeline_version":     existing.PipelineVersion,
		"verification_status":  existing.VerificationStatus,
		"reason":               "held artefact does not match the record describing it",
		"recorded_module_hash": existing.ModuleHash,
		"computed_module_hash": computedZip,
		"recorded_go_mod_hash": existing.GoModHash,
		"computed_go_mod_hash": computedGoMod,
	}}
	if err := uc.audit.RecordEvent(e); err != nil {
		return fmt.Errorf("recording held-artefact mismatch for %s: %w", existing.Coordinate(), err)
	}
	return nil
}
