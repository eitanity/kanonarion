package application

import (
	"context"
	"fmt"

	"github.com/eitanity/kanonarion/internal/audit"
	"github.com/eitanity/kanonarion/internal/coordinate"
	domain2 "github.com/eitanity/kanonarion/internal/fetch/domain"
	"github.com/eitanity/kanonarion/internal/fetch/ports"
)

// ServeModuleUseCase resolves a single ModuleCoordinate to a servable blob,
// fetching and verifying on a miss. It is the only individually exported WRITE
// use case: it powers a gating module proxy that serves only
// approved packages and fetches-and-verifies on miss. The bulk pipeline stays
// behind the composition root.
//
// "Miss" means the blob is not servable, which covers two cases: no fact record
// exists yet, or a record exists but its content blob is absent from the store
// (e.g. evicted). Both trigger a fetch-and-verify; the underlying verification
// path (sumdb/hash) is unchanged — Serve never weakens it and never makes a
// gating decision of its own. The caller inspects VerificationStatus and applies
// its own fail-closed policy before streaming the bytes behind Handle.
type ServeModuleUseCase struct {
	fetch *FetchModuleUseCase
	blobs ports.BlobStore
	audit ports.AuditSink
}

// NewServeModuleUseCase constructs a ServeModuleUseCase over the fetch pipeline
// and the blob store the pipeline persists into. blobs is the same store fetch
// writes to, used here only to confirm a cached record's blob is still present.
func NewServeModuleUseCase(fetch *FetchModuleUseCase, blobs ports.BlobStore) *ServeModuleUseCase {
	return &ServeModuleUseCase{fetch: fetch, blobs: blobs}
}

// WithAudit wires an assurance-log sink so each served coordinate emits a
// verification outcome: record_read_verified when the module was positively
// verified, verification_failed otherwise. It mirrors WithSigner: the sink is
// optional, so a caller that does not supply one simply logs nothing. Returns
// the receiver for chaining.
func (uc *ServeModuleUseCase) WithAudit(sink ports.AuditSink) *ServeModuleUseCase {
	uc.audit = sink
	return uc
}

// ServeRequest is the input to Serve.
type ServeRequest struct {
	// Coordinate is the module to resolve and serve.
	Coordinate coordinate.ModuleCoordinate
	// SkipVCSVerify skips the git cross-verification step on a fetch; sumdb
	// verification still runs. Forwarded to the fetch pipeline unchanged.
	SkipVCSVerify bool
}

// ServeResult is the output of Serve.
type ServeResult struct {
	// Handle is the opaque blob handle for the module zip, ready to stream to a
	// consumer via BlobStore.Get. Guaranteed present in the store on success.
	Handle ports.BlobHandle
	// VerificationStatus is the outcome the fetch pipeline recorded for this
	// module. The caller applies its own fail-closed policy against it before
	// serving the bytes.
	VerificationStatus domain2.VerificationStatus
	// Record is the full fact record backing this handle.
	Record domain2.FactRecord
	// FromCache reports whether the record was served from an existing record
	// (true) or freshly fetched and verified (false).
	FromCache bool
}

// Serve resolves req.Coordinate to a servable blob handle, fetching and
// verifying on a miss. On a cache hit it confirms the referenced blob is still
// present; if it has been evicted, it re-fetches (forcing past the cache) so the
// returned Handle always names a blob that exists in the store. It returns an
// error only on infrastructure failure (proxy, VCS, storage) — a module that
// fails integrity verification still returns successfully with the failing
// VerificationStatus set, so the caller, not Serve, decides whether to serve it.
func (uc *ServeModuleUseCase) Serve(ctx context.Context, req ServeRequest) (ServeResult, error) {
	res, err := uc.fetch.Execute(ctx, FetchRequest{
		Coordinate:    req.Coordinate,
		SkipVCSVerify: req.SkipVCSVerify,
	})
	if err != nil {
		return ServeResult{}, fmt.Errorf("fetch-on-miss for %s: %w", req.Coordinate, err)
	}

	// A cache hit may reference a blob that has since been evicted. Treat an
	// absent blob as a miss and re-fetch, forcing past the cache so the record
	// and its blob are rewritten together.
	if res.FromCache {
		present, err := uc.blobs.Exists(ctx, ports.BlobHandle(res.Record.ContentLocation))
		if err != nil {
			return ServeResult{}, fmt.Errorf("checking blob presence for %s: %w", req.Coordinate, err)
		}
		if !present {
			res, err = uc.fetch.Execute(ctx, FetchRequest{
				Coordinate:    req.Coordinate,
				Force:         true,
				SkipVCSVerify: req.SkipVCSVerify,
			})
			if err != nil {
				return ServeResult{}, fmt.Errorf("re-fetch of evicted %s: %w", req.Coordinate, err)
			}
		}
	}

	handle := ports.BlobHandle(res.Record.ContentLocation)
	present, err := uc.blobs.Exists(ctx, handle)
	if err != nil {
		return ServeResult{}, fmt.Errorf("confirming blob presence for %s: %w", req.Coordinate, err)
	}
	if !present {
		return ServeResult{}, fmt.Errorf("fetched %s but its content blob %q is absent from the store", req.Coordinate, handle)
	}

	status := domain2.VerificationStatus(res.Record.VerificationStatus)
	if err := uc.recordServeOutcome(res.Record, status); err != nil {
		return ServeResult{}, err
	}

	return ServeResult{
		Handle:             handle,
		VerificationStatus: status,
		Record:             res.Record,
		FromCache:          res.FromCache,
	}, nil
}

// recordServeOutcome appends the assurance-log event for a resolved coordinate:
// record_read_verified when the record was positively verified, otherwise
// verification_failed with the verification detail as the rejection reason. The
// exact status travels in the payload either way, so a hard mismatch is never
// conflated with an un-analysed outcome. Serve makes no gating decision — it
// records what it observed and leaves the fail-closed policy to the caller. A
// nil sink is a no-op; an emit failure fails the serve so the log can never
// silently miss what was served.
func (uc *ServeModuleUseCase) recordServeOutcome(rec domain2.FactRecord, status domain2.VerificationStatus) error {
	if uc.audit == nil {
		return nil
	}
	var event audit.Event
	if status.IsVerified() {
		event = audit.Event{
			Type: audit.EventRecordReadVerified,
			Payload: map[string]any{
				"module":              rec.ModulePath,
				"version":             rec.ModuleVersion,
				"pipeline_version":    rec.PipelineVersion,
				"verification_status": string(status),
			},
		}
	} else {
		event = audit.Event{
			Type: audit.EventVerificationFailed,
			Payload: map[string]any{
				"module":              rec.ModulePath,
				"version":             rec.ModuleVersion,
				"pipeline_version":    rec.PipelineVersion,
				"verification_status": string(status),
				"reason":              serveRejectionReason(rec),
			},
		}
	}
	if err := uc.audit.RecordEvent(event); err != nil {
		return fmt.Errorf("recording serve audit event for %s: %w", rec.Coordinate(), err)
	}
	return nil
}

// serveRejectionReason is the human-readable reason a served record was not
// positively verified: the fetch pipeline's verification detail when present,
// otherwise the status itself so the reason is never blank.
func serveRejectionReason(rec domain2.FactRecord) string {
	if rec.VerificationDetail != "" {
		return rec.VerificationDetail
	}
	return rec.VerificationStatus
}
