package application

import (
	"context"
	"crypto/rand"
	"fmt"
	"log/slog"

	"github.com/eitanity/kanonarion/internal/coordinate"

	"github.com/eitanity/kanonarion/internal/audit"

	"github.com/eitanity/kanonarion/internal/walk/domain"
	walkports "github.com/eitanity/kanonarion/internal/walk/ports"
	"github.com/oklog/ulid/v2"
)

// ExecuteWalkUseCase runs a Walk and persists the resulting WalkRecord.
type ExecuteWalkUseCase struct {
	walker          *Walker
	store           walkports.WalkStore
	operator        string
	pipelineVersion string
	logger          *slog.Logger
	audit           walkports.AuditSink // optional; nil disables audit emission
}

// NewExecuteWalkUseCase constructs an ExecuteWalkUseCase.
func NewExecuteWalkUseCase(
	walker *Walker,
	store walkports.WalkStore,
	operator string,
	pipelineVersion string,
	logger *slog.Logger,
) *ExecuteWalkUseCase {
	return &ExecuteWalkUseCase{
		walker:          walker,
		store:           store,
		operator:        operator,
		pipelineVersion: pipelineVersion,
		logger:          logger,
	}
}

// WithAudit wires an audit sink so each successful walk appends one
// walk_completed assurance-log event carrying the walk id, root coordinate,
// scope, node count and content hash. It is optional — a nil sink (the default)
// disables emission — and returns the receiver for chaining, mirroring the
// other optional-dependency builders. Only a succeeded walk emits: a partial or
// cancelled walk defines no complete population to anchor.
func (uc *ExecuteWalkUseCase) WithAudit(sink walkports.AuditSink) *ExecuteWalkUseCase {
	uc.audit = sink
	return uc
}

// ExecuteWalkResult is the output of Execute.
type ExecuteWalkResult struct {
	Record domain.WalkRecord

	// Reused reports that this run did not mint a new walk: the analysis it
	// performed was identical to one already stored, so Record is that stored
	// walk. It is not the same claim as "nothing ran" — the resolution itself
	// was re-derived, and finding it identical is the measurement. What is
	// reused is the walk's IDENTITY, and with it everything downstream that is
	// keyed on a walk id.
	//
	// The short-circuit above it (a cached successful walk served without
	// walking at all) also reports Reused, because from the caller's side the
	// distinction that matters is the same: the returned record was not
	// produced by this run.
	Reused bool
}

// Execute runs the walk for req and persists the resulting WalkRecord.
//
// If a successful walk already exists for the same target and scope, and Force is false,
// Execute returns the existing record and skips the walk.
//
// If the most recent stored walk for the same target and scope is partial or cancelled,
// Execute reuses its ID so the existing record is updated in-place rather than
// creating a duplicate. The fetch cache ensures already-succeeded modules are
// cache hits, so only previously-failed modules are retried over the network.
//
// The walk ID is logged as walk_started (or walk_resuming) before the walk
// runs, so it can be correlated with log output even if the walk is interrupted.
func (uc *ExecuteWalkUseCase) Execute(ctx context.Context, req WalkRequest) (ExecuteWalkResult, error) {
	scope := req.Scope
	if scope == "" {
		scope = domain.WalkScopeCode
	}
	depth := req.Depth
	if depth == "" {
		depth = domain.WalkDepthFull
	}

	// Project walks root at the local main module at the synthetic "local"
	// version, which — unlike a published semver — does not pin content: the
	// working tree's go.mod can change between runs. Skip the succeeded-cache
	// short-circuit so a project walk always re-resolves the current go.mod.
	// (The fetch-level cache still makes unchanged dependencies cheap.)
	summaries, err := uc.store.ListWalks(ctx, walkports.WalkFilter{Target: &req.Target, Scope: &scope, Limit: 1})
	if !req.ProjectMode && err == nil && len(summaries) > 0 {
		s := summaries[0]
		// A shallow cached walk must not satisfy a full walk request.
		cacheUsable := s.OverallStatus == domain.WalkSucceeded &&
			(depth == domain.WalkDepthShallow || s.Depth != domain.WalkDepthShallow)
		if !req.Force && cacheUsable {
			fullRec, gerr := uc.store.GetWalk(ctx, s.ID)
			// A stored walk resolved by superseded graph logic must not be served.
			// The pipeline version is what makes a corrected resolver take effect on
			// its own, rather than every caller having to know to pass --force;
			// serving a stale graph presents a known-incomplete dependency set as
			// authoritative. The version is read from the graph, not the walk record:
			// the record's own pipeline version is left unset by the current
			// composition, while the graph's always reflects the resolver that
			// produced it.
			current := uc.walker.graphPipelineVersion()
			switch {
			case gerr != nil:
				// Fall through and re-walk if GetWalk fails for some reason.
			case fullRec.Graph.PipelineVersion != current:
				uc.logger.InfoContext(ctx, "walk_cache_stale",
					slog.String("walk_id", s.ID),
					slog.String("target", req.Target.String()),
					slog.String("stored_pipeline_version", fullRec.Graph.PipelineVersion),
					slog.String("current_pipeline_version", current),
					slog.String("reason", "graph pipeline version superseded; re-resolving"),
				)
			default:
				uc.logger.InfoContext(ctx, "walk_skipped",
					slog.String("walk_id", s.ID),
					slog.String("target", req.Target.String()),
					slog.String("reason", "cached successful walk exists"),
				)
				return ExecuteWalkResult{Record: fullRec, Reused: true}, nil
			}
		}
	}

	id, resuming, err := uc.resolveWalkID(ctx, req.Target, scope)
	if err != nil {
		return ExecuteWalkResult{}, err
	}
	if resuming {
		uc.logger.InfoContext(ctx, "walk_resuming",
			slog.String("walk_id", id),
			slog.String("target", req.Target.String()),
		)
	} else {
		uc.logger.InfoContext(ctx, "walk_started",
			slog.String("walk_id", id),
			slog.String("target", req.Target.String()),
		)
	}

	outcome, err := uc.walker.Walk(ctx, req)
	if err != nil {
		return ExecuteWalkResult{}, fmt.Errorf("running walk: %w", err)
	}

	policy := domain.DefaultDepthPolicy()
	if req.Policy != nil {
		policy = *req.Policy
	}
	operator := uc.operator
	if req.Operator != "" {
		operator = req.Operator
	}
	rec := domain.NewWalkRecord(id, operator, uc.pipelineVersion, scope, depth, outcome, policy, req.PolicyHash)
	// The directory this walk was rooted at, so a later re-scan by walk id can
	// reach the same analysis surface — notably a vendored tree — instead of
	// silently answering about the fetched artefacts. Empty for a walk of a
	// published coordinate, which has no project root. It is set outside the
	// constructor because it is provenance the record carries rather than part
	// of the walk the constructor seals: NewWalkRecord builds the hashed shape,
	// and this field is not in it.
	rec.ProjectDir = req.ProjectDir
	// The identity of the analysis just performed, computed before the seal
	// because the seal does not cover it. It is what makes an unchanged input
	// resolve to the walk it resolved to last time instead of to a new one.
	identity, err := domain.WalkRecordHasher{}.IdentityHash(rec)
	if err != nil {
		return ExecuteWalkResult{}, fmt.Errorf("hashing walk identity: %w", err)
	}
	rec.IdentityHash = identity

	// A walk that analysed exactly what an already-stored walk analysed IS that
	// walk. Minting a second id for it is what made every downstream record —
	// licences, vulnerability scans, SBOMs, all keyed on the walk id — unreachable
	// from the next run, so the tool re-derived a full scan because its own cache
	// key was fresh by construction rather than because anything had changed.
	//
	// --force is the operator saying "measure it again anyway", and it skips this
	// for the same reason it skips the cache above.
	if !req.Force {
		if prior, ok := uc.reusableWalk(ctx, req.Target, scope, identity, id); ok {
			uc.logger.InfoContext(ctx, "walk_identity_reused",
				slog.String("walk_id", prior.ID),
				slog.String("discarded_walk_id", id),
				slog.String("target", req.Target.String()),
				slog.String("identity_hash", identity),
				slog.String("reason", "an existing walk records the same analysis"),
			)
			return ExecuteWalkResult{Record: prior, Reused: true}, nil
		}
	}

	rec, err = domain.WalkRecordHasher{}.SetContentHash(rec)
	if err != nil {
		return ExecuteWalkResult{}, fmt.Errorf("hashing walk record: %w", err)
	}

	if err := uc.store.PutWalk(ctx, rec); err != nil {
		return ExecuteWalkResult{}, fmt.Errorf("persisting walk record: %w", err)
	}

	// Assurance log: one walk_completed event per successful walk anchors the
	// audited population — the dependency set everything downstream is scoped
	// from — in the tamper-resistant append-only log, not only in the mutable
	// walk record.
	if err := uc.emitWalkCompleted(rec); err != nil {
		return ExecuteWalkResult{}, err
	}

	return ExecuteWalkResult{Record: rec}, nil
}

// emitWalkCompleted appends one walk_completed event for a successful walk. A
// nil audit sink disables emission, and a walk that did not succeed emits
// nothing: only a completed closure defines a population worth anchoring.
func (uc *ExecuteWalkUseCase) emitWalkCompleted(rec domain.WalkRecord) error {
	if uc.audit == nil || rec.OverallStatus != domain.WalkSucceeded {
		return nil
	}
	if err := uc.audit.RecordEvent(walkCompletedEvent(rec)); err != nil {
		return fmt.Errorf("recording walk completion audit event: %w", err)
	}
	return nil
}

// walkCompletedEvent builds the assurance-log envelope for one successful walk.
func walkCompletedEvent(rec domain.WalkRecord) audit.Event {
	return audit.Event{
		Type: audit.EventWalkCompleted,
		Payload: map[string]any{
			"walk_id":      rec.ID,
			"module":       rec.Target.Path(),
			"version":      rec.Target.Version(),
			"scope":        string(rec.Scope),
			"node_count":   len(rec.Graph.Nodes),
			"content_hash": rec.ContentHash,
		},
	}
}

// reusableWalk returns a stored walk for target and scope whose identity is
// identity, if one exists and can be read back intact.
//
// currentID is the id this run would otherwise write under. A match on it is not
// a reuse — it is the same row, and the run should persist over it normally,
// which is what a resumed partial walk relies on.
//
// Every failure here is answered by falling through to a normal write. A lookup
// that could not be made is not evidence that no prior walk exists, and the
// worst outcome of writing a second record is the behaviour that shipped before
// identities existed; the worst outcome of trusting a failed read would be
// serving a record this run never established.
func (uc *ExecuteWalkUseCase) reusableWalk(
	ctx context.Context,
	target coordinate.ModuleCoordinate,
	scope domain.WalkScope,
	identity string,
	currentID string,
) (domain.WalkRecord, bool) {
	// An empty identity names no analysis; it is what the rows written before the
	// column existed carry, and matching on it would serve an arbitrary old walk.
	if identity == "" {
		return domain.WalkRecord{}, false
	}
	summaries, err := uc.store.ListWalks(ctx, walkports.WalkFilter{
		Target:       &target,
		Scope:        &scope,
		IdentityHash: &identity,
		Limit:        1,
	})
	if err != nil || len(summaries) == 0 {
		return domain.WalkRecord{}, false
	}
	if summaries[0].ID == currentID {
		return domain.WalkRecord{}, false
	}
	prior, err := uc.store.GetWalk(ctx, summaries[0].ID)
	if err != nil {
		uc.logger.WarnContext(ctx, "walk_identity_match_unreadable",
			slog.String("walk_id", summaries[0].ID),
			slog.String("identity_hash", identity),
			slog.String("error", err.Error()),
			slog.String("reason", "re-walking rather than serving a record that could not be read back"),
		)
		return domain.WalkRecord{}, false
	}
	return prior, true
}

// resolveWalkID returns the walk ID to use. If the most recent stored walk for
// target and scope has status partial or cancelled, its ID is returned with resuming=true
// so the record is updated in-place. Otherwise a fresh ULID is generated.
func (uc *ExecuteWalkUseCase) resolveWalkID(ctx context.Context, target coordinate.ModuleCoordinate, scope domain.WalkScope) (id string, resuming bool, err error) {
	summaries, err := uc.store.ListWalks(ctx, walkports.WalkFilter{Target: &target, Scope: &scope, Limit: 1})
	if err == nil && len(summaries) > 0 {
		if s := summaries[0]; s.OverallStatus == domain.WalkPartial || s.OverallStatus == domain.WalkCancelled {
			return s.ID, true, nil
		}
	}
	newID, err := ulid.New(ulid.Now(), rand.Reader)
	if err != nil {
		return "", false, fmt.Errorf("generating walk id: %w", err)
	}
	return newID.String(), false, nil
}
