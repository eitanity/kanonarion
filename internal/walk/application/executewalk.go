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
				return ExecuteWalkResult{Record: fullRec}, nil
			}
		}
	}

	id, resuming := uc.resolveWalkID(ctx, req.Target, scope)
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
	rec := domain.NewWalkRecord(id, uc.operator, uc.pipelineVersion, scope, depth, outcome, policy, req.PolicyHash)
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
			"module":       rec.Target.Path,
			"version":      rec.Target.Version,
			"scope":        string(rec.Scope),
			"node_count":   len(rec.Graph.Nodes),
			"content_hash": rec.ContentHash,
		},
	}
}

// resolveWalkID returns the walk ID to use. If the most recent stored walk for
// target and scope has status partial or cancelled, its ID is returned with resuming=true
// so the record is updated in-place. Otherwise a fresh ULID is generated.
func (uc *ExecuteWalkUseCase) resolveWalkID(ctx context.Context, target coordinate.ModuleCoordinate, scope domain.WalkScope) (id string, resuming bool) {
	summaries, err := uc.store.ListWalks(ctx, walkports.WalkFilter{Target: &target, Scope: &scope, Limit: 1})
	if err == nil && len(summaries) > 0 {
		if s := summaries[0]; s.OverallStatus == domain.WalkPartial || s.OverallStatus == domain.WalkCancelled {
			return s.ID, true
		}
	}
	return ulid.MustNew(ulid.Now(), rand.Reader).String(), false
}
