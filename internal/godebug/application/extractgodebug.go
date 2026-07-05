// Package application orchestrates godebug detection: load via ports,
// delegate classification to the domain taxonomy, evaluate governance via the
// config policy, persist the record and emit audit facts. It contains no
// source parsing, no risk rules and no I/O of its own.
package application

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/eitanity/kanonarion/internal/audit"
	configdomain "github.com/eitanity/kanonarion/internal/config/domain"
	fetchports "github.com/eitanity/kanonarion/internal/fetch/ports"
	"github.com/eitanity/kanonarion/internal/godebug/domain"
	"github.com/eitanity/kanonarion/internal/godebug/ports"
)

// Config wires the ExtractGoDebugUseCase dependencies.
type Config struct {
	Scanner   ports.GoDebugScanner
	Store     ports.GoDebugStore
	Audit     ports.AuditSink
	Clock     fetchports.Clock
	Stopwatch fetchports.Stopwatch
	Logger    *slog.Logger
}

// ExtractGoDebugUseCase detects, classifies, policy-evaluates and persists
// the GODEBUG / //go:debug settings of a project.
type ExtractGoDebugUseCase struct {
	scanner   ports.GoDebugScanner
	store     ports.GoDebugStore
	audit     ports.AuditSink
	clock     fetchports.Clock
	stopwatch fetchports.Stopwatch
	logger    *slog.Logger
}

// NewExtractGoDebugUseCase constructs the use case.
func NewExtractGoDebugUseCase(cfg Config) *ExtractGoDebugUseCase {
	return &ExtractGoDebugUseCase{
		scanner: cfg.Scanner, store: cfg.Store, audit: cfg.Audit,
		clock: cfg.Clock, stopwatch: cfg.Stopwatch, logger: cfg.Logger,
	}
}

// Extract scans goModPath, classifies every setting against the versioned
// taxonomy, evaluates it against policy, persists the record, and emits one
// audit event per setting. The returned record's settings carry their tier
// and policy verdict.
func (uc *ExtractGoDebugUseCase) Extract(
	ctx context.Context, goModPath string, policy configdomain.GoDebugPolicy,
) (domain.Record, error) {
	lap := uc.stopwatch.Start()

	res, err := uc.scanner.ScanProject(goModPath)
	if err != nil {
		return domain.Record{}, fmt.Errorf("scanning project godebug settings: %w", err)
	}

	ss := res.Settings
	for i := range ss {
		s := &ss[i]
		s.Tier = domain.Classify(s.Name)
		outcome := policy.Evaluate(s.Tier.String())
		s.PolicyOutcome = string(outcome)
		// A not-applied setting is recorded and classified but never gates
		// the build: it has no effect on the current binary. Only an
		// applied, policy-failing setting is blocking.
		s.PolicyBlocking = s.Applied && outcome == configdomain.PolicyOutcomeWarn
	}
	domain.Sort(ss)

	rec := domain.Record{
		Ecosystem:         domain.EcosystemGo,
		ProjectModulePath: res.ProjectModulePath,
		Settings:          ss,
		TaxonomyVersion:   domain.TaxonomyVersion(),
		ExtractedAt:       uc.clock.Now().UTC(),
		SchemaVersion:     domain.GoDebugSchemaVersion,
		PipelineVersion:   domain.PipelineVersion,
	}
	rec.ContentHash = domain.Hash(ss)

	if err := uc.store.PutGoDebugRecord(ctx, rec); err != nil {
		return domain.Record{}, fmt.Errorf("persisting godebug record: %w", err)
	}
	for _, s := range ss {
		if err := uc.audit.RecordEvent(auditEvent(res.ProjectModulePath, s)); err != nil {
			return domain.Record{}, fmt.Errorf("recording godebug audit event: %w", err)
		}
	}

	if uc.logger != nil {
		uc.logger.Debug("godebug scan complete",
			"project", res.ProjectModulePath,
			"settings", len(ss),
			"taxonomy", domain.TaxonomyVersion(),
			"elapsed", lap.Elapsed())
	}
	return rec, nil
}

// auditEvent builds the audit envelope for a classified setting. One
// event per detected setting makes add/remove/modify between scans observable
// from the append-only log without a bespoke diff schema.
func auditEvent(project string, s domain.Setting) audit.Event {
	return audit.Event{
		Type: audit.EventGoDebugSettingObserved,
		Payload: map[string]any{
			"project":         project,
			"source":          s.Source,
			"line":            s.Line,
			"module":          s.Module,
			"setting":         s.Name,
			"value":           s.Value,
			"applied":         s.Applied,
			"classification":  s.Tier.String(),
			"policy_outcome":  s.PolicyOutcome,
			"policy_blocking": s.PolicyBlocking,
		},
	}
}
