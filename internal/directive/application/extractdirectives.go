// Package application orchestrates directive detection: load via ports,
// delegate classification to the domain, evaluate governance via the config
// policy, persist the record and emit audit facts. It contains no parsing,
// no risk rules and no I/O of its own.
package application

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/oklog/ulid/v2"

	"github.com/eitanity/kanonarion/internal/audit"
	configdomain "github.com/eitanity/kanonarion/internal/config/domain"
	"github.com/eitanity/kanonarion/internal/directive/domain"
	"github.com/eitanity/kanonarion/internal/directive/ports"
	fetchports "github.com/eitanity/kanonarion/internal/fetch/ports"
)

// Config wires the ExtractDirectivesUseCase dependencies.
type Config struct {
	Parser    ports.DirectiveParser
	Store     ports.DirectiveStore
	Audit     ports.AuditSink
	Clock     fetchports.Clock
	Stopwatch fetchports.Stopwatch
	Logger    *slog.Logger
}

// ExtractDirectivesUseCase detects, classifies, policy-evaluates and persists
// the replace/exclude directives of a project.
type ExtractDirectivesUseCase struct {
	parser    ports.DirectiveParser
	store     ports.DirectiveStore
	audit     ports.AuditSink
	clock     fetchports.Clock
	stopwatch fetchports.Stopwatch
	logger    *slog.Logger
}

// NewExtractDirectivesUseCase constructs the use case.
func NewExtractDirectivesUseCase(cfg Config) *ExtractDirectivesUseCase {
	return &ExtractDirectivesUseCase{
		parser: cfg.Parser, store: cfg.Store, audit: cfg.Audit,
		clock: cfg.Clock, stopwatch: cfg.Stopwatch, logger: cfg.Logger,
	}
}

// Extract scans goModPath, classifies and policy-evaluates every directive
// against policy, persists the record, and emits one audit event per
// directive. The returned record's directives carry their classification and
// policy verdict.
func (uc *ExtractDirectivesUseCase) Extract(
	ctx context.Context, goModPath string, policy configdomain.DirectivePolicy,
) (domain.Record, error) {
	lap := uc.stopwatch.Start()
	startedAt := uc.clock.Now().UTC()

	res, err := uc.parser.ParseProject(goModPath)
	if err != nil {
		return domain.Record{}, fmt.Errorf("parsing project directives: %w", err)
	}

	ds := res.Directives
	for i := range ds {
		d := &ds[i]
		d.Class = domain.Classify(*d, res.ResolvedVersions[d.OldPath])
		d.ReachabilityTarget = domain.ReachabilityTargetOf(*d)
		outcome := policy.Evaluate(policyCategory(*d))
		d.PolicyOutcome = string(outcome)
		d.PolicyBlocking = outcome == configdomain.PolicyOutcomeWarn
	}
	domain.Sort(ds)

	completedAt := uc.clock.Now().UTC()
	rec := domain.Record{
		ID:                ulid.Make().String(),
		Ecosystem:         domain.EcosystemGo,
		ProjectModulePath: res.ProjectModulePath,
		Directives:        ds,
		ResolvedVersions:  res.ResolvedVersions,
		StartedAt:         startedAt,
		CompletedAt:       completedAt,
		ExtractedAt:       completedAt,
		SchemaVersion:     domain.DirectiveSchemaVersion,
		PipelineVersion:   domain.PipelineVersion,
	}
	rec.ContentHash = domain.Hash(ds)

	if err := uc.store.PutDirectiveRecord(ctx, rec); err != nil {
		return domain.Record{}, fmt.Errorf("persisting directive record: %w", err)
	}
	for _, d := range ds {
		if err := uc.audit.RecordEvent(auditEvent(res.ProjectModulePath, d)); err != nil {
			return domain.Record{}, fmt.Errorf("recording directive audit event: %w", err)
		}
	}

	if uc.logger != nil {
		uc.logger.Debug("directive scan complete",
			"project", res.ProjectModulePath,
			"directives", len(ds),
			"elapsed", lap.Elapsed())
	}
	return rec, nil
}

// policyCategory maps a classified directive onto the config policy category
// token. The mapping lives here, not in config, so the config context stays
// ignorant of the directive bounded context.
func policyCategory(d domain.Directive) string {
	switch d.Kind {
	case domain.KindReplace:
		switch {
		case d.IsLocal:
			return configdomain.DirectiveLocalPathReplace
		case d.NewPath != "" && d.NewPath != d.OldPath:
			return configdomain.DirectiveModulePathReplace
		default:
			return configdomain.DirectiveVersionReplace
		}
	case domain.KindExclude:
		if d.Class == domain.RiskHigh {
			return configdomain.DirectiveExcludeNewer
		}
		return configdomain.DirectiveExcludeOlder
	default:
		return ""
	}
}

// auditEvent builds the audit envelope for a classified directive.
func auditEvent(project string, d domain.Directive) audit.Event {
	t := audit.EventReplaceDirectiveObserved
	if d.Kind == domain.KindExclude {
		t = audit.EventExcludeDirectiveObserved
	}
	return audit.Event{
		Type: t,
		Payload: map[string]any{
			"project":             project,
			"source":              d.Source,
			"line":                d.Line,
			"old_path":            d.OldPath,
			"old_version":         d.OldVersion,
			"new_path":            d.NewPath,
			"new_version":         d.NewVersion,
			"local_path":          d.LocalPath,
			"applied":             d.Applied,
			"classification":      d.Class.String(),
			"reachability_target": d.ReachabilityTarget,
			"policy_outcome":      d.PolicyOutcome,
			"policy_blocking":     d.PolicyBlocking,
		},
	}
}
