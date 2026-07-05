// Package application orchestrates FIPS assessment: load via ports,
// delegate classification to the domain catalogue, evaluate governance via
// the config policy, persist the record and emit audit facts. It contains
// no source parsing, no risk rules and no I/O of its own.
package application

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/eitanity/kanonarion/internal/audit"
	configdomain "github.com/eitanity/kanonarion/internal/config/domain"
	fetchports "github.com/eitanity/kanonarion/internal/fetch/ports"
	"github.com/eitanity/kanonarion/internal/fips/domain"
	"github.com/eitanity/kanonarion/internal/fips/ports"
)

// Config wires the ExtractFIPSUseCase dependencies.
type Config struct {
	Scanner   ports.FIPSScanner
	Store     ports.FIPSStore
	Audit     ports.AuditSink
	Clock     fetchports.Clock
	Stopwatch fetchports.Stopwatch
	Logger    *slog.Logger
}

// ExtractFIPSUseCase detects, classifies, policy-evaluates and persists the
// FIPS-eligibility facts of a project.
type ExtractFIPSUseCase struct {
	scanner   ports.FIPSScanner
	store     ports.FIPSStore
	audit     ports.AuditSink
	clock     fetchports.Clock
	stopwatch fetchports.Stopwatch
	logger    *slog.Logger
}

// NewExtractFIPSUseCase constructs the use case.
func NewExtractFIPSUseCase(cfg Config) *ExtractFIPSUseCase {
	return &ExtractFIPSUseCase{
		scanner: cfg.Scanner, store: cfg.Store, audit: cfg.Audit,
		clock: cfg.Clock, stopwatch: cfg.Stopwatch, logger: cfg.Logger,
	}
}

// Extract scans goModPath, classifies every finding against the catalogue,
// evaluates it against policy, persists the record, and emits one audit
// event per finding. The returned record's findings carry their category
// and policy verdict; the headline ToolchainCapable / variant fields and a
// stable compliance-assessment line are also populated.
func (uc *ExtractFIPSUseCase) Extract(
	ctx context.Context, goModPath string, policy configdomain.FIPSPolicy,
) (domain.Record, error) {
	lap := uc.stopwatch.Start()

	res, err := uc.scanner.ScanProject(goModPath)
	if err != nil {
		return domain.Record{}, fmt.Errorf("scanning project FIPS facts: %w", err)
	}

	evaluate := func(c domain.Category) (string, bool) {
		outcome := policy.Evaluate(string(c))
		// Blocking when policy resolved to warn; allow/notify never gate.
		return string(outcome), outcome == configdomain.PolicyOutcomeWarn
	}
	capable, variant, findings, contentHash, summary := domain.AssembleAssessment(res, evaluate)

	rec := domain.Record{
		Ecosystem:            domain.EcosystemGo,
		ProjectModulePath:    res.ProjectModulePath,
		ToolchainCapable:     capable,
		ToolchainVariant:     variant,
		ToolchainRaw:         res.ToolchainRaw,
		Findings:             findings,
		ComplianceAssessment: summary,
		Caveat:               domain.EligibilityCaveat,
		CatalogueVersion:     domain.CatalogueVersion(),
		ExtractedAt:          uc.clock.Now().UTC(),
		SchemaVersion:        domain.FIPSSchemaVersion,
		PipelineVersion:      domain.PipelineVersion,
		ContentHash:          contentHash,
	}

	if err := uc.store.PutFIPSRecord(ctx, rec); err != nil {
		return domain.Record{}, fmt.Errorf("persisting fips record: %w", err)
	}
	for _, f := range findings {
		if err := uc.audit.RecordEvent(auditEvent(res.ProjectModulePath, capable, variant, f)); err != nil {
			return domain.Record{}, fmt.Errorf("recording fips audit event: %w", err)
		}
	}

	if uc.logger != nil {
		uc.logger.Debug("fips scan complete",
			"project", res.ProjectModulePath,
			"toolchain_capable", capable,
			"variant", variant,
			"findings", len(findings),
			"catalogue", domain.CatalogueVersion(),
			"elapsed", lap.Elapsed())
	}
	return rec, nil
}

// auditEvent builds the audit envelope for a classified finding.
// One event per finding makes add/remove/modify between scans observable
// from the append-only log without a bespoke diff schema (mirroring).
func auditEvent(project string, toolchainCapable bool, toolchainVariant string, f domain.Finding) audit.Event {
	return audit.Event{
		Type: audit.EventFIPSAssessment,
		Payload: map[string]any{
			"project":           project,
			"toolchain_capable": toolchainCapable,
			"toolchain_variant": toolchainVariant,
			"kind":              string(f.Kind),
			"package":           f.Package,
			"module":            f.Module,
			"source":            f.Source,
			"line":              f.Line,
			"toolchain_raw":     f.ToolchainRaw,
			"category":          string(f.Category),
			"policy_outcome":    f.PolicyOutcome,
			"policy_blocking":   f.PolicyBlocking,
		},
	}
}
