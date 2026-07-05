// Package application orchestrates vendored-closure reconciliation: load via
// the scanner port, delegate finding aggregation to the domain, evaluate
// governance via the config policy, persist the record and emit an audit
// fact. It contains no filesystem access, no hashing and no reconciliation
// rules of its own.
package application

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/eitanity/kanonarion/internal/audit"
	configdomain "github.com/eitanity/kanonarion/internal/config/domain"
	fetchports "github.com/eitanity/kanonarion/internal/fetch/ports"
	"github.com/eitanity/kanonarion/internal/vendortree/domain"
	"github.com/eitanity/kanonarion/internal/vendortree/ports"
)

// Config wires the ExtractVendorUseCase dependencies.
type Config struct {
	Scanner   ports.VendorScanner
	Store     ports.VendorStore
	Audit     ports.AuditSink
	Clock     fetchports.Clock
	Stopwatch fetchports.Stopwatch
	Logger    *slog.Logger
}

// ExtractVendorUseCase reconciles, policy-evaluates and persists a project's
// vendored closure.
type ExtractVendorUseCase struct {
	scanner   ports.VendorScanner
	store     ports.VendorStore
	audit     ports.AuditSink
	clock     fetchports.Clock
	stopwatch fetchports.Stopwatch
	logger    *slog.Logger
}

// NewExtractVendorUseCase constructs the use case.
func NewExtractVendorUseCase(cfg Config) *ExtractVendorUseCase {
	return &ExtractVendorUseCase{
		scanner: cfg.Scanner, store: cfg.Store, audit: cfg.Audit,
		clock: cfg.Clock, stopwatch: cfg.Stopwatch, logger: cfg.Logger,
	}
}

// Extract scans the vendored project at goModPath, reconciles modules.txt /
// vendor/ / go.mod / go.sum into classified findings, evaluates each against
// policy, persists the record, and emits one audit event for the scan.
// ErrNotVendored is propagated unchanged so the caller can treat "no vendored
// tree" per the requested mode.
func (uc *ExtractVendorUseCase) Extract(
	ctx context.Context, goModPath string, vendorOnly bool, policy configdomain.VendorPolicy,
) (domain.Record, error) {
	lap := uc.stopwatch.Start()

	res, err := uc.scanner.ScanProject(goModPath, vendorOnly)
	if err != nil {
		return domain.Record{}, fmt.Errorf("scanning vendored project: %w", err)
	}

	mods, findings := domain.Aggregate(res)
	for i := range findings {
		f := &findings[i]
		outcome := policy.Evaluate(f.Kind.PolicyCategory())
		f.PolicyOutcome = string(outcome)
		f.PolicyBlocking = outcome == configdomain.PolicyOutcomeWarn
	}
	domain.SortModules(mods)
	domain.SortFindings(findings)

	rec := domain.Record{
		Ecosystem:         domain.EcosystemGo,
		ProjectModulePath: res.ProjectModulePath,
		VendorDir:         res.VendorDir,
		VendorOnly:        res.VendorOnly,
		Modules:           mods,
		Findings:          findings,
		OverallStatus:     domain.OverallStatus(findings),
		ExtractedAt:       uc.clock.Now().UTC(),
		SchemaVersion:     domain.VendorSchemaVersion,
		PipelineVersion:   domain.PipelineVersion,
	}
	rec.ContentHash = domain.Hash(mods, findings)

	if err := uc.store.PutVendorRecord(ctx, rec); err != nil {
		return domain.Record{}, fmt.Errorf("persisting vendor record: %w", err)
	}
	if err := uc.audit.RecordEvent(auditEvent(rec)); err != nil {
		return domain.Record{}, fmt.Errorf("recording vendor audit event: %w", err)
	}

	if uc.logger != nil {
		uc.logger.Debug("vendor scan complete",
			"project", res.ProjectModulePath,
			"modules", len(mods),
			"findings", len(findings),
			"vendor_only", res.VendorOnly,
			"elapsed", lap.Elapsed())
	}
	return rec, nil
}

// auditEvent builds the audit envelope for a vendored-closure scan.
// One event per scan records the reconciled posture; finding-level detail is
// in the persisted record. Re-scans appended over time make a tree's
// drift/inconsistency history first-class in the append-only log.
func auditEvent(r domain.Record) audit.Event {
	return audit.Event{
		Type: audit.EventVendorTreeGenerated,
		Payload: map[string]any{
			"project":       r.ProjectModulePath,
			"vendor_dir":    r.VendorDir,
			"vendor_only":   r.VendorOnly,
			"module_count":  len(r.Modules),
			"finding_count": len(r.Findings),
			"status":        r.OverallStatus,
			"content_hash":  r.ContentHash,
		},
	}
}
