package application

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/eitanity/kanonarion/internal/audit"
	domain2 "github.com/eitanity/kanonarion/internal/fetch/domain"
	"github.com/eitanity/kanonarion/internal/fetch/ports"
)

// WithAudit wires an assurance-log sink so the write side emits an event when a
// re-measurement is refused for weakening a record's verification anchor, and
// when an operator explicitly permits such a weakening. A nil sink (the default)
// emits nothing and changes no behaviour. Returns uc for chaining.
func (uc *FetchModuleUseCase) WithAudit(sink ports.AuditSink) *FetchModuleUseCase {
	uc.audit = sink
	return uc
}

// WithAllowVerificationDowngrade permits a weaker re-measurement to replace a
// stronger stored record. It is deliberately NOT --force: forcing means
// "re-measure this module now", not "permit a weaker anchor to replace a
// stronger fact", and conflating the two is what let a --from-modcache run
// silently demote records a network run had anchored to the transparency log.
// The default (false) keeps the stronger record. Returns uc for chaining.
func (uc *FetchModuleUseCase) WithAllowVerificationDowngrade(allow bool) *FetchModuleUseCase {
	uc.allowVerificationDowngrade = allow
	return uc
}

// persistRecord seals a measurement and appends it to the ledger, returning the
// composed view of the artefact afterwards.
//
// It appends. Nothing is overwritten and nothing is deduplicated: the ledger key
// carries the artefact hash and the time of measurement, so every measurement
// that passes is its own row and its predecessors survive to be composed with
// it. That is the whole point — an overwriting store destroyed the evidence an
// investigation into a verification demotion needed, and could not corroborate
// its own audit log.
//
// Before sealing, a validation leg this measurement did not perform is inherited
// from an earlier measurement of the same artefact, naming the record it came
// from. A --skip-vcs run records no VCS leg at all; a later --force performs the
// check; a later --skip-vcs --force transfers the earlier result forward rather
// than discarding evidence the store already holds.
//
// The verification-strength guard is retained unchanged. It is no longer load
// bearing — a weaker measurement can no longer destroy a stronger one, because
// nothing is destroyed — but retiring it is a deliberate follow-up so this
// change does one thing.
func (uc *FetchModuleUseCase) persistRecord(ctx context.Context, log *slog.Logger, req FetchRequest, m domain2.FetchedModule) (domain2.CompositeRecord, error) {
	existing, ok, err := uc.facts.GetFetchRecord(ctx, m.Coordinate, m.PipelineVersion)
	if err != nil {
		// Not readable means not decidable, and a bad run writes nothing: a store
		// that cannot be read may hold a tamper or a divergence, and appending on
		// top of it would add a measurement to evidence nobody has checked.
		return domain2.CompositeRecord{}, fmt.Errorf("reading existing records before append: %w", err)
	}

	m, err = uc.inheritLegs(ctx, log, m)
	if err != nil {
		return domain2.CompositeRecord{}, err
	}

	sealed, err := domain2.Seal(m)
	if err != nil {
		return domain2.CompositeRecord{}, fmt.Errorf("sealing measurement of %s: %w", m.Coordinate, err)
	}
	record := sealed.Record()

	// A full record following a go.mod-only one is an artefact upgrade, not a
	// demotion: the stored record described a version whose zip was never fetched,
	// and refusing the upgrade would leave every consumer that needs source
	// starved while the fetch reported success. The anchor comparison does not see
	// that dimension, so it is exempted here rather than folded into the ranking.
	addsArtefactCoverage := ok && existing.IsGoModOnly() && !record.IsGoModOnly()

	weakens := ok && !addsArtefactCoverage && domain2.ReplacementWeakensAnchor(existing.FactRecord, record)
	if weakens {
		attrs := []slog.Attr{
			slog.String("existing_verification_status", existing.VerificationStatus),
			slog.String("incoming_verification_status", record.VerificationStatus),
			slog.String("existing_acquisition_mode", modeOrUnrecorded(existing.AcquisitionMode)),
			slog.String("incoming_acquisition_mode", modeOrUnrecorded(record.AcquisitionMode)),
			slog.Bool("force", req.Force),
		}
		if !uc.allowVerificationDowngrade {
			log.LogAttrs(ctx, slog.LevelWarn, "record_write_refused_weaker_verification", attrs...)
			if aerr := uc.recordOverwriteEvent(audit.EventFactRecordWriteRefused, existing.FactRecord, record, req.Force); aerr != nil {
				return domain2.CompositeRecord{}, aerr
			}
			if uc.cachedArtefactsReadable(ctx, log, existing.FactRecord) {
				return existing, nil
			}
			// The composed record is the stronger fact, but this run cannot resolve
			// its artefacts — the very reason the cache check re-fetched. Handing it
			// back would return an address the caller cannot read, trading one half
			// of the fix for the other. The store keeps the stronger fact; this run
			// gets the artefacts it just measured, unpersisted.
			log.InfoContext(ctx, "kept_record_unreadable_returning_measured_artefacts",
				slog.String("kept_content_location", existing.ContentLocation),
				slog.String("measured_content_location", record.ContentLocation),
			)
			measured, cerr := domain2.Compose([]domain2.FactRecord{record})
			if cerr != nil {
				return domain2.CompositeRecord{}, fmt.Errorf("composing the unpersisted measurement of %s: %w", m.Coordinate, cerr)
			}
			return measured, nil
		}
		log.LogAttrs(ctx, slog.LevelWarn, "record_downgraded_by_operator_request", attrs...)
		if aerr := uc.recordOverwriteEvent(audit.EventFactRecordDowngraded, existing.FactRecord, record, req.Force); aerr != nil {
			return domain2.CompositeRecord{}, aerr
		}
	}

	if err := uc.facts.PutFetchRecord(ctx, sealed); err != nil {
		return domain2.CompositeRecord{}, fmt.Errorf("appending fact record: %w", err)
	}
	log.InfoContext(ctx, "record_appended",
		slog.String("verification_status", record.VerificationStatus),
		slog.String("content_hash", record.ContentHash),
		slog.String("acquisition_mode", record.AcquisitionMode),
		slog.String("measurement_kind", record.MeasurementKind),
	)

	// Re-read so the caller receives the artefact as the ledger now knows it —
	// including the measurement just appended, and including a first-seen date
	// that predates this run when the artefact was already held.
	composed, found, err := uc.facts.GetFetchRecord(ctx, m.Coordinate, m.PipelineVersion)
	if err != nil {
		return domain2.CompositeRecord{}, fmt.Errorf("composing records after append: %w", err)
	}
	if !found {
		// The row was appended a moment ago; its absence means the store is not
		// answering for what it was just told, which is not something to paper over.
		return domain2.CompositeRecord{}, fmt.Errorf("appended fact record for %s is absent from the store", m.Coordinate)
	}
	return composed, nil
}

// inheritLegs transfers a validation leg this measurement did not perform from
// an earlier measurement of the same artefact, marking it inherited and naming
// the record it came from.
//
// The name is what makes the copy falsifiable. Without it, "inherited" is an
// unfalsifiable claim sitting on a tamper-evident record, and a reader cannot
// tell evidence carried forward from evidence that was never established at all.
//
// Inheritance must not launder evidence, so the source record is verified before
// anything is taken from it. The store's list read rehydrates every row it
// returns and fails closed, so a bad source aborts the run rather than being
// quietly skipped in favour of an older one.
//
// A store that does not offer the list capability simply inherits nothing: the
// legs this run performed are recorded, the ones it did not are absent, and
// absence is an honest answer.
func (uc *FetchModuleUseCase) inheritLegs(ctx context.Context, log *slog.Logger, m domain2.FetchedModule) (domain2.FetchedModule, error) {
	if m.SumDBCheck != domain2.LegAbsent && m.VCSCheck != domain2.LegAbsent {
		return m, nil
	}
	lister, ok := uc.facts.(ports.FactRecordLister)
	if !ok {
		return m, nil
	}
	prior, err := lister.ListFetchRecords(ctx, m.Coordinate, m.PipelineVersion)
	if err != nil {
		return domain2.FetchedModule{}, fmt.Errorf("reading earlier measurements to inherit validation legs: %w", err)
	}

	identity := domain2.ArtefactIdentityOfMeasurement(m)

	// Latest first: the most recent establishment of a leg is the one worth
	// carrying forward.
	for i := len(prior) - 1; i >= 0; i-- {
		r := prior[i]
		priorIdentity, ierr := domain2.ArtefactIdentityOf(r)
		if ierr != nil {
			return domain2.FetchedModule{}, fmt.Errorf("reading the identity of an earlier measurement of %s: %w", m.Coordinate, ierr)
		}
		if !priorIdentity.Equal(identity) {
			continue
		}
		if m.SumDBCheck == domain2.LegAbsent && r.SumDBCheck != string(domain2.LegAbsent) {
			m.SumDBCheck = domain2.LegInherited
			m.SumDBCheckSource = r.ContentHash
			log.InfoContext(ctx, "validation_leg_inherited",
				slog.String("leg", string(domain2.LegSumDB)),
				slog.String("source_content_hash", r.ContentHash),
			)
		}
		if m.VCSCheck == domain2.LegAbsent && r.VCSCheck != string(domain2.LegAbsent) {
			m.VCSCheck = domain2.LegInherited
			m.VCSCheckSource = r.ContentHash
			log.InfoContext(ctx, "validation_leg_inherited",
				slog.String("leg", string(domain2.LegVCS)),
				slog.String("source_content_hash", r.ContentHash),
			)
		}
		if m.SumDBCheck != domain2.LegAbsent && m.VCSCheck != domain2.LegAbsent {
			break
		}
	}
	return m, nil
}

// recordOverwriteEvent appends the assurance-log entry for a refused or
// operator-permitted weakening. A nil sink is a no-op; an emit failure is
// returned rather than swallowed, so the one event that explains why a stored
// record did (or did not) change is never lost silently.
func (uc *FetchModuleUseCase) recordOverwriteEvent(t audit.EventType, existing, incoming domain2.FactRecord, force bool) error {
	if uc.audit == nil {
		return nil
	}
	e := audit.Event{Type: t, Payload: map[string]any{
		"module":                       incoming.ModulePath,
		"version":                      incoming.ModuleVersion,
		"pipeline_version":             incoming.PipelineVersion,
		"existing_verification_status": existing.VerificationStatus,
		"incoming_verification_status": incoming.VerificationStatus,
		"existing_acquisition_mode":    modeOrUnrecorded(existing.AcquisitionMode),
		"incoming_acquisition_mode":    modeOrUnrecorded(incoming.AcquisitionMode),
		"existing_content_hash":        existing.ContentHash,
		"incoming_content_hash":        incoming.ContentHash,
		"force":                        force,
	}}
	if err := uc.audit.RecordEvent(e); err != nil {
		return fmt.Errorf("recording %s audit event for %s: %w", t, incoming.Coordinate(), err)
	}
	return nil
}

// modeOrUnrecorded renders an acquisition mode for a log line, naming the empty
// value rather than emitting a blank field: a record written before the mode was
// persisted is "unrecorded", which is a different claim from any of the three
// modes and must read as one.
func modeOrUnrecorded(mode string) string {
	if mode == "" {
		return "unrecorded"
	}
	return mode
}
