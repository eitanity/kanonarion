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

// persistRecord writes record unless doing so would trade a stronger
// verification anchor for a weaker one, and returns the record that is now
// authoritative for the coordinate.
//
// A fact record is keyed on (module path, version, pipeline version) alone, so
// every re-measurement overwrites its predecessor in place — including one made
// in a mode that cannot reach the same anchor. The --from-modcache path tops out
// at VerifiedBySumDBOnly and records mode-locked "modcache:zip:<coord>" handles;
// letting it replace a network run's Verified record demoted the module's chain
// of custody and left behind a handle the default blob store cannot resolve.
//
// A refusal is not an error: the fetch succeeded, the measurement simply did not
// improve on what is stored. The existing record is returned as the fetch result
// and one WARN names both statuses and both acquisition modes, so a
// --from-modcache run over a network-verified store is visibly a no-op rather
// than a silent demotion. An equal-or-stronger measurement overwrites exactly as
// before, so a genuine re-verification and a status upgrade still land.
//
// The guard applies to forced runs too — see WithAllowVerificationDowngrade.
func (uc *FetchModuleUseCase) persistRecord(ctx context.Context, log *slog.Logger, req FetchRequest, record domain2.FactRecord) (domain2.FactRecord, error) {
	existing, ok, err := uc.facts.GetFetchRecord(ctx, record.Coordinate(), record.PipelineVersion)
	if err != nil {
		// Not readable means not decidable: overwriting here could demote a record
		// this run never saw, so the fetch fails rather than guessing.
		return domain2.FactRecord{}, fmt.Errorf("reading existing record before overwrite: %w", err)
	}

	// A full record replacing a go.mod-only one is an artefact upgrade, not a
	// demotion: the stored record described a version whose zip was never fetched,
	// and refusing the upgrade would leave every consumer that needs source
	// starved while the fetch reported success. The anchor comparison does not see
	// that dimension, so it is exempted here rather than folded into the ranking.
	addsArtefactCoverage := ok && existing.IsGoModOnly() && !record.IsGoModOnly()

	weakens := ok && !addsArtefactCoverage && domain2.ReplacementWeakensAnchor(existing, record)
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
			if aerr := uc.recordOverwriteEvent(audit.EventFactRecordWriteRefused, existing, record, req.Force); aerr != nil {
				return domain2.FactRecord{}, aerr
			}
			if uc.cachedArtefactsReadable(ctx, log, existing) {
				return existing, nil
			}
			// The kept record is the stronger fact, but this run cannot resolve its
			// artefacts — the very reason the cache check re-fetched. Handing it back
			// would return a handle the caller cannot read, trading one half of the fix
			// for the other. The store keeps the stronger fact; this run gets the
			// artefacts it just measured, unpersisted.
			log.InfoContext(ctx, "kept_record_unreadable_returning_measured_artefacts",
				slog.String("kept_content_location", existing.ContentLocation),
				slog.String("measured_content_location", record.ContentLocation),
			)
			return record, nil
		}
		log.LogAttrs(ctx, slog.LevelWarn, "record_downgraded_by_operator_request", attrs...)
		if aerr := uc.recordOverwriteEvent(audit.EventFactRecordDowngraded, existing, record, req.Force); aerr != nil {
			return domain2.FactRecord{}, aerr
		}
	}

	if err := uc.facts.PutFetchRecord(ctx, record); err != nil {
		return domain2.FactRecord{}, fmt.Errorf("persisting fact record: %w", err)
	}
	log.InfoContext(ctx, "record_persisted",
		slog.String("verification_status", record.VerificationStatus),
		slog.String("content_hash", record.ContentHash),
		slog.String("acquisition_mode", record.AcquisitionMode),
	)
	return record, nil
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
