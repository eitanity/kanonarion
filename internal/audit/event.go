// Package audit defines the context-neutral audit-event vocabulary.
//
// The audit log is an append-only JSONL assurance artefact. Historically it
// recorded exactly one kind of fact (a stored fact-record write). The
// supply-chain gaps introduce several further event types.
// Doing that as four ad-hoc struct changes would be a mistake: this package
// makes event-type extension *cheap* by fixing one envelope shape
// a discriminator plus a free-form payload — so a new event type is a new
// constant, never a schema migration.
//
// This package is pure (no I/O): emitters across bounded contexts depend on
// the vocabulary here, never on the JSONL adapter that persists it.
package audit

import "fmt"

// EventType is the discriminator stored as the `event_type` field of every
// audit envelope. Adding a value here is the *entire* cost of introducing a
// new audit event — there is no on-disk schema to migrate.
type EventType string

const (
	// EventFactRecordWritten records that a verified module fact-record was
	// persisted. This is the original (and, before, only) event; its
	// envelope keeps the historical flat field layout for back-compatibility,
	// with `event_type` added purely additively.
	EventFactRecordWritten EventType = "fact_record_written"

	// EventFactRecordWriteRefused records that a re-measurement was refused
	// because it would have replaced a stronger verification anchor with a weaker
	// one. The existing record is kept and returned as the fetch result. The
	// payload names both statuses, both acquisition modes and whether the run was
	// forced, so a demotion attempt is reconstructable from the log alone —
	// previously a demotion appeared only as a second fact_record_written entry
	// with no indication of what it displaced or how the run was invoked.
	EventFactRecordWriteRefused EventType = "fact_record_write_refused"

	// EventFactRecordDowngraded records that a weaker re-measurement replaced a
	// stronger record because the operator explicitly permitted it. It is the
	// only path by which a verification anchor can now weaken, and it carries the
	// same payload as EventFactRecordWriteRefused so the two read as one series.
	EventFactRecordDowngraded EventType = "fact_record_downgraded"

	// EventReplaceDirectiveObserved records a go.mod/go.work `replace`
	// directive together with its risk classification (wired by).
	EventReplaceDirectiveObserved EventType = "replace_directive_observed"

	// EventExcludeDirectiveObserved records a go.mod `exclude` directive
	// together with its risk classification (wired by).
	EventExcludeDirectiveObserved EventType = "exclude_directive_observed"

	// EventGoDebugSettingObserved records a GODEBUG / //go:debug setting and
	// its versioned taxonomy classification (wired by).
	EventGoDebugSettingObserved EventType = "godebug_setting_observed"

	// EventVendorTreeGenerated records a vendored-closure scan / vendor-tree
	// generation (wired by).
	EventVendorTreeGenerated EventType = "vendor_tree_generated"

	// EventFIPSAssessment records a FIPS toolchain / algorithm assessment
	// (wired by).
	EventFIPSAssessment EventType = "fips_assessment"

	// EventVerificationFailed records that the read/serve path rejected a
	// record: a record that was not positively verified against a trust anchor
	// (self-hash integrity on read, or sumdb/VCS cross-verification on serve).
	// This is the single highest-value security event — a tampered or
	// mismatched blob being refused — which was previously invisible in the
	// append-only log. The payload carries the exact verification status so a
	// reader distinguishes a hard mismatch from an un-analysed/unknown outcome.
	EventVerificationFailed EventType = "verification_failed"

	// EventRecordReadVerified records a successful verified read/serve: a
	// record that passed the read/serve verification path and was presented to
	// the consumer. Emitting it lets the log show what was actually served, not
	// only what was written.
	EventRecordReadVerified EventType = "record_read_verified"

	// EventVulnScanCompleted records that a walk-wide vulnerability scan run
	// finished. Payload carries the walk id, scan-run id, snapshot identity and
	// the overall module counts (affected/clean/unscannable/failed). It anchors
	// "we scanned this dependency set against this database on this date" in the
	// tamper-resistant log, not only in the mutable vuln DB.
	EventVulnScanCompleted EventType = "vuln_scan_completed"

	// EventVulnFindingObserved records a single vulnerability finding surfaced by
	// a scan. Payload carries the module coordinate, the vulnerability id and the
	// module's overall status. One event per finding makes "when did we first
	// learn module X was affected by CVE-Y" answerable from the append-only log.
	EventVulnFindingObserved EventType = "vuln_finding_observed"

	// EventLicenseExtracted records that a module's licence facts were extracted
	// and persisted. Payload carries the module coordinate, the resolved primary
	// SPDX, the overall status (Detected / Unclassified / None / …) and the
	// source of the identity (the scanner). Licence extraction is half of the
	// compliance verdict; anchoring each extraction here means a licence that
	// later drives a compliance decision is visible in the append-only log, not
	// only in the mutable licence record.
	EventLicenseExtracted EventType = "license_extracted"

	// EventWalkCompleted records that a dependency-graph walk finished
	// successfully. Payload carries the walk id, root coordinate, scope, node
	// count and content hash. The walk record defines the audited population
	// everything else is scoped from; anchoring each completed walk here means
	// the input that bounds every downstream verdict leaves a tamper-resistant
	// trail of when it was resolved and what it contained, not only a mutable
	// walk record.
	EventWalkCompleted EventType = "walk_completed"

	// EventCallGraphExtracted records that a module's call graph was analysed and
	// a generation persisted. Payload carries the module coordinate, what the
	// analysis read (a fetched artefact or a working tree), the pipeline version,
	// the completeness level, the overall status and the record's content hash.
	//
	// Call graph extraction is what every reachability and capability answer is
	// derived from, and the ledger is append-only, so a generation that later
	// underpins such an answer is visible here and not only in the mutable
	// callgraph ledger. It also restores the stream's use as a tripwire: a store
	// write that appended nothing let a stable line count read as "nothing ran".
	EventCallGraphExtracted EventType = "callgraph_extracted"
)

// knownEventTypes is the closed set of recognised discriminators. A gap
// ticket extends the vocabulary by adding a constant above and an entry here;
// nothing else changes.
var knownEventTypes = map[EventType]struct{}{
	EventFactRecordWritten:        {},
	EventFactRecordWriteRefused:   {},
	EventFactRecordDowngraded:     {},
	EventReplaceDirectiveObserved: {},
	EventExcludeDirectiveObserved: {},
	EventGoDebugSettingObserved:   {},
	EventVendorTreeGenerated:      {},
	EventFIPSAssessment:           {},
	EventVerificationFailed:       {},
	EventRecordReadVerified:       {},
	EventVulnScanCompleted:        {},
	EventVulnFindingObserved:      {},
	EventLicenseExtracted:         {},
	EventWalkCompleted:            {},
	EventCallGraphExtracted:       {},
}

// Known reports whether t is a recognised event type.
func (t EventType) Known() bool {
	_, ok := knownEventTypes[t]
	return ok
}

// Event is a generic, future-proof audit envelope. Timestamp is set by the
// persisting adapter (it owns the clock); Type is the discriminator; Payload
// carries the event-specific body that gap tickets populate without touching
// this package or any storage schema.
type Event struct {
	Type    EventType
	Payload map[string]any
}

// Validate enforces the only invariant the envelope itself owns: the
// discriminator must be a recognised event type. Payload shape is the
// concern of the emitting context, not of the envelope.
func (e Event) Validate() error {
	if !e.Type.Known() {
		return fmt.Errorf("unknown audit event type %q", e.Type)
	}
	return nil
}
