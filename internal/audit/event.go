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

import (
	"fmt"
	"sort"
)

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

	// EventInterfaceExtracted records that a module's public API was extracted
	// and a generation persisted. Payload carries the module coordinate, the
	// artefact the extraction read, the pipeline version, the overall status, the
	// package count and the record's content hash.
	//
	// The interface record is what every API-compatibility answer — what a bump
	// removes, what a migration must rewrite — is derived from, so a generation
	// that later underpins such an answer is visible in the append-only log and
	// not only in the mutable interface ledger.
	EventInterfaceExtracted EventType = "interface_extracted"

	// EventExamplesExtracted records that a module's Example* functions were
	// harvested and a generation persisted. Payload carries the module
	// coordinate, the artefact the extraction read, the pipeline version, the
	// overall status, the example count and the record's content hash.
	//
	// Examples are evidence of how an API is meant to be called, quoted back in
	// adoption and migration answers; anchoring each extraction here means the
	// generation that supplied a quoted example is stated in the append-only log.
	EventExamplesExtracted EventType = "examples_extracted"

	// EventExtractionRunCompleted records that an extraction run over a walk
	// finished and its run record was persisted. Payload carries the run id, the
	// walk it ran over, the requested stages, the module count, the per-stage
	// outcome counts, the overall status and the run's content hash.
	//
	// The per-stage events say what each module produced; this one says which
	// campaign asked for them and what it concluded overall, so a reader can tell
	// a full pipeline run from a single-module re-extraction without inferring it
	// from the timestamps of the events around it.
	EventExtractionRunCompleted EventType = "extraction_run_completed"

	// EventStdlibCustodyRecorded records that a standard-library chain-of-custody
	// measurement was persisted. Payload carries the toolchain version, the route
	// the bytes were acquired by (the published go.dev/dl tarball or the local
	// toolchain's source tree), the verification anchors that acquisition
	// established, the bytes it was taken over and the measurement's content hash.
	//
	// It is named for the write, not for the verification: the event WITNESSES
	// that a custody record exists and by which route it was obtained, and the
	// record itself carries the claims. Custody is the one record whose whole
	// value is provable observation, so the observation being unwitnessed was the
	// sharpest form of the gap — an operator could see that the stdlib was
	// verified but not when, or by which run, that was established.
	EventStdlibCustodyRecorded EventType = "stdlib_custody_recorded"

	// EventSBOMGenerated records that an SBOM document was produced and its
	// record persisted. Payload carries the record id, the walk the document
	// describes, the format, the pipeline version, the document's content hash
	// and whether the document's creation timestamp was supplied by the caller.
	//
	// The SBOM is the artefact that leaves the building: it is handed to
	// customers, attached to releases and read by regulators. A document could be
	// produced and re-produced with no trace of when, from which walk, or how
	// often, so this anchors the production itself. It witnesses the write — the
	// document's own claims (its components, their licences, its completeness
	// statements) are the DOCUMENT's, reachable through the content hash, and
	// restating them here would make the log a second unsealed copy.
	EventSBOMGenerated EventType = "sbom_generated"

	// EventSBOMServed records that a stored SBOM record was served to a caller
	// instead of being generated afresh. Payload carries the record served (id,
	// walk, format, pipeline version, content hash) and the identity that
	// requested this serving.
	//
	// A served answer is an observation: "when did we last produce this artefact,
	// and how often has it gone out" stays answerable only if a re-serve is
	// visible. It is deliberately distinct from sbom_generated — a reader must be
	// able to tell a document that was produced from one that was handed over
	// again — and the requester is the serving's own, not the record's operator,
	// which named whoever asked for the original generation.
	EventSBOMServed EventType = "sbom_served"

	// EventAdvisorySnapshotRecorded records that an advisory database snapshot
	// was persisted. Payload carries the database the snapshot came from, that
	// database's own generation of itself, when it was retrieved, the content
	// identity of the persisted bytes and the route that acquired it.
	//
	// "What did we know and when" turns exactly on when a snapshot arrived, and
	// the arrival was the one remaining silent write. It witnesses the persist
	// and its route: it states nothing about the advisories the snapshot holds,
	// how many there are, or any module's standing — those are questions for the
	// snapshot, which the content identity reaches. A scan that reuses a stored
	// snapshot appends nothing, because reuse is not an acquisition.
	EventAdvisorySnapshotRecorded EventType = "advisory_snapshot_recorded"

	// EventVulnScanServed records that a stored walk scan run was served to a
	// caller instead of being measured again. Payload names the run served, the
	// walk identity it answered for, the advisory database that run was judged
	// against, and the surface that asked.
	//
	// It is named for the act, not for the run: nothing was scanned, so what the
	// event witnesses is an ASKING. Without it reuse is invisible — record and
	// ledger timestamps then track only when evidence was DERIVED, and an
	// unchanged store answers from existing rows indefinitely with no observation
	// trace, so "when did we last check" becomes unrecoverable while "when did we
	// first learn" stays answerable from the derivation events. Those are two
	// different questions, and this event is what makes the second one askable.
	//
	// It restates none of the run's conclusions: the findings, the per-module
	// statuses and the coverage are the RUN's, reachable through the scan id.
	// Copying them here would make the log an unsealed second summary of a run
	// the store already holds sealed, and one that would go stale silently.
	EventVulnScanServed EventType = "vuln_scan_served"
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
	EventInterfaceExtracted:       {},
	EventExamplesExtracted:        {},
	EventExtractionRunCompleted:   {},
	EventStdlibCustodyRecorded:    {},
	EventSBOMGenerated:            {},
	EventSBOMServed:               {},
	EventAdvisorySnapshotRecorded: {},
	EventVulnScanServed:           {},
}

// KnownEventTypes returns the recognised discriminators, sorted.
//
// It reads the same map Known() does, which is the gate every emitter passes
// through: Event.Validate refuses an envelope whose type is not in it, so a
// type that can be emitted is a type this function names. A reader that
// enumerates the vocabulary — the ledger command's --event-type help and its
// refusal of an unrecognised value — therefore cannot fall behind the emitters
// the way a second, hand-written list would.
func KnownEventTypes() []EventType {
	out := make([]EventType, 0, len(knownEventTypes))
	for t := range knownEventTypes {
		out = append(out, t)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
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
