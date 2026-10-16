package domain

import (
	"errors"
	"fmt"
	"sort"

	"github.com/eitanity/kanonarion/internal/coordinate"
	"github.com/eitanity/kanonarion/internal/gotoolchain"
)

// ErrNoRecordsToCompose is returned by Compose when handed no records. It is a
// programming error rather than an absence: absence is reported by the store as
// "not found", and composing nothing has no meaningful answer.
var ErrNoRecordsToCompose = errors.New("no vulnerability records to compose")

// Compose returns the record a reader gets for one coordinate, given every
// record the ledger holds for it, without naming an analysis frame.
//
// Records must each have verified their own content hash before reaching here:
// a record that cannot be checked stops the read, so composition never has to
// decide what to do about an unverifiable row.
//
// Composition PICKS a stored record; it never merges two. A merged record would
// carry a content hash describing neither of the measurements it was built
// from, and the hash is the whole evidence chain. So the answer to "advisory
// known since snapshot X, reachability last established at completeness Y" is a
// record that states its own snapshot, completeness and frame — the served
// record names its provenance rather than having it summarised away — plus the
// ledger, which still holds every generation for a reader that wants the rest.
//
// A caller that has a frame in mind must use ComposeAt instead. Its one
// production caller composes the generations a single scan run reached, which
// share that run's frame. The served record still states the frame it was
// reached in, so an answer is never laundered into an answer to the other
// question; what is forbidden — carrying a reachability finding across a rooting
// boundary — is a merge, and this does not merge.
func Compose(records []VulnerabilityRecord) (VulnerabilityRecord, error) {
	if len(records) == 0 {
		return VulnerabilityRecord{}, ErrNoRecordsToCompose
	}
	if c := findToolchainConflict(records); c != nil {
		return VulnerabilityRecord{}, *c
	}
	return best(records), nil
}

// best returns the record the ladder serves first. It is separate from Compose
// so a caller that has already established the group is non-empty does not have
// to handle an error it has just ruled out.
func best(records []VulnerabilityRecord) VulnerabilityRecord {
	ordered := make([]VulnerabilityRecord, len(records))
	copy(ordered, records)
	sort.SliceStable(ordered, func(i, j int) bool { return servesBefore(ordered[i], ordered[j]) })
	return ordered[0]
}

// ComposeAt returns the record a reader gets for one coordinate within one
// analysis frame. ok is false when the ledger holds nothing in that frame — a
// caller asking about an isolated analysis is never handed a target-rooted
// record, because the two answer different questions and a scan that reused the
// wrong one would attribute a reachability finding to a build it was never
// computed against.
//
// Records written before the frame was recorded are the one exception, and it is
// deliberately narrow: they are considered only when NO record in the group
// states a frame at all. A store that has not been re-scanned since the field
// landed therefore still answers as it always did, while a coordinate that has
// been measured in a stated frame stops matching against rows that cannot say
// which question they answer.
func ComposeAt(records []VulnerabilityRecord, rooting Rooting) (VulnerabilityRecord, bool, error) {
	candidates := atRooting(records, rooting)
	if len(candidates) == 0 {
		return VulnerabilityRecord{}, false, nil
	}
	// The frame is selected first and the toolchain checked within it: two
	// toolchains that scanned one frame are two verdicts about two builds.
	if c := findToolchainConflict(candidates); c != nil {
		return VulnerabilityRecord{}, false, *c
	}
	// best rather than Compose: the only error Compose has is an empty group, and
	// the line above has just ruled it out. The error stays in the signature —
	// the store's read paths branch on it — but it is one this function no longer
	// has a way to produce, and the guard that pretended otherwise was dead code
	// no test could reach.
	return best(candidates), true, nil
}

// ComposeForIndex returns the record the findings index of one frame describes.
// It is ComposeAt, except on a toolchain conflict: then the index describes the
// generations scanned under the toolchain of the frame's newest record. A Go
// upgrade puts two toolchains in one frame, and the newest is the build a
// walk-anchored read answers for; the unpinned read still refuses. Every other
// refusal stands, and the store's writer and its index verifier both use this.
func ComposeForIndex(records []VulnerabilityRecord, rooting Rooting) (VulnerabilityRecord, bool, error) {
	rec, ok, err := ComposeAt(records, rooting)
	var conflict ToolchainConflict
	if err == nil || !errors.As(err, &conflict) {
		return rec, ok, err
	}
	toolchain := newestToolchain(atRooting(records, rooting))
	current := make([]VulnerabilityRecord, 0, len(records))
	for _, r := range records {
		// A record stating no toolchain was not scanned under this one, so it is
		// not part of this toolchain's answer.
		if r.Toolchain == toolchain {
			current = append(current, r)
		}
	}
	return ComposeAt(current, rooting)
}

// newestToolchain is the toolchain named by the newest record that names one;
// a conflict guarantees there is such a record.
func newestToolchain(records []VulnerabilityRecord) gotoolchain.Version {
	var (
		newest VulnerabilityRecord
		found  bool
	)
	for _, r := range records {
		if r.Toolchain != "" && (!found || newerScan(r, newest)) {
			newest, found = r, true
		}
	}
	return newest.Toolchain
}

// ComposeInFrame picks the record answering for one frame out of a walk's
// candidate set, together with the isolated-frame record it declined to answer
// from. found is false when the candidates hold nothing this frame's question
// can be answered from.
//
// The isolated frame is the one legitimate fallback: it answers "does the module,
// built alone, reach the advisory", which belongs to no project. Another
// consumer's target-rooted record answers about a build the caller did not ask
// about and is never served. A conflict in the frame that answers is returned;
// a conflict among isolated records offered only as the aside drops the aside.
//
// It is the selection every walk-anchored read makes — vuln-show and
// reachability under --walk-id/--gomod, the batch reports and the local probe's
// seed — so the surfaces cannot answer one walk differently.
func ComposeInFrame(recs []VulnerabilityRecord, rooting Rooting) (rec, isolated VulnerabilityRecord, hasIsolated, found bool, _ error) {
	if len(recs) == 0 {
		return VulnerabilityRecord{}, VulnerabilityRecord{}, false, false, nil
	}
	rec, found, err := ComposeAt(recs, rooting)
	if err != nil {
		return VulnerabilityRecord{}, VulnerabilityRecord{}, false, false, fmt.Errorf("composing vulnerability record in frame %s: %w", rooting, err)
	}
	if !found {
		var ierr error
		isolated, hasIsolated, ierr = ComposeAt(isolatedOnly(recs), RootingIsolated)
		if ierr != nil {
			return VulnerabilityRecord{}, VulnerabilityRecord{}, false, false, fmt.Errorf("composing the isolated-frame record: %w", ierr)
		}
		// Served as the answer, not as an aside: the record states its frame.
		return isolated, VulnerabilityRecord{}, false, hasIsolated, nil
	}
	if RecordRooting(rec) == RootingIsolated {
		// An aside drawn from the frame that produced the answer is the same
		// record printed twice.
		return rec, VulnerabilityRecord{}, false, true, nil
	}
	isolated, hasIsolated, ierr := ComposeAt(isolatedOnly(recs), RootingIsolated)
	if ierr != nil {
		isolated, hasIsolated = VulnerabilityRecord{}, false
	}
	return rec, isolated, hasIsolated, true, nil
}

// isolatedOnly narrows a candidate set to the records that state the isolated
// frame. A bare ComposeAt over the whole set would fall back to every record
// when none states a frame, and label one that never claimed isolation as such.
func isolatedOnly(recs []VulnerabilityRecord) []VulnerabilityRecord {
	out := make([]VulnerabilityRecord, 0, len(recs))
	for _, r := range recs {
		if RecordRooting(r) == RootingIsolated {
			out = append(out, r)
		}
	}
	return out
}

// ComposeForConsumer returns the record that answers a CONSUMER's question about
// coord — "is this advisory reachable in a build that consumes the module" —
// together with the isolated-frame record it declined to answer from, if the
// ledger holds one.
//
// It exists because the ladder in servesBefore ranks records that answer
// different questions against each other, and the rung that decides is
// call-graph completeness. An isolated scan builds the module alone, so it
// records BUILT_WITH_BODIES; a govulncheck analysis rooted at the consuming
// project records no completeness at all, because the call graph it searched was
// not one this tool built. Every target-rooted record therefore sits on the
// bottom completeness rung and every isolated one on the top, and the isolated
// answer wins on that rung no matter how much older it is. Measured on a real
// store, an isolated "NOT reachable" from 17:49 was served over two
// target-rooted records from 17:52 and 17:54 that carried the consumer's route
// to the vulnerable symbol.
//
// The rule here is not a new rung. Rooting stays a dimension: this picks the
// frame FIRST and lets the ladder decide only within it. A record rooted at a
// consumer answers the consumer's question; an isolated record answers a
// different one and is returned as an aside so a caller can report it, labelled,
// rather than as the answer.
//
// A record rooted at coord ITSELF is not a consumer frame — the module is its
// own root, so there is no consumer above it for a route to start from — and it
// is neither the answer nor the aside.
//
// When the ledger holds no consumer-rooted record at all the question cannot be
// answered in its own frame, so the whole group competes exactly as Compose
// would rank it and no aside is returned: nothing was declined.
func ComposeForConsumer(records []VulnerabilityRecord, coord coordinate.ModuleCoordinate) (VulnerabilityRecord, VulnerabilityRecord, bool, error) {
	if len(records) == 0 {
		return VulnerabilityRecord{}, VulnerabilityRecord{}, false, ErrNoRecordsToCompose
	}
	consumer := make([]VulnerabilityRecord, 0, len(records))
	isolated := make([]VulnerabilityRecord, 0, len(records))
	for _, r := range records {
		switch rooting := RecordRooting(r); {
		case rooting.IsTargetRooted() && !rooting.IsRootedAt(coord):
			consumer = append(consumer, r)
		case rooting == RootingIsolated:
			isolated = append(isolated, r)
		}
	}
	if len(consumer) == 0 {
		if c := findToolchainConflict(records); c != nil {
			return VulnerabilityRecord{}, VulnerabilityRecord{}, false, *c
		}
		return best(records), VulnerabilityRecord{}, false, nil
	}
	// Checked within the consumer frame, which is the group that answers. The
	// isolated aside is reported alongside rather than competing, so it is not
	// part of the question two toolchains could disagree about.
	if c := findToolchainConflict(consumer); c != nil {
		return VulnerabilityRecord{}, VulnerabilityRecord{}, false, *c
	}
	if len(isolated) == 0 {
		return best(consumer), VulnerabilityRecord{}, false, nil
	}
	return best(consumer), best(isolated), true, nil
}

// ComposeForTree returns the record that may seed a probe of the working tree
// whose go.mod declares modulePath, and ok is false when the ledger holds none
// it may be seeded from.
//
// The frame of a probe is the tree itself, which is not a walk and has no walk
// id to pin against, so the tree's own module path is the anchor. Two kinds of
// record answer for it:
//
//   - a record rooted at this module path, at whatever version the walk that
//     produced it assigned the root. That IS the tree's own build, measured
//     earlier.
//   - an isolated record, which answers "does the module, built alone, reach the
//     advisory" — a question with no consumer in it, so it belongs to no project
//     and misattributes nothing. It is the same fallback the anchored read paths
//     take, and it is the one that carries most stores: a walk scans its
//     dependencies through an isolated per-module pool.
//
// Another consumer's target-rooted record is never returned. It answers a
// question about a build the probe was not asked about, and seeding a fresh
// probe of THIS tree with it carries that build's reachability judgments into an
// answer about this one.
//
// Records that state no frame at all are considered only when NO record in the
// group states one, on the same narrow terms as ComposeAt: a store not re-scanned
// since the frame was recorded still seeds, while a coordinate that HAS been
// measured in a stated frame stops matching against rows that cannot say which
// question they answer.
func ComposeForTree(records []VulnerabilityRecord, modulePath string) (VulnerabilityRecord, bool, error) {
	if len(records) == 0 {
		return VulnerabilityRecord{}, false, ErrNoRecordsToCompose
	}
	own := make([]VulnerabilityRecord, 0, len(records))
	isolated := make([]VulnerabilityRecord, 0, len(records))
	anyStated := false
	for _, r := range records {
		rooting := RecordRooting(r)
		if rooting.IsRecorded() {
			anyStated = true
		}
		switch {
		case rooting.IsRootedAtPath(modulePath):
			own = append(own, r)
		case rooting == RootingIsolated:
			isolated = append(isolated, r)
		}
	}
	for _, group := range [][]VulnerabilityRecord{own, isolated} {
		if len(group) == 0 {
			continue
		}
		if c := findToolchainConflict(group); c != nil {
			return VulnerabilityRecord{}, false, *c
		}
		return best(group), true, nil
	}
	if !anyStated {
		if c := findToolchainConflict(records); c != nil {
			return VulnerabilityRecord{}, false, *c
		}
		return best(records), true, nil
	}
	return VulnerabilityRecord{}, false, nil
}

// atRooting narrows records to the requested frame, falling back to the whole
// group only when no record in it states a frame.
func atRooting(records []VulnerabilityRecord, rooting Rooting) []VulnerabilityRecord {
	matched := make([]VulnerabilityRecord, 0, len(records))
	anyStated := false
	for _, r := range records {
		if RecordRooting(r).IsRecorded() {
			anyStated = true
		}
		if RecordRooting(r) == rooting {
			matched = append(matched, r)
		}
	}
	if !anyStated {
		// Nothing in this group can say which question it answers, so narrowing
		// on the frame would report "never measured in this frame" for a store
		// whose every record predates the field. The records compete as they did
		// before the frame existed.
		return records
	}
	return matched
}

// servesBefore orders two records by which should be served first.
//
// The ladder, in order, and each rung is a rule about authority rather than
// about time:
//
//  1. A record reporting a matched advisory outranks one that does not. A
//     finding does not decay into an all-clear because a later scan ran; a
//     transition out of a finding needs a stated reason, and the findings axis
//     carries the one reason there is — Withdrawn, which reports the retraction
//     and stays in this tier so the record holding the reason is the one served.
//  2. Among records reporting nothing, an analysed one outranks a coverage gap.
//     Evidence of absence beats absence of evidence; ranking them together let a
//     failed scan answer a security question purely on being newer.
//  3. The higher call-graph completeness wins. This is the rung that stops a
//     newer, weaker measurement from displacing better-founded evidence: a scan
//     against a newer advisory database backed by a metadata-only graph is
//     better at "does an advisory exist" and worse at "is it reachable in what
//     we ship", and serving it unconditionally would replace an established
//     not-reachable finding with an unresolved one and call that an update.
//     Rung 1 is what keeps the other half honest — a genuinely new advisory
//     makes the newer record report a finding, and rung 1 serves it before this
//     rung is ever consulted.
//  4. The newer advisory-database snapshot wins. That axis is monotone: a later
//     database knows about strictly more advisories.
//  5. The newer scan wins, and finally the content hash decides. The hash is not
//     authority and is not claimed to be — it is here so the served record does
//     not depend on the order rows happen to come back in.
//
// Rooting is deliberately absent from the ladder. It is a dimension, and
// laddering it would silently discard the answer to one of the two questions;
// ComposeAt is where a caller says which one it is asking.
func servesBefore(a, b VulnerabilityRecord) bool {
	coverageA, findingsA := RecordAxes(a)
	coverageB, findingsB := RecordAxes(b)

	if ra, rb := reportsAdvisory(findingsA), reportsAdvisory(findingsB); ra != rb {
		return ra
	}
	if aa, ab := coverageA == CoverageAnalysed, coverageB == CoverageAnalysed; aa != ab {
		return aa
	}
	if ra, rb := completenessRung(a.CallGraphCompleteness), completenessRung(b.CallGraphCompleteness); ra != rb {
		return ra > rb
	}
	if !a.DatabaseSnapshot.RetrievedAt().Equal(b.DatabaseSnapshot.RetrievedAt()) {
		return a.DatabaseSnapshot.RetrievedAt().After(b.DatabaseSnapshot.RetrievedAt())
	}
	if a.DatabaseSnapshot.Version() != b.DatabaseSnapshot.Version() {
		// Both snapshots claim the same retrieval instant, so the instant cannot
		// order them. The version string is the database's own generation label
		// and is the only remaining statement about which is later.
		return a.DatabaseSnapshot.Version() > b.DatabaseSnapshot.Version()
	}
	if !a.ScannedAt.Equal(b.ScannedAt) {
		return a.ScannedAt.After(b.ScannedAt)
	}
	return a.ContentHash < b.ContentHash
}

// reportsAdvisory reports whether a findings axis states that an advisory
// matched this module — live or retracted — as opposed to reporting none.
func reportsAdvisory(f RecordFindingsStatus) bool {
	return f == FindingsRecordAffected || f == FindingsRecordWithdrawn
}

// completenessRung orders the call-graph fidelity a record's reachability
// findings were derived at. Higher is more complete.
//
// The levels mirror internal/callgraph/domain.CompletenessLevel, which is the
// source of truth for the ladder; the values are compared as strings here
// because a VulnerabilityRecord stores the level as one and this domain does not
// depend on the call-graph domain. TestCompletenessRung_CoversEveryCallGraphLevel
// pins the two together, so a level added there cannot silently fall to the
// bottom rung here.
//
// An unrecorded level ranks below every stated one but above nothing else: a
// record that consulted no call graph made no reachability claim, so it must not
// displace one that did, and it must still be servable when it is all there is.
func completenessRung(level string) int {
	switch level {
	case "BUILT_WITH_BODIES":
		return 4
	case "TYPE_ONLY":
		return 3
	case "METADATA_ONLY":
		return 2
	case "FAILED":
		return 1
	default:
		return 0
	}
}
