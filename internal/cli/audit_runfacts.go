package cli

import "time"

// What `audit` states about the RUN, on the machine channel.
//
// audit narrates its own provenance to a person — which walk answered and
// whether it was re-resolved or reused, which scan run answered and against
// which advisory snapshot, what the reachability half of that answer rests on,
// the toolchain axis, and the date the staleness column carries — and until the
// envelope existed there was nowhere in the document for any of it. A --json
// caller read a set of rows with no record of where they came from.
//
// Two rules hold these types together:
//
//	one fact, one spelling. The reachability basis and the toolchain axis are
//	the objects `vuln-scan --json` already publishes, reused verbatim rather
//	than re-rendered here. A second rendering of one fact is how two commands
//	come to disagree about it, and a consumer that learns the shape from one
//	surface must recognise it on the other.
//
//	a state that was not measured is a VALUE. Every key below is emitted on
//	every run — an empty scope, a walk that produced no record, a run with no
//	staleness lookup to date — because a missing key and a null both read as
//	"nothing to report", which is the one thing an unmeasured axis does not
//	mean. Each object carries the boolean that says outright whether the thing
//	happened, so the reader is never asked to infer it from an empty string.

// auditRunJSON is the run-level half of `audit --json`, embedded in the envelope
// so every key sits at the top level beside the dependency scope.
type auditRunJSON struct {
	Walk auditWalkJSON `json:"walk"`
	Scan auditScanJSON `json:"scan"`
	// Reachability is `vuln-scan --json`'s own object under its own key: how many
	// of this answer's verdicts depend on the project's source, and whether this
	// invocation is the one that read it.
	Reachability vulnScanReachability `json:"reachability_basis"`
	// Toolchain is the axis beside the module evidence, in the shape vuln-scan
	// publishes, carrying the sentence the reader is shown verbatim.
	Toolchain vulnScanToolchainJSON `json:"toolchain"`
	Staleness auditStalenessJSON    `json:"staleness"`
}

// auditWalkJSON names the walk that fixed the dependency set and says whether
// this run derived it or served a stored one.
//
// The distinction is what the answer is worth: a reused record was not measured
// by this invocation, and in the cases where that matters — release evidence,
// incident response — a reader must be able to tell the two apart without
// parsing the stderr sentence that states it.
type auditWalkJSON struct {
	// Resolved is false when this run took no walk at all: an empty dependency
	// scope, or a walk leg that produced no record. The remaining fields are
	// then empty because there is no walk for them to name.
	Resolved bool `json:"resolved"`
	// ID is the walk record every downstream leg of this audit was keyed on.
	ID string `json:"id"`
	// Reused is true when the go.mod was re-resolved, the resolution turned out
	// identical to a stored walk, and that record answered. It is not "skipped":
	// the resolution ran either way.
	Reused bool `json:"reused"`
	// CompletedAt dates the record that answered, so a reused walk is checkable
	// against the store rather than taken on the sentence's word. RFC 3339 in
	// UTC, the same rendering the derivation statement prints.
	CompletedAt string `json:"completed_at"`
}

// auditScanJSON names the vulnerability scan run whose verdicts fill the
// vuln_status column, and the advisory generation it was judged against.
type auditScanJSON struct {
	// Answered is false when no scan run answered this audit: an empty scope, or
	// a scan leg that failed and was reported on stderr. The row verdicts are
	// then whatever the store already held, which is what the empty run id says.
	Answered bool `json:"answered"`
	// RunID names the run. It is stated on both arms, which the derivation
	// sentence is not: a scan derived by this run says so in prose and names no
	// id, leaving a --json consumer with no handle on the run it just paid for.
	RunID string `json:"run_id"`
	// Reused is true when a stored run answered and nothing was re-scanned.
	Reused bool `json:"reused"`
	// Snapshot is the advisory database generation the verdicts were judged
	// against — the fact that dates the answer, in the shape vuln-scan publishes.
	Snapshot vulnScanSnapshotJSON `json:"snapshot"`
}

// auditStalenessJSON dates the staleness column for the run as a whole.
//
// It is the machine-readable half of the table's footer, which is printed on
// STDOUT in the text form and had no JSON counterpart at all: the rows carry
// staleness_looked_up_at each, but the run-level statement "this is how current
// the whole column is" was a fact only a person could read.
type auditStalenessJSON struct {
	// Measured is false when no row in this answer carries a lookup — an offline
	// run with no ledger entry, a scope resolving nothing, a set that is entirely
	// toolchain-pinned. The text form prints no footer at all in that case, and
	// the remaining fields are empty.
	Measured bool `json:"measured"`
	// AsOf is the OLDEST lookup behind the column, because a table where most
	// rows were served from the ledger and a few re-queried is only as current as
	// the row asked about longest ago. RFC 3339 in UTC, so it is the same value a
	// row's staleness_looked_up_at carries rather than the minute-resolution
	// rendering the footer shows a person.
	AsOf string `json:"as_of"`
	// Age is how old that lookup was when this run read it, rounded to the
	// second. A duration string rather than a number of seconds, and in the same
	// units as TTL beside it, because the TTL is the figure it has to be compared
	// against and a reader should not have to convert one to do it.
	Age string `json:"age"`
	// TTL is the staleness.ttl in force: how long a recorded lookup may be served
	// before the proxy is asked again.
	TTL string `json:"ttl"`
	// RefreshWith is the command that re-queries the column, carried as data
	// because a remedy a consumer has to parse out of a sentence is not one it
	// can act on. audit has no flag of its own here: the TTL governs this column
	// and `latest --fresh` is what re-asks.
	RefreshWith string `json:"refresh_with"`
}

// stalenessRefreshCommand is the remedy the footer names and the field carries.
// One constant so the sentence and the field cannot offer different commands.
const stalenessRefreshCommand = "latest --fresh"

// newAuditRunJSON projects an audit's derivation and its rows onto the run-level
// half of the document.
//
// It is built from the SAME auditDerivation the stderr statements are written
// from, and the staleness date from the same helper the table's footer uses, so
// the document and the screen cannot state different things about one run.
func newAuditRunJSON(d auditDerivation, results []auditModuleResult, ttl time.Duration, now time.Time) auditRunJSON {
	return auditRunJSON{
		Walk:         auditWalkOf(d),
		Scan:         auditScanOf(d),
		Reachability: auditReachabilityOf(d),
		Toolchain:    toolchainSectionOf(d.toolchain),
		Staleness:    auditStalenessOf(results, ttl, now),
	}
}

// unauditedRunJSON is the run-level half for a run that audited nothing: the
// dependency scope resolved no module, so no walk was taken, no scan answered
// and no toolchain was judged.
//
// Every key is still present, stating that, rather than left out to be read as
// "nothing to report".
func unauditedRunJSON() auditRunJSON {
	return auditRunJSON{
		Toolchain: unjudgedToolchainSection("no dependency was audited, so this run took no walk and judged no toolchain"),
	}
}

// auditWalkOf names the walk the derivation records.
func auditWalkOf(d auditDerivation) auditWalkJSON {
	if d.walkRecord.ID == "" {
		return auditWalkJSON{}
	}
	return auditWalkJSON{
		Resolved:    true,
		ID:          d.walkRecord.ID,
		Reused:      d.walkReused,
		CompletedAt: d.walkRecord.CompletedAt.UTC().Format(time.RFC3339),
	}
}

// auditScanOf names the scan run that answered.
//
// A reused run is read off the derivation's own copy of it, and a derived one
// off the facts the scan leg handed back, because those are the two places the
// run is known — and each is the measurement its own statement was built from.
func auditScanOf(d auditDerivation) auditScanJSON {
	if d.scanReused {
		return auditScanJSON{
			Answered: true,
			RunID:    d.scanRun.ID,
			Reused:   true,
			Snapshot: vulnScanSnapshotOf(d.scanRun.Snapshot),
		}
	}
	if d.scanFacts.RunID == "" {
		return auditScanJSON{}
	}
	return auditScanJSON{
		Answered: true,
		RunID:    d.scanFacts.RunID,
		Reused:   false,
		Snapshot: d.scanFacts.Snapshot,
	}
}

// auditReachabilityOf states what the reachability half of the answer rests on.
//
// On a reused run the count is the derivation's, which is the number the stderr
// sentence states, so the two cannot disagree. On a derived one it is the count
// that run took as it wrote the records.
func auditReachabilityOf(d auditDerivation) vulnScanReachability {
	if d.scanReused {
		return vulnScanReachability{Verdicts: d.scanReachabilityVerdicts, SourceReadByThisRun: false}
	}
	return d.scanFacts.Reachability
}

// auditStalenessOf dates the column from the same lookup the footer names.
func auditStalenessOf(results []auditModuleResult, ttl time.Duration, now time.Time) auditStalenessJSON {
	oldest := auditStalenessAsOf(results)
	if oldest.IsZero() {
		return auditStalenessJSON{}
	}
	return auditStalenessJSON{
		Measured:    true,
		AsOf:        oldest.UTC().Format(time.RFC3339),
		Age:         now.Sub(oldest).Round(time.Second).String(),
		TTL:         ttl.String(),
		RefreshWith: stalenessRefreshCommand,
	}
}

// auditStalenessAsOf returns the lookup that dates the whole staleness column:
// the OLDEST one behind it. The zero time means no row carries a lookup at all.
//
// One helper, two surfaces — the table's footer and the document's staleness
// object — so the date a person reads and the date a machine reads are the same
// measurement rather than two that could drift.
func auditStalenessAsOf(results []auditModuleResult) time.Time {
	var oldest time.Time
	for _, r := range results {
		if r.StalenessLookedUpAt.IsZero() {
			continue
		}
		if oldest.IsZero() || r.StalenessLookedUpAt.Before(oldest) {
			oldest = r.StalenessLookedUpAt
		}
	}
	return oldest
}
