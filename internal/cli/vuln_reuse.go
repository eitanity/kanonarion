package cli

import (
	"fmt"
	"time"

	vulndomain "github.com/eitanity/kanonarion/internal/vuln/domain"
)

// reachabilityVerdicts counts the findings in a record set that carry a
// reachability answer.
//
// It measures how much of a scan is a function of the project's own source.
// govulncheck runs in source mode, so "does this advisory reach our code" is
// computed from the source in front of it, while WHICH advisories apply at all
// is fixed by the module versions the walk resolved. That split is why a reused
// run is sound on one half of its answer and unvouched-for on the other.
//
// A record set with no such verdict has nothing whose basis a reused run could
// have moved under, and the derivation then says nothing about reachability
// rather than attaching a caveat to an answer that was never given.
func reachabilityVerdicts(recs []vulndomain.VulnerabilityRecord) int {
	n := 0
	for _, rec := range recs {
		n += recordReachabilityVerdicts(rec)
	}
	return n
}

// recordReachabilityVerdicts is the per-record half of the count. A nil
// Reachable is the record's way of saying reachability was not answered for that
// finding, so it is not counted: "not computed" is not a verdict.
func recordReachabilityVerdicts(rec vulndomain.VulnerabilityRecord) int {
	n := 0
	for _, f := range rec.Findings {
		if f.Reachable != nil {
			n++
		}
	}
	return n
}

// reusedScanLine states that a stored vulnerability scan answered this run, and
// what the reachability half of that answer rests on.
//
// One function, two surfaces: `audit` narrates it inside its derivation block
// and `vuln-scan` writes it on its own. Two renderers of one fact is how they
// come to disagree, and a reader who learns the sentence from one command has to
// recognise it from the other.
//
// The run and its date are named so the statement is checkable, and --force is
// named in the same line because a reader who wants the measurement taken again
// needs to be told how in the place they learn it was not.
//
// What the line does NOT say is that the source is unchanged. The call-graph
// line next door can claim identity because it re-reads the tree and compares;
// nothing re-reads the source here, and the reuse key does not consider it, so
// this states the basis of the verdicts and stops. The stronger sentence would
// be the more useful one and the false one.
//
// The clause is omitted entirely when the run answered no reachability question,
// because there is then no answer for it to qualify.
func reusedScanLine(run vulndomain.WalkScanRun, verdicts int) string {
	line := fmt.Sprintf("vulnerability scan: reused run %s of %s against snapshot %s@%s; nothing was re-scanned",
		run.ID, run.CompletedAt.UTC().Format(time.RFC3339),
		run.Snapshot.Source(), run.Snapshot.Version())
	if verdicts > 0 {
		line += fmt.Sprintf(", and its %d reachability verdict%s came from the source that run read, which this run did not re-read",
			verdicts, pluralise(verdicts, "", "s"))
	}
	return line + " (--force to re-measure)"
}

// vulnScanReachability is the machine-readable half of the statement above: how
// many of this document's verdicts depend on the project's source, and whether
// this invocation is the one that read it.
//
// It exists because an agent cannot read the stderr sentence. The document
// already carries the run's id and dates, so WHEN the source was read is a
// lookup a consumer can already make; what it could not see is that a reused run
// did not read the source again.
//
// Emitted on every run, reused or not, so a consumer reads one key rather than
// inferring a fact from a key's absence.
type vulnScanReachability struct {
	// Verdicts is the number of findings in the run carrying a reachability
	// answer. Zero means nothing in this document depends on the source.
	Verdicts int `json:"verdicts"`
	// SourceReadByThisRun is false on a served run: the verdicts came from the
	// source the named run read, and this invocation did not read it again.
	SourceReadByThisRun bool `json:"source_read_by_this_run"`
}

// vulnScanDocument is `vuln-scan --json`: the run record, plus the basis of its
// reachability leg.
//
// The run is EMBEDDED, not nested, so every key a consumer reads today keeps its
// place at the top level and the change is one added key on an object that
// already exists. The STORED type is untouched, which is the point: an output
// statement must not move a record's content hash or the pipeline generation it
// belongs to.
type vulnScanDocument struct {
	vulndomain.WalkScanRun
	Reachability vulnScanReachability `json:"reachability_basis"`
}
