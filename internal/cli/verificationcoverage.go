package cli

import (
	"context"
	"fmt"
	"io"

	"github.com/eitanity/kanonarion/internal/coordinate"
	fetchdomain "github.com/eitanity/kanonarion/internal/fetch/domain"
	stdlibdomain "github.com/eitanity/kanonarion/internal/stdlib/domain"
	walkdomain "github.com/eitanity/kanonarion/internal/walk/domain"
)

// fetchRecordReader is the one read the coverage report needs. It is declared
// here rather than taking a whole Container so the walk entry points, which are
// driven by five callers with different jobs, gain a dependency they can decline
// by passing nil.
type fetchRecordReader interface {
	ComposeFetchRecord(ctx context.Context, coord coordinate.ModuleCoordinate) (fetchdomain.CompositeRecord, bool, error)
}

// graphVerificationCoverage aggregates how a walk's graph was verified, reading
// the fetch record behind each node.
//
// A read error is treated as an absent record rather than failing the command:
// this is a report about a walk that has already produced its answer, and losing
// that answer because one record could not be read would be the worse trade.
// Absence is visible in the output either way, so nothing is silently counted as
// verified.
func graphVerificationCoverage(
	ctx context.Context,
	nodes []walkdomain.GraphNode,
	records fetchRecordReader,
) fetchdomain.VerificationCoverage {
	rows := graphVerificationRows(ctx, nodes, records)
	obs := make([]fetchdomain.CoverageObservation, 0, len(rows))
	for _, r := range rows {
		obs = append(obs, r.observation)
	}
	return fetchdomain.VerificationCoverageOf(obs)
}

// moduleVerification is one module's contribution to the coverage aggregate,
// with the reason that was RECORDED for it rather than one derived here.
//
// The counts alone cannot answer the question they are usually asked in service
// of. "Seven modules are checksum-database-only" is a number; whether that is a
// proxy stripping Origin metadata, a forge that could not be reached, or
// --skip-vcs-verify left set in CI is the answer, and until now establishing it
// meant parsing another command's JSON with python3 — a status without its basis
// is a claim the reader cannot check.
type moduleVerification struct {
	// Coordinate is the module as the walk resolved it.
	Coordinate string `json:"coordinate"`
	Path       string `json:"path"`
	Version    string `json:"version"`
	// OriginalCoordinate is the coordinate a replace directive stood in for,
	// present only on a replaced node. The class and the reason belong to the
	// bytes, which are the replacement's, but the name a reader arrives with is
	// usually the original — a row carrying only the fork's name is unfindable
	// by anyone reading the manifest that named upstream.
	OriginalCoordinate string `json:"original_coordinate,omitempty"`
	// Class is the coverage bucket this module fell in — the same vocabulary the
	// aggregate counts, so a reader can sum the rows and get the totals.
	Class string `json:"class"`
	// Status is the verification status the record itself recorded. It is the
	// finer of the two words and it is the one that answers "why": a bucket folds
	// several statuses together on purpose — every Unverified* status carries the
	// same amount of assurance, namely none — and what to DO about a module
	// differs entirely between them. Empty where nothing recorded a status.
	Status string `json:"status,omitempty"`
	// Reason is the prose the record recorded alongside that status. Most records
	// carry none: a measurement that went as expected records the status and
	// nothing else, and the detail is written when something is worth saying —
	// a hash that disagreed, a database that could not be reached. Its absence is
	// therefore not a gap in this report, and the report says so in words rather
	// than leaving a blank that reads as "nothing to report".
	Reason string `json:"reason,omitempty"`

	// observation is the row's contribution to the aggregate. It is unexported
	// and derived here, beside the row, so the per-module report and the totals
	// are one measurement rather than two that may disagree.
	observation fetchdomain.CoverageObservation
}

// graphVerificationRows classifies every node of a walk's graph and records why.
// It is the single pass both the aggregate and the per-module report are built
// from.
func graphVerificationRows(
	ctx context.Context,
	nodes []walkdomain.GraphNode,
	records fetchRecordReader,
) []moduleVerification {
	rows := make([]moduleVerification, 0, len(nodes))
	for _, n := range nodes {
		row := moduleVerification{
			Coordinate: n.Coordinate.String(),
			Path:       n.Coordinate.Path(),
			Version:    n.Coordinate.Version(),
		}
		if !n.OriginalCoordinate.IsZero() {
			row.OriginalCoordinate = n.OriginalCoordinate.String()
		}
		switch n.ResolutionSource {
		// The standard library is toolchain-provided: its custody rides on the
		// graph node, and there is no fetch record to look up. Reading it from
		// the node reports the assurance it actually has instead of the absence
		// a record lookup would invent.
		case walkdomain.ResolutionStdlib:
			row.observation = stdlibCoverageObservation(n)
			if n.Stdlib != nil {
				row.Status = n.Stdlib.VerificationStatus
				row.Reason = n.Stdlib.VerificationDetail
			}
		// A module built from a local source tree has no remote artefact and so
		// no fetch record. Counting it as an absent measurement would report a
		// project walk as short of its own main module on every run.
		case walkdomain.ResolutionLocalMainModule, walkdomain.ResolutionLocalReplace:
			row.observation = fetchdomain.CoverageObservation{
				Bucket:   fetchdomain.BucketLocalSource,
				Recorded: true,
			}
			row.Status = "local source"
			row.Reason = "built from a local source tree; there is no published artefact to check a checksum against"
		default:
			rec, found, err := records.ComposeFetchRecord(ctx, n.Coordinate)
			switch {
			case err != nil:
				row.Reason = "the fetch record for this module could not be read, so nothing here describes how it was verified"
			case !found:
				row.Reason = "no fetch record is stored for this coordinate, so no verification of it was ever measured"
			default:
				row.observation = fetchdomain.CoverageObservation{
					Bucket:   fetchdomain.BucketForVerification(fetchdomain.VerificationStatus(rec.VerificationStatus)),
					Legs:     rec.Legs,
					Recorded: true,
				}
				row.Status = rec.VerificationStatus
				row.Reason = rec.VerificationDetail
			}
		}
		row.Class = row.observation.Bucket.String()
		if !row.observation.Recorded {
			row.Class = fetchdomain.BucketUnrecorded.String()
		}
		rows = append(rows, row)
	}
	return rows
}

// stdlibCoverageObservation reads the standard library's custody off the graph
// node. Its vocabulary is deliberately distinct from the fetch stage's — the
// tarball is checked against go.dev/dl, not against a checksum database — so it
// is mapped here rather than cast into a status enum that has never heard of it.
// It carries no validation legs, so it reports as not-measured for the ledger,
// which is exactly what it is.
func stdlibCoverageObservation(n walkdomain.GraphNode) fetchdomain.CoverageObservation {
	if n.Stdlib == nil || n.Stdlib.VerificationStatus == "" {
		return fetchdomain.CoverageObservation{}
	}
	bucket := fetchdomain.BucketUnrecognised
	switch stdlibdomain.VerificationStatus(n.Stdlib.VerificationStatus) {
	case stdlibdomain.VerifiedGoDevChecksum:
		// The published checksum plus a release-tag anchor in the Go source
		// repository is the stdlib's equivalent of the strongest module class.
		bucket = fetchdomain.BucketCrossVerified
	case stdlibdomain.VerifiedLocalToolchain:
		// Checked against the toolchain already on this host rather than the
		// published manifest: a positive offline signal, no published anchor.
		bucket = fetchdomain.BucketGoSumOnly
	case stdlibdomain.GoDevChecksumMismatch, stdlibdomain.UnverifiedGoDevUnavailable:
		bucket = fetchdomain.BucketUnverified
	}
	return fetchdomain.CoverageObservation{Bucket: bucket, Recorded: true}
}

// reportGraphVerificationCoverage writes the coverage aggregate for a walk's
// graph. A nil reader skips it entirely: the walk entry points are also driven
// by audit, inspect and sbom, which either report their own coverage or are
// using the walk as a means rather than presenting it as the answer.
func reportGraphVerificationCoverage(
	ctx context.Context,
	nodes []walkdomain.GraphNode,
	records fetchRecordReader,
	stderr io.Writer,
) error {
	if records == nil {
		return nil
	}
	return writeVerificationCoverage(stderr, graphVerificationCoverage(ctx, nodes, records))
}

// writeVerificationCoverage renders the coverage aggregate.
//
// It goes to stderr on both commands, never stdout: stdout is the data channel
// that --json callers pipe into jq, and a report about the run does not belong
// in the run's output. The figures are counts only — no host is named and no
// proxy is judged, because coverage catches every cause of a collapse while a
// proxy allowlist would catch one and age badly.
func writeVerificationCoverage(w io.Writer, c fetchdomain.VerificationCoverage) error {
	if c.Total == 0 {
		return nil
	}

	if _, err := fmt.Fprintf(w, "verification coverage over %d module(s):\n", c.Total); err != nil {
		return fmt.Errorf("writing coverage header: %w", err)
	}
	for _, row := range []struct {
		bucket fetchdomain.VerificationBucket
		count  int
	}{
		{fetchdomain.BucketCrossVerified, c.CrossVerified},
		{fetchdomain.BucketChecksumDBOnly, c.ChecksumDBOnly},
		{fetchdomain.BucketGoSumOnly, c.GoSumOnly},
		{fetchdomain.BucketUnverified, c.Unverified},
		{fetchdomain.BucketLocalSource, c.LocalSource},
		{fetchdomain.BucketUnrecorded, c.Unrecorded},
		{fetchdomain.BucketUnrecognised, c.Unrecognised},
	} {
		// Zero rows are dropped so the line stays readable, EXCEPT
		// cross-verified: printing "0" is the entire point on a collapsed graph,
		// and a row that disappears when it hits zero cannot report a collapse.
		if row.count == 0 && row.bucket != fetchdomain.BucketCrossVerified {
			continue
		}
		if _, err := fmt.Fprintf(w, "  %-34s %5d  %5.1f%%\n",
			row.bucket, row.count, percentOf(row.count, c.Total)); err != nil {
			return fmt.Errorf("writing coverage row: %w", err)
		}
	}

	// The ledger's own answer, which the status cannot give: whether this run
	// established the VCS anchor or carried it forward, and — the class that
	// matters most — whether no cross-verification evidence exists at all.
	// A record written before the ledger carries no legs and is reported as not
	// measured, never as never-cross-verified: the check may well have run, the
	// record simply cannot say, and conflating the two makes an unmigrated store
	// look like a collapse.
	// State the honest denominator. Against the graph total a project walk
	// reports a shortfall for its own main module and the standard library,
	// neither of which has a module artefact to anchor.
	if n := c.CrossVerifiable(); n > 0 {
		if _, err := fmt.Fprintf(w, "  cross-verified %d of %d module(s) where it applies (%.1f%%)\n",
			c.CrossVerified, n, percentOf(c.CrossVerified, n)); err != nil {
			return fmt.Errorf("writing coverage denominator: %w", err)
		}
	}

	if c.CrossVerifiable() > 0 {
		if _, err := fmt.Fprintf(w,
			"  VCS evidence (fetch ledger): %d rechecked by this run, %d inherited, %d never established, %d not measured\n",
			c.VCSRechecked, c.VCSInherited, c.VCSNever, c.VCSNotMeasured); err != nil {
			return fmt.Errorf("writing coverage legs: %w", err)
		}
	}

	if c.IsCollapsed() {
		if _, err := fmt.Fprintf(w,
			"  note: no module in this graph carries a VCS anchor — cross-verification covered none of it\n"); err != nil {
			return fmt.Errorf("writing coverage note: %w", err)
		}
	}
	return nil
}

// percentOf is the share of total, guarding the empty graph so the report never
// divides by zero on a scope that resolved to nothing.
func percentOf(n, total int) float64 {
	if total == 0 {
		return 0
	}
	return 100 * float64(n) / float64(total)
}
