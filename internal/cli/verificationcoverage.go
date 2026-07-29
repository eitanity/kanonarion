package cli

import (
	"context"
	"fmt"
	"io"

	"github.com/eitanity/kanonarion/internal/coordinate"
	fetchapp "github.com/eitanity/kanonarion/internal/fetch/application"
	fetchdomain "github.com/eitanity/kanonarion/internal/fetch/domain"
	stdlibdomain "github.com/eitanity/kanonarion/internal/stdlib/domain"
	walkdomain "github.com/eitanity/kanonarion/internal/walk/domain"
)

// fetchRecordReader is the one read the coverage report needs. It is declared
// here rather than taking a whole Container so the walk entry points, which are
// driven by five callers with different jobs, gain a dependency they can decline
// by passing nil.
type fetchRecordReader interface {
	GetFetchRecord(ctx context.Context, coord coordinate.ModuleCoordinate, pipelineVersion string) (fetchdomain.CompositeRecord, bool, error)
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
	obs := make([]fetchdomain.CoverageObservation, 0, len(nodes))
	for _, n := range nodes {
		// The standard library is toolchain-provided: its custody rides on the
		// graph node, and there is no fetch record to look up. Reading it from
		// the node reports the assurance it actually has instead of the absence
		// a record lookup would invent.
		if n.ResolutionSource == walkdomain.ResolutionStdlib {
			obs = append(obs, stdlibCoverageObservation(n))
			continue
		}
		// A module built from a local source tree has no remote artefact and so
		// no fetch record. Counting it as an absent measurement would report a
		// project walk as short of its own main module on every run.
		if n.ResolutionSource == walkdomain.ResolutionLocalMainModule ||
			n.ResolutionSource == walkdomain.ResolutionLocalReplace {
			obs = append(obs, fetchdomain.CoverageObservation{
				Bucket:   fetchdomain.BucketLocalSource,
				Recorded: true,
			})
			continue
		}
		rec, found, err := records.GetFetchRecord(ctx, n.Coordinate, fetchapp.PipelineVersion)
		if err != nil || !found {
			obs = append(obs, fetchdomain.CoverageObservation{})
			continue
		}
		obs = append(obs, fetchdomain.CoverageObservation{
			Bucket:   fetchdomain.BucketForVerification(fetchdomain.VerificationStatus(rec.VerificationStatus)),
			Legs:     rec.Legs,
			Recorded: true,
		})
	}
	return fetchdomain.VerificationCoverageOf(obs)
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
