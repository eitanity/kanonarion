package cli

import (
	"bytes"
	"context"
	"strings"
	"testing"

	"github.com/eitanity/kanonarion/internal/coordinate"
	"github.com/eitanity/kanonarion/internal/coordinate/coordinatetest"
	fetchdomain "github.com/eitanity/kanonarion/internal/fetch/domain"
	stdlibdomain "github.com/eitanity/kanonarion/internal/stdlib/domain"
	walkdomain "github.com/eitanity/kanonarion/internal/walk/domain"
)

// fakeFetchRecords answers the one read the coverage report makes.
type fakeFetchRecords struct {
	byCoord map[coordinate.ModuleCoordinate]fetchdomain.CompositeRecord
}

func (f fakeFetchRecords) GetFetchRecord(_ context.Context, coord coordinate.ModuleCoordinate, _ string) (fetchdomain.CompositeRecord, bool, error) {
	rec, ok := f.byCoord[coord]
	return rec, ok, nil
}

// The standard library's verification vocabulary is deliberately distinct from
// the fetch stage's — the tarball is checked against go.dev/dl, not a checksum
// database. Casting it into the module status enum reports the toolchain as an
// unrecognised status, which is a gap where there is none. This pins the
// mapping in both directions: a known stdlib status is never unrecognised, and
// an unknown one still is.
func TestStdlibCoverageObservation_UsesItsOwnVocabulary(t *testing.T) {
	node := func(status string) walkdomain.GraphNode {
		return walkdomain.GraphNode{
			ResolutionSource: walkdomain.ResolutionStdlib,
			Stdlib:           &walkdomain.StdlibFacts{VerificationStatus: status},
		}
	}

	for status, want := range map[stdlibdomain.VerificationStatus]fetchdomain.VerificationBucket{
		stdlibdomain.VerifiedGoDevChecksum:      fetchdomain.BucketCrossVerified,
		stdlibdomain.VerifiedLocalToolchain:     fetchdomain.BucketGoSumOnly,
		stdlibdomain.GoDevChecksumMismatch:      fetchdomain.BucketUnverified,
		stdlibdomain.UnverifiedGoDevUnavailable: fetchdomain.BucketUnverified,
	} {
		got := stdlibCoverageObservation(node(string(status)))
		if !got.Recorded {
			t.Errorf("%s reported no measurement", status)
		}
		if got.Bucket != want {
			t.Errorf("%s bucketed as %v, want %v", status, got.Bucket, want)
		}
	}

	// A status neither vocabulary knows still lands in the safety net.
	if got := stdlibCoverageObservation(node("SomeFutureStdlibStatus")); got.Bucket != fetchdomain.BucketUnrecognised {
		t.Errorf("unknown stdlib status bucketed as %v, want BucketUnrecognised", got.Bucket)
	}

	// An offline run acquires no custody at all: absence of a measurement, not a
	// failed one.
	if got := stdlibCoverageObservation(walkdomain.GraphNode{ResolutionSource: walkdomain.ResolutionStdlib}); got.Recorded {
		t.Error("a stdlib node without custody facts must report as unmeasured, not as a status")
	}
}

// A walk graph holds nodes that are not proxy artefacts. Reading a fetch record
// for the local main module would report an absent measurement for the very
// module the operator is auditing, on every run.
func TestGraphVerificationCoverage_LocalAndStdlibNodes(t *testing.T) {
	dep := coordinatetest.MustNew("example.com/dep", "v1.0.0")
	local, err := coordinate.NewLocalCoordinate("example.com/app")
	if err != nil {
		t.Fatalf("local coordinate: %v", err)
	}

	records := fakeFetchRecords{byCoord: map[coordinate.ModuleCoordinate]fetchdomain.CompositeRecord{
		dep: {
			FactRecord: fetchdomain.FactRecord{VerificationStatus: string(fetchdomain.Verified)},
			Legs:       []fetchdomain.ValidationLeg{{Kind: fetchdomain.LegVCS, Provenance: fetchdomain.LegRechecked}},
		},
	}}

	nodes := []walkdomain.GraphNode{
		{Coordinate: dep, ResolutionSource: walkdomain.ResolutionMVS},
		{Coordinate: local, ResolutionSource: walkdomain.ResolutionLocalMainModule},
		{ResolutionSource: walkdomain.ResolutionStdlib, Stdlib: &walkdomain.StdlibFacts{
			VerificationStatus: string(stdlibdomain.VerifiedGoDevChecksum),
		}},
	}

	c := graphVerificationCoverage(context.Background(), nodes, records)

	if c.Total != 3 {
		t.Fatalf("Total=%d, want 3", c.Total)
	}
	if c.CrossVerified != 2 {
		t.Errorf("CrossVerified=%d, want 2 (the dependency and the stdlib tarball): %+v", c.CrossVerified, c)
	}
	if c.LocalSource != 1 {
		t.Errorf("the local main module must be local source, not an absent record: %+v", c)
	}
	if c.Unrecorded != 0 || c.Unrecognised != 0 {
		t.Errorf("no node should be unrecorded or unrecognised here: %+v", c)
	}
	// The stdlib carries no validation legs and the main module is excluded, so
	// the ledger tally covers the dependency alone.
	if c.VCSRechecked != 1 || c.VCSNotMeasured != 1 || c.VCSNever != 0 {
		t.Errorf("unexpected ledger tally: %+v", c)
	}
}

// A missing record is reported as absent rather than failing the command or
// being silently counted as verified.
func TestGraphVerificationCoverage_MissingRecordIsAbsent(t *testing.T) {
	dep := coordinatetest.MustNew("example.com/dep", "v1.0.0")
	c := graphVerificationCoverage(context.Background(),
		[]walkdomain.GraphNode{{Coordinate: dep, ResolutionSource: walkdomain.ResolutionMVS}},
		fakeFetchRecords{})
	if c.Unrecorded != 1 || c.CrossVerified != 0 {
		t.Errorf("a module with no record must be unrecorded, never verified: %+v", c)
	}
}

// The collapse is the whole point, and a row that vanishes when it hits zero
// cannot report one. The cross-verified line must print even at zero, and the
// note must name the condition in words.
func TestWriteVerificationCoverage_CollapseIsLoud(t *testing.T) {
	c := fetchdomain.VerificationCoverageOf([]fetchdomain.CoverageObservation{
		{Bucket: fetchdomain.BucketChecksumDBOnly, Recorded: true},
		{Bucket: fetchdomain.BucketChecksumDBOnly, Recorded: true},
	})
	var buf bytes.Buffer
	if err := writeVerificationCoverage(&buf, c); err != nil {
		t.Fatalf("writeVerificationCoverage: %v", err)
	}
	out := buf.String()
	for _, want := range []string{
		"cross-verified (checksum db + VCS)     0",
		"cross-verified 0 of 2 module(s) where it applies (0.0%)",
		"no module in this graph carries a VCS anchor",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("collapse output missing %q:\n%s", want, out)
		}
	}
}

// A fully anchored graph says so and raises no note.
func TestWriteVerificationCoverage_HealthyGraphRaisesNoNote(t *testing.T) {
	c := fetchdomain.VerificationCoverageOf([]fetchdomain.CoverageObservation{
		{Bucket: fetchdomain.BucketCrossVerified, Recorded: true},
		{Bucket: fetchdomain.BucketCrossVerified, Recorded: true},
	})
	var buf bytes.Buffer
	if err := writeVerificationCoverage(&buf, c); err != nil {
		t.Fatalf("writeVerificationCoverage: %v", err)
	}
	out := buf.String()
	if strings.Contains(out, "no module in this graph carries a VCS anchor") {
		t.Errorf("a fully anchored graph must not report a collapse:\n%s", out)
	}
	if !strings.Contains(out, "cross-verified 2 of 2 module(s) where it applies (100.0%)") {
		t.Errorf("full coverage not stated:\n%s", out)
	}
}

// An empty scope writes nothing rather than a zero-module report.
func TestWriteVerificationCoverage_EmptyGraphIsSilent(t *testing.T) {
	var buf bytes.Buffer
	if err := writeVerificationCoverage(&buf, fetchdomain.VerificationCoverage{}); err != nil {
		t.Fatalf("writeVerificationCoverage: %v", err)
	}
	if buf.Len() != 0 {
		t.Errorf("empty graph produced output: %q", buf.String())
	}
}

// The aggregate audit prints must equal the rows audit prints. It is derived
// from the same per-row observations rather than a second store read, so the
// two cannot drift; this pins that they are wired that way.
func TestAuditVerificationCoverage_EqualsTheRows(t *testing.T) {
	results := []auditModuleResult{
		{Verification: "Verified", coverage: fetchdomain.CoverageObservation{Bucket: fetchdomain.BucketCrossVerified, Recorded: true}},
		{Verification: "Verified", coverage: fetchdomain.CoverageObservation{Bucket: fetchdomain.BucketCrossVerified, Recorded: true}},
		{Verification: "VerifiedBySumDBOnly", coverage: fetchdomain.CoverageObservation{Bucket: fetchdomain.BucketChecksumDBOnly, Recorded: true}},
		{Verification: "(not fetched)"},
	}
	c := auditVerificationCoverage(results)

	if c.Total != len(results) {
		t.Fatalf("Total=%d, want %d", c.Total, len(results))
	}
	var verified, sumdbOnly int
	for _, r := range results {
		switch r.Verification {
		case "Verified":
			verified++
		case "VerifiedBySumDBOnly":
			sumdbOnly++
		}
	}
	if c.CrossVerified != verified {
		t.Errorf("aggregate says %d cross-verified, the rows say %d", c.CrossVerified, verified)
	}
	if c.ChecksumDBOnly != sumdbOnly {
		t.Errorf("aggregate says %d checksum-db-only, the rows say %d", c.ChecksumDBOnly, sumdbOnly)
	}
	if c.Unrecorded != 1 {
		t.Errorf("the unfetched row must be unrecorded: %+v", c)
	}
}
