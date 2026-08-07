package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/eitanity/kanonarion/internal/cli/testfakes"
	"github.com/eitanity/kanonarion/internal/coordinate"
	"github.com/eitanity/kanonarion/internal/coordinate/coordinatetest"
	fetchdomain "github.com/eitanity/kanonarion/internal/fetch/domain"
	walkdomain "github.com/eitanity/kanonarion/internal/walk/domain"
)

// coverageFixture builds a walk whose graph has one module of each class that
// matters to the report: cross-verified, degraded to the checksum database, and
// the local main module that has nothing to cross-verify.
func coverageFixture(t *testing.T) (*testfakes.FakeQueryWalks, fakeFetchRecords, string) {
	t.Helper()

	anchored := coordinatetest.MustNew("example.com/anchored", "v1.0.0")
	degraded := coordinatetest.MustNew("example.com/degraded", "v2.0.0")
	local, err := coordinate.NewLocalCoordinate("example.com/app")
	if err != nil {
		t.Fatalf("local coordinate: %v", err)
	}

	records := fakeFetchRecords{byCoord: map[coordinate.ModuleCoordinate]fetchdomain.CompositeRecord{
		anchored: {
			FactRecord: fetchdomain.FactRecord{VerificationStatus: string(fetchdomain.Verified)},
			Legs:       []fetchdomain.ValidationLeg{{Kind: fetchdomain.LegVCS, Provenance: fetchdomain.LegRechecked}},
		},
		degraded: {
			FactRecord: fetchdomain.FactRecord{VerificationStatus: string(fetchdomain.VerifiedBySumDBOnly)},
			Legs:       []fetchdomain.ValidationLeg{{Kind: fetchdomain.LegSumDB, Provenance: fetchdomain.LegRechecked}},
		},
	}}

	walks := testfakes.NewFakeQueryWalks()
	const id = "01KQDBVW092ER1HNXZ60X27CMD"
	walks.AddWalk(walkdomain.WalkRecord{
		ID: id,
		Graph: walkdomain.Graph{Nodes: []walkdomain.GraphNode{
			{Coordinate: anchored, ResolutionSource: walkdomain.ResolutionMVS},
			{Coordinate: degraded, ResolutionSource: walkdomain.ResolutionMVS},
			{Coordinate: local, ResolutionSource: walkdomain.ResolutionLocalMainModule},
		}},
	})
	return walks, records, id
}

// The figures are a CI gate's input, so the field names are a contract. This
// pins the document by its JSON keys rather than by the Go struct, which is the
// only way the contract can actually break in a test.
func TestRunVerificationCoverage_JSONFieldNames(t *testing.T) {
	walks, records, id := coverageFixture(t)

	jsonOut = true
	t.Cleanup(func() { jsonOut = false })

	var buf bytes.Buffer
	if err := runVerificationCoverage(context.Background(), id, walks, records, false, &buf); err != nil {
		t.Fatalf("runVerificationCoverage: %v", err)
	}

	var got map[string]any
	if err := json.Unmarshal(buf.Bytes(), &got); err != nil {
		t.Fatalf("decoding coverage document: %v\n%s", err, buf.String())
	}

	for key, want := range map[string]float64{
		"total":            3,
		"recorded":         3,
		"cross_verifiable": 2,
		"cross_verified":   1,
		"checksum_db_only": 1,
		"go_sum_only":      0,
		"unverified":       0,
		"local_source":     1,
		"unrecorded":       0,
		"unrecognised":     0,
	} {
		v, ok := got[key]
		if !ok {
			t.Errorf("field %q missing: a gate asserting on it cannot tell zero from absent", key)
			continue
		}
		if v != want {
			t.Errorf("%s = %v, want %v", key, v, want)
		}
	}

	if got["walk_id"] != id {
		t.Errorf("walk_id = %v, want %s", got["walk_id"], id)
	}
	if got["collapsed"] != false {
		t.Errorf("collapsed = %v: one module carries a VCS anchor, so the graph has not collapsed", got["collapsed"])
	}

	vcs, ok := got["vcs"].(map[string]any)
	if !ok {
		t.Fatalf("vcs = %T, want an object", got["vcs"])
	}
	for key, want := range map[string]float64{
		"rechecked": 1, "inherited": 0, "never": 1, "not_measured": 0,
	} {
		if vcs[key] != want {
			t.Errorf("vcs.%s = %v, want %v", key, vcs[key], want)
		}
	}
}

// The acceptance the ticket names: a graph where cross-verification covered
// nothing must say so, rather than presenting populated status rows without
// comment. `collapsed` is derived in the document so every gate agrees on what
// a collapse is instead of each re-deriving it from the counts.
func TestRunVerificationCoverage_ReportsCollapse(t *testing.T) {
	degraded := coordinatetest.MustNew("example.com/degraded", "v2.0.0")
	records := fakeFetchRecords{byCoord: map[coordinate.ModuleCoordinate]fetchdomain.CompositeRecord{
		degraded: {
			FactRecord: fetchdomain.FactRecord{VerificationStatus: string(fetchdomain.VerifiedBySumDBOnly)},
			Legs:       []fetchdomain.ValidationLeg{{Kind: fetchdomain.LegSumDB, Provenance: fetchdomain.LegRechecked}},
		},
	}}
	walks := testfakes.NewFakeQueryWalks()
	const id = "01KQDBVW092ER1HNXZ60X27CME"
	walks.AddWalk(walkdomain.WalkRecord{
		ID:    id,
		Graph: walkdomain.Graph{Nodes: []walkdomain.GraphNode{{Coordinate: degraded, ResolutionSource: walkdomain.ResolutionMVS}}},
	})

	jsonOut = true
	t.Cleanup(func() { jsonOut = false })

	var buf bytes.Buffer
	if err := runVerificationCoverage(context.Background(), id, walks, records, false, &buf); err != nil {
		t.Fatalf("runVerificationCoverage: %v", err)
	}
	var doc map[string]any
	if err := json.Unmarshal(buf.Bytes(), &doc); err != nil {
		t.Fatalf("decoding coverage document: %v", err)
	}
	if doc["collapsed"] != true {
		t.Errorf("collapsed = %v, want true: nothing in this graph carries a VCS anchor", doc["collapsed"])
	}
	if doc["cross_verified"] != float64(0) {
		t.Errorf("cross_verified = %v, want 0", doc["cross_verified"])
	}
}

// Without --json the aggregate is the command's answer, so it goes to stdout —
// unlike the same line on walk and audit, where it is a side report and must
// stay out of the data channel.
func TestRunVerificationCoverage_HumanOutputOnStdout(t *testing.T) {
	walks, records, id := coverageFixture(t)

	var buf bytes.Buffer
	if err := runVerificationCoverage(context.Background(), id, walks, records, false, &buf); err != nil {
		t.Fatalf("runVerificationCoverage: %v", err)
	}
	out := buf.String()
	for _, want := range []string{id, "verification coverage over 3 module(s)", "cross-verified"} {
		if !strings.Contains(out, want) {
			t.Errorf("output missing %q:\n%s", want, out)
		}
	}
}

// An unknown walk is a question about a run that does not exist, not an empty
// answer about one that does. Reporting zero coverage for it would be a
// confident figure derived from nothing.
func TestRunVerificationCoverage_UnknownWalk(t *testing.T) {
	_, records, _ := coverageFixture(t)
	walks := testfakes.NewFakeQueryWalks()

	var buf bytes.Buffer
	err := runVerificationCoverage(context.Background(), "01KQDBVW092ER1HNXZ60X27CMZ", walks, records, false, &buf)
	if err == nil {
		t.Fatal("an unknown walk must be an error, not an empty report")
	}
	var exit *exitError
	if !errors.As(err, &exit) || exit.code != ExitNotFound {
		t.Errorf("err = %v, want an exitError with code %d", err, ExitNotFound)
	}
	if buf.Len() != 0 {
		t.Errorf("nothing should be written for an unknown walk, got:\n%s", buf.String())
	}
}
