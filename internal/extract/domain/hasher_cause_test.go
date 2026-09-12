package domain_test

import (
	"strings"
	"testing"
	"time"

	"github.com/eitanity/kanonarion/internal/coordinate"
	"github.com/eitanity/kanonarion/internal/coordinate/coordinatetest"
	"github.com/eitanity/kanonarion/internal/extract/domain"
	"github.com/eitanity/kanonarion/internal/failurecause"
	fetchdomain "github.com/eitanity/kanonarion/internal/fetch/domain"
)

func runWith(stage domain.StageResult) domain.ExtractionRun {
	return domain.ExtractionRun{
		SchemaVersion:   domain.ExtractionRunSchemaVersion,
		Ecosystem:       fetchdomain.EcosystemGo,
		ID:              "01EXTRACTRUN00000000000001",
		WalkID:          "01WALK0000000000000000001",
		RequestedStages: []string{"callgraph"},
		PerModuleResults: map[coordinate.ModuleCoordinate]domain.ModuleExtractionResult{
			coordinatetest.MustNew("example.com/mod", "v1.0.0"): {
				Coordinate: coordinatetest.MustNew("example.com/mod", "v1.0.0"),
				Stages:     map[string]domain.StageResult{"callgraph": stage},
			},
		},
		StartedAt:     time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
		CompletedAt:   time.Date(2026, 1, 1, 0, 1, 0, 0, time.UTC),
		OverallStatus: domain.ExtractionRunPartial,
	}
}

// TestExtractionRun_CarriesTheCauseToTheStore covers the axis the run printed
// and then dropped: a stored run could say a module failed and not say whether
// running again would repair it.
func TestExtractionRun_CarriesTheCauseToTheStore(t *testing.T) {
	var h domain.ExtractionRunHasher
	run, err := h.SetContentHash(runWith(domain.StageResult{
		Status: domain.StageFailed,
		Error:  "callgraph stage status=OutOfMemory: ended by the operating system",
		Cause:  failurecause.Environment,
	}))
	if err != nil {
		t.Fatalf("SetContentHash: %v", err)
	}
	data, err := h.Marshal(run)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	back, err := h.Unmarshal(data)
	if err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	got := back.PerModuleResults[coordinatetest.MustNew("example.com/mod", "v1.0.0")].Stages["callgraph"]
	if got.Cause != failurecause.Environment {
		t.Errorf("Cause after a round trip = %q, want environment", got.Cause)
	}
	if err := h.VerifyContentHash(back); err != nil {
		t.Errorf("the round-tripped run does not verify: %v", err)
	}
}

// The control that keeps the new field hash-transparent: a stage with no cause
// must marshal to exactly the bytes it did before the field existed, or every
// stored run written before this change stops verifying.
func TestExtractionRun_AnUnrecordedCauseIsOmitted(t *testing.T) {
	var h domain.ExtractionRunHasher
	run, err := h.SetContentHash(runWith(domain.StageResult{
		Status: domain.StageFailed,
		Error:  "callgraph stage status=LoadFailed: no packages",
	}))
	if err != nil {
		t.Fatalf("SetContentHash: %v", err)
	}
	data, err := h.Marshal(run)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	if string(data) == "" {
		t.Fatal("Marshal produced nothing")
	}
	if strings.Contains(string(data), `"cause"`) {
		t.Errorf("a stage with no cause emitted a cause field, which changes the hash of every record "+
			"written before the field existed: %s", data)
	}
}

// TestExtractionRunInProgress_RoundTrips pins the status a checkpointed run
// carries. It is the only status a run can hold that describes the record
// rather than the outcome, so a build that could write it and not read it back
// would turn every killed run into an unparseable one.
func TestExtractionRunInProgress_RoundTrips(t *testing.T) {
	if got := domain.ExtractionRunInProgress.String(); got != "in_progress" {
		t.Fatalf("String() = %q, want in_progress", got)
	}
	encoded, err := domain.ExtractionRunInProgress.MarshalJSON()
	if err != nil {
		t.Fatalf("MarshalJSON: %v", err)
	}
	var back domain.ExtractionRunStatus
	if err := back.UnmarshalJSON(encoded); err != nil {
		t.Fatalf("UnmarshalJSON(%s): %v", encoded, err)
	}
	if back != domain.ExtractionRunInProgress {
		t.Errorf("round trip produced %v, want in_progress", back)
	}
}
