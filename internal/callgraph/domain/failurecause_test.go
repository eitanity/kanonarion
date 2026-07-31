package domain_test

import (
	"encoding/json"
	"testing"

	"github.com/eitanity/kanonarion/internal/callgraph/domain"
)

// TestRecordIsCacheable pins the cache-eligibility rule the extraction use case
// and the vuln stage's on-demand spawner both read.
func TestRecordIsCacheable(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name   string
		status domain.CallGraphStatus
		cause  domain.FailureCause
		want   bool
	}{
		{"extracted, no cause", domain.CallGraphStatusExtracted, domain.FailureCauseUnrecorded, true},
		{"partial, no cause", domain.CallGraphStatusPartial, domain.FailureCauseUnrecorded, true},
		{"excluded by config", domain.CallGraphStatusExcludedByConfig, domain.FailureCauseUnrecorded, true},
		{"load failed, module", domain.CallGraphStatusLoadFailed, domain.FailureCauseModule, true},
		{"load failed, environment", domain.CallGraphStatusLoadFailed, domain.FailureCauseEnvironment, false},
		{"cancelled, environment", domain.CallGraphStatusCancelled, domain.FailureCauseEnvironment, false},
		{"out of memory, environment", domain.CallGraphStatusOutOfMemory, domain.FailureCauseEnvironment, false},
		// The legacy shape: a failure written before the axis existed. It states no
		// cause, so it is not evidence the module was at fault, so it is re-attempted
		// once rather than served forever.
		{"load failed, no cause", domain.CallGraphStatusLoadFailed, domain.FailureCauseUnrecorded, false},
		{"extraction failed, no cause", domain.CallGraphStatusExtractionFailed, domain.FailureCauseUnrecorded, false},
		{"unknown status, no cause", domain.CallGraphStatusUnknown, domain.FailureCauseUnrecorded, false},
		// A cause from a future generation is not a stated module fault.
		{"unrecognised cause", domain.CallGraphStatusLoadFailed, domain.FailureCause("cosmic-rays"), false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			r := makeTestRecord()
			r.OverallStatus = tc.status
			r.FailureCause = tc.cause
			if got := domain.RecordIsCacheable(r); got != tc.want {
				t.Errorf("RecordIsCacheable(status=%s, cause=%s) = %v, want %v",
					tc.status, tc.cause, got, tc.want)
			}
		})
	}
}

// TestEnvironmentFailureNeverServesAGoodRecordsPlace guards the asymmetry that
// makes the rule safe to land: an ineligible failure does not suppress the good
// record beside it, because composition has already picked the good one.
func TestEnvironmentFailureBesideAGoodRecordIsNotWhatComposeServes(t *testing.T) {
	t.Parallel()

	failed := makeTestRecord()
	failed.Nodes, failed.Edges, failed.NodeCount, failed.EdgeCount = nil, nil, 0, 0
	failed.OverallStatus = domain.CallGraphStatusLoadFailed
	failed.Completeness = domain.CompletenessFailed
	failed.FailureCause = domain.FailureCauseEnvironment
	failed.ArtefactIdentity = "zip:h1:abc"
	failed.AnalysisSource = domain.AnalysisSourceModuleZip

	good := makeTestRecord()
	good.Completeness = domain.CompletenessBuiltWithBodies
	good.ArtefactIdentity = "zip:h1:abc"
	good.AnalysisSource = domain.AnalysisSourceModuleZip

	composed, err := domain.Compose([]domain.CallGraphRecord{failed, good}, domain.ComposeRequest{})
	if err != nil {
		t.Fatalf("Compose: %v", err)
	}
	if composed.OverallStatus != domain.CallGraphStatusExtracted {
		t.Fatalf("Compose served %s, want Extracted", composed.OverallStatus)
	}
	if !domain.RecordIsCacheable(composed) {
		t.Error("the composed answer is a built graph and must be cacheable")
	}
}

// TestFailureCauseIsAbsentWhenZero is the migration guard. The field must not
// appear in the canonical encoding of a record that states no cause, or every
// record already in the store would stop verifying against its stored hash.
func TestFailureCauseIsAbsentWhenZero(t *testing.T) {
	t.Parallel()

	var h domain.CallGraphRecordHasher
	sealed, err := h.SetContentHash(makeTestRecord())
	if err != nil {
		t.Fatalf("SetContentHash: %v", err)
	}
	raw, err := h.Marshal(sealed)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	var keys map[string]json.RawMessage
	if err := json.Unmarshal(raw, &keys); err != nil {
		t.Fatalf("unmarshalling canonical bytes: %v", err)
	}
	if _, present := keys["failure_cause"]; present {
		t.Error("failure_cause is present in the canonical encoding of a record that states no cause: " +
			"every record written before the axis existed would stop verifying")
	}
}

// TestFailureCauseIsHashCovered proves the axis is tamper-evident. Cache
// eligibility is decided by this field, so a field outside the hash would let a
// record be re-labelled as a module fault and served forever without detection.
func TestFailureCauseIsHashCovered(t *testing.T) {
	t.Parallel()

	var h domain.CallGraphRecordHasher
	r := makeTestRecord()
	r.OverallStatus = domain.CallGraphStatusLoadFailed
	r.FailureCause = domain.FailureCauseEnvironment
	sealed, err := h.SetContentHash(r)
	if err != nil {
		t.Fatalf("SetContentHash: %v", err)
	}
	if err := h.VerifyContentHash(sealed); err != nil {
		t.Fatalf("VerifyContentHash on an untampered record: %v", err)
	}

	tampered := sealed
	tampered.FailureCause = domain.FailureCauseModule
	if err := h.VerifyContentHash(tampered); err == nil {
		t.Error("relabelling the failure cause left the content hash valid: the field is outside the hash")
	}
}

// TestFailureCauseRoundTrips keeps the cause on the serialised record, so the
// gate reads what was written rather than a zero value the decoder dropped.
func TestFailureCauseRoundTrips(t *testing.T) {
	t.Parallel()

	var h domain.CallGraphRecordHasher
	r := makeTestRecord()
	r.OverallStatus = domain.CallGraphStatusLoadFailed
	r.FailureCause = domain.FailureCauseEnvironment
	sealed, err := h.SetContentHash(r)
	if err != nil {
		t.Fatalf("SetContentHash: %v", err)
	}
	raw, err := h.Marshal(sealed)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	back, err := h.Unmarshal(raw)
	if err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if back.FailureCause != domain.FailureCauseEnvironment {
		t.Errorf("FailureCause = %q after round trip, want %q", back.FailureCause, domain.FailureCauseEnvironment)
	}
	if domain.RecordIsCacheable(back) {
		t.Error("an environment failure round-tripped into a cacheable record")
	}
}

// TestFailureCauseStringNamesTheZeroValue keeps the zero value from rendering as
// an empty field a reader would take for an absence of failure.
func TestFailureCauseStringNamesTheZeroValue(t *testing.T) {
	t.Parallel()

	if got := domain.FailureCauseUnrecorded.String(); got != "not recorded" {
		t.Errorf("FailureCauseUnrecorded.String() = %q, want %q", got, "not recorded")
	}
	if got := domain.FailureCauseEnvironment.String(); got != "environment" {
		t.Errorf("FailureCauseEnvironment.String() = %q, want %q", got, "environment")
	}
}

// TestRecordIsFailure_UnknownStatusIsNotAFailure: a status written by a newer
// generation is not evidence that the extraction failed. Reading it as one would
// let this generation discard a graph it simply cannot name the outcome of,
// which is the opposite of what the axis is for.
func TestRecordIsFailure_UnknownStatusIsNotAFailure(t *testing.T) {
	t.Parallel()

	if domain.RecordIsFailure(domain.CallGraphRecord{OverallStatus: domain.CallGraphStatus(99)}) {
		t.Error("a status this generation does not define was read as a failure")
	}
}
