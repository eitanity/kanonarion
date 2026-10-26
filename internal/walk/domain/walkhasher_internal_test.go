package domain

import (
	"errors"
	"strings"
	"testing"

	"code.eitanity.com/kanonarion/internal/coordinate"
	"code.eitanity.com/kanonarion/internal/coordinate/coordinatetest"
	fetchdomain "code.eitanity.com/kanonarion/internal/fetch/domain"
)

func TestMarshalCanonicalWalk_MarshalFailure(t *testing.T) {
	original := canonicalMarshal
	t.Cleanup(func() { canonicalMarshal = original })
	injected := errors.New("injected marshal failure")
	canonicalMarshal = func(any) ([]byte, error) { return nil, injected }

	_, err := WalkRecordHasher{}.SetContentHash(WalkRecord{})
	if err == nil {
		t.Fatal("SetContentHash() error = nil, want wrapped marshal error")
	}
	if !errors.Is(err, injected) {
		t.Errorf("SetContentHash() error = %v, want it to wrap the injected error", err)
	}
	if !strings.Contains(err.Error(), "canonical walk record") {
		t.Errorf("SetContentHash() error = %q, want it to name the record being marshalled", err.Error())
	}
}

func TestVerifyContentHash_MarshalFailure(t *testing.T) {
	original := canonicalMarshal
	t.Cleanup(func() { canonicalMarshal = original })
	injected := errors.New("injected marshal failure")
	canonicalMarshal = func(any) ([]byte, error) { return nil, injected }

	err := WalkRecordHasher{}.VerifyContentHash(WalkRecord{})
	if !errors.Is(err, injected) {
		t.Errorf("VerifyContentHash() error = %v, want it to wrap the injected error", err)
	}
}

// TestSetContentHash_FetchRecordMarshalFailure drives the injected
// composite-marshal failure through toCanonicalNodeEntry,
// canonicalNodeResults and marshalCanonicalWalk: a node's fetch record that
// cannot be canonicalised must fail the hash with the coordinate named, never
// hash a record that silently dropped a node's evidence.
func TestSetContentHash_FetchRecordMarshalFailure(t *testing.T) {
	original := marshalCompositeFetch
	t.Cleanup(func() { marshalCompositeFetch = original })
	injected := errors.New("injected composite marshal failure")
	marshalCompositeFetch = func(fetchdomain.CompositeRecord) ([]byte, error) { return nil, injected }

	coord := coordinatetest.MustNew("example.com/mod", "v1.0.0")
	rec := WalkRecord{
		PerNodeResults: map[coordinate.ModuleCoordinate]NodeResult{
			coord: {Coordinate: coord, FetchRecord: &fetchdomain.CompositeRecord{}},
		},
	}
	_, err := WalkRecordHasher{}.SetContentHash(rec)
	if err == nil {
		t.Fatal("SetContentHash() error = nil, want wrapped composite marshal error")
	}
	if !errors.Is(err, injected) {
		t.Errorf("SetContentHash() error = %v, want it to wrap the injected error", err)
	}
	if !strings.Contains(err.Error(), "example.com/mod") {
		t.Errorf("SetContentHash() error = %q, want it to name the failing coordinate", err.Error())
	}
}

func TestIdentityHash_MarshalFailure(t *testing.T) {
	original := canonicalMarshal
	t.Cleanup(func() { canonicalMarshal = original })
	injected := errors.New("injected marshal failure")
	canonicalMarshal = func(any) ([]byte, error) { return nil, injected }

	if _, err := (WalkRecordHasher{}).IdentityHash(WalkRecord{}); !errors.Is(err, injected) {
		t.Errorf("IdentityHash() error = %v, want it to wrap the injected error", err)
	}
}

// TestNodeStatus_IsFailure: an unrecognised status counts as a failure.
func TestNodeStatus_IsFailure(t *testing.T) {
	for s, want := range map[NodeStatus]bool{
		NodeSucceeded: false, NodeLocalReplace: false, NodeFetchFailed: true, NodeInternalPanic: true, NodeStatus(99): true,
	} {
		if got := s.IsFailure(); got != want {
			t.Errorf("%v.IsFailure() = %v, want %v", s, got, want)
		}
	}
}

func TestCountNodeFailures(t *testing.T) {
	a, b := coordinatetest.MustNew("example.com/a", "v1.0.0"), coordinatetest.MustNew("example.com/b", "v1.0.0")
	rec := WalkRecord{PerNodeResults: map[coordinate.ModuleCoordinate]NodeResult{
		a: {Status: NodeSucceeded}, b: {Status: NodeFetchFailed},
	}}
	if got := CountNodeFailures(rec); got != 1 {
		t.Errorf("CountNodeFailures = %d, want 1", got)
	}
}

func TestArtefactAbsenceNoun(t *testing.T) {
	for s, want := range map[ResolutionSource]string{
		ResolutionLocalMainModule: "local main module", ResolutionLocalReplace: "local replace",
		ResolutionLocalWorkspaceMember: "workspace member", ResolutionStdlib: "Go standard library",
		ResolutionTinyGo: "TinyGo toolchain", ResolutionDepthBounded: "requirement beyond the depth bound",
		ResolutionMVS: "",
	} {
		if got := s.ArtefactAbsenceNoun(); got != want {
			t.Errorf("%s.ArtefactAbsenceNoun() = %q, want %q", s, got, want)
		}
	}
}
