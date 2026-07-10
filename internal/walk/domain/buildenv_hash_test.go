package domain_test

import (
	"bytes"
	"testing"

	domain3 "github.com/eitanity/kanonarion/internal/walk/domain"
)

// TestWalkRecordHasher_BuildEnvRoundTrip verifies the resolved build environment
// survives the canonical marshal/unmarshal round-trip and is covered by the
// content hash.
func TestWalkRecordHasher_BuildEnvRoundTrip(t *testing.T) {
	hasher := domain3.WalkRecordHasher{}
	rec := domain3.NewWalkRecord("01ARZ3NDEKTSV4RRFFQ69G5FAV", "ci-bot", "0.2.0", domain3.WalkScopeCode, domain3.WalkDepthFull, buildOutcome(), domain3.DefaultDepthPolicy(), "")
	rec.Graph.BuildEnv = domain3.BuildEnv{GOOS: "linux", GOARCH: "arm64", GoVersion: "go1.26.4"}

	rec, err := hasher.SetContentHash(rec)
	if err != nil {
		t.Fatalf("SetContentHash: %v", err)
	}
	if err := hasher.VerifyContentHash(rec); err != nil {
		t.Fatalf("VerifyContentHash: %v", err)
	}

	data, err := hasher.Marshal(rec)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	back, err := hasher.Unmarshal(data)
	if err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if back.Graph.BuildEnv != rec.Graph.BuildEnv {
		t.Errorf("BuildEnv after round-trip = %+v, want %+v", back.Graph.BuildEnv, rec.Graph.BuildEnv)
	}
}

// TestWalkRecordHasher_ZeroBuildEnvOmitted verifies a record with no build
// environment omits the build_env key entirely, so records created before the
// field existed hash and verify identically (backward compatibility).
func TestWalkRecordHasher_ZeroBuildEnvOmitted(t *testing.T) {
	hasher := domain3.WalkRecordHasher{}
	rec, err := hasher.SetContentHash(
		domain3.NewWalkRecord("01ARZ3NDEKTSV4RRFFQ69G5FAV", "ci-bot", "0.2.0", domain3.WalkScopeCode, domain3.WalkDepthFull, buildOutcome(), domain3.DefaultDepthPolicy(), ""),
	)
	if err != nil {
		t.Fatalf("SetContentHash: %v", err)
	}
	data, err := hasher.Marshal(rec)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	if bytes.Contains(data, []byte("build_env")) {
		t.Errorf("zero BuildEnv must be omitted from canonical JSON, got: %s", data)
	}
}
