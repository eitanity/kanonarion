package localfile_test

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	fetchdomain "github.com/eitanity/kanonarion/internal/fetch/domain"
	"github.com/eitanity/kanonarion/internal/walk/adapters/policy/localfile"
	domain2 "github.com/eitanity/kanonarion/internal/walk/domain"
)

const validPolicy = `
version: "1"
stages:
  fetch:
    max_depth: 2
    follow_replace: false
    follow_test: false
    follow_indirect: false
  license:
    max_depth: 1
    follow_replace: true
    follow_test: false
    follow_indirect: true
`

func TestLoadPolicy_Valid(t *testing.T) {
	path := writeTempFile(t, validPolicy)
	store := localfile.New(path)
	result, err := store.LoadPolicy(context.Background())
	if err != nil {
		t.Fatalf("LoadPolicy: %v", err)
	}
	if result.Policy.Version != "1" {
		t.Errorf("Version = %q, want %q", result.Policy.Version, "1")
	}
	fetch := result.Policy.Stages["fetch"]
	if fetch.MaxDepth != 2 {
		t.Errorf("fetch.MaxDepth = %d, want 2", fetch.MaxDepth)
	}
	if fetch.FollowReplace {
		t.Error("fetch.FollowReplace = true, want false")
	}
	if fetch.FollowIndirect {
		t.Error("fetch.FollowIndirect = true, want false")
	}
	if result.ContentHash == "" {
		t.Error("ContentHash is empty")
	}
	if result.Source != path {
		t.Errorf("Source = %q, want %q", result.Source, path)
	}
}

func TestLoadPolicy_NotFound(t *testing.T) {
	store := localfile.New("/no/such/file.yaml")
	_, err := store.LoadPolicy(context.Background())
	if !errors.Is(err, localfile.ErrPolicyNotFound) {
		t.Errorf("error = %v, want ErrPolicyNotFound", err)
	}
}

func TestLoadPolicy_MissingVersion(t *testing.T) {
	path := writeTempFile(t, "stages:\n  fetch:\n    max_depth: 1\n")
	store := localfile.New(path)
	_, err := store.LoadPolicy(context.Background())
	if err == nil {
		t.Fatal("expected error for missing version, got nil")
	}
}

func TestLoadPolicy_VersionTooNew(t *testing.T) {
	path := writeTempFile(t, "version: \"999\"\nstages: {}\n")
	store := localfile.New(path)
	_, err := store.LoadPolicy(context.Background())
	if err == nil {
		t.Fatal("expected error for schema version too new, got nil")
	}
}

func TestLoadPolicy_InvalidYAML(t *testing.T) {
	path := writeTempFile(t, "version: [unclosed\n")
	store := localfile.New(path)
	_, err := store.LoadPolicy(context.Background())
	if err == nil {
		t.Fatal("expected error for invalid YAML, got nil")
	}
}

func TestLoadPolicy_UnknownStagePreserved(t *testing.T) {
	yaml := "version: \"1\"\nstages:\n  future_stage:\n    max_depth: 5\n"
	path := writeTempFile(t, yaml)
	result, err := localfile.New(path).LoadPolicy(context.Background())
	if err != nil {
		t.Fatalf("LoadPolicy with unknown stage: %v", err)
	}
	if _, ok := result.Policy.Stages["future_stage"]; !ok {
		t.Error("unknown stage was dropped; want it preserved for forward compat")
	}
}

func TestParse_Minimal(t *testing.T) {
	p, err := localfile.Parse([]byte("version: \"1\"\nstages: {}\n"))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if p.Version != "1" {
		t.Errorf("Version = %q, want %q", p.Version, "1")
	}
}

func TestLoadPolicy_HashDeterminism(t *testing.T) {
	path1 := writeTempFile(t, validPolicy)
	path2 := writeTempFile(t, validPolicy)

	r1, err := localfile.New(path1).LoadPolicy(context.Background())
	if err != nil {
		t.Fatalf("first load: %v", err)
	}
	r2, err := localfile.New(path2).LoadPolicy(context.Background())
	if err != nil {
		t.Fatalf("second load: %v", err)
	}
	if r1.ContentHash != r2.ContentHash {
		t.Errorf("hash not deterministic: %q != %q", r1.ContentHash, r2.ContentHash)
	}
}

func TestWalkRecord_PolicyRoundTrip(t *testing.T) {
	p, err := localfile.Parse([]byte(validPolicy))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if p.Stages["fetch"].MaxDepth != 2 {
		t.Errorf("MaxDepth = %d, want 2", p.Stages["fetch"].MaxDepth)
	}

	target := fetchdomain.ModuleCoordinate{Path: "example.com/m", Version: "v1.0.0"}
	outcome := domain2.WalkOutcome{
		Target:         target,
		Graph:          domain2.Graph{Target: target},
		PerNodeResults: map[fetchdomain.ModuleCoordinate]domain2.NodeResult{},
		OverallStatus:  domain2.WalkSucceeded,
	}
	rec := domain2.NewWalkRecord("TEST-POLICY-001", "bot", "1.0.0", domain2.WalkScopeCode, domain2.WalkDepthFull, outcome, p, "sha256:abc")
	rec, err = domain2.WalkRecordHasher{}.SetContentHash(rec)
	if err != nil {
		t.Fatalf("SetContentHash: %v", err)
	}

	if rec.PolicyVersion != "1" {
		t.Errorf("PolicyVersion = %q, want %q", rec.PolicyVersion, "1")
	}
	if rec.PolicyHash != "sha256:abc" {
		t.Errorf("PolicyHash = %q, want %q", rec.PolicyHash, "sha256:abc")
	}
	if rec.StageDepths["fetch"].MaxDepth != 2 {
		t.Errorf("StageDepths[fetch].MaxDepth = %d, want 2", rec.StageDepths["fetch"].MaxDepth)
	}

	// Round-trip through Marshal/Unmarshal.
	data, err := domain2.WalkRecordHasher{}.Marshal(rec)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	rec2, err := domain2.WalkRecordHasher{}.Unmarshal(data)
	if err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if rec2.PolicyVersion != rec.PolicyVersion {
		t.Errorf("PolicyVersion round-trip: %q != %q", rec2.PolicyVersion, rec.PolicyVersion)
	}
	if rec2.PolicyHash != rec.PolicyHash {
		t.Errorf("PolicyHash round-trip: %q != %q", rec2.PolicyHash, rec.PolicyHash)
	}
	if rec2.StageDepths["fetch"].MaxDepth != rec.StageDepths["fetch"].MaxDepth {
		t.Errorf("StageDepths[fetch].MaxDepth round-trip: %d != %d",
			rec2.StageDepths["fetch"].MaxDepth, rec.StageDepths["fetch"].MaxDepth)
	}
}

func writeTempFile(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "policy.yaml")
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil { //nolint:gosec
		t.Fatalf("writing temp file: %v", err)
	}
	return path
}
