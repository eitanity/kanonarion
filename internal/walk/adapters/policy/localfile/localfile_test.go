package localfile_test

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/eitanity/kanonarion/internal/coordinate"

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

	target := coordinate.ModuleCoordinate{Path: "example.com/m", Version: "v1.0.0"}
	outcome := domain2.WalkOutcome{
		Target:         target,
		Graph:          domain2.Graph{Target: target},
		PerNodeResults: map[coordinate.ModuleCoordinate]domain2.NodeResult{},
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

func TestParse_AllowedVCSHostsAbsentKeepsDefaults(t *testing.T) {
	// The footgun this guards: setting an unrelated fetch field must not zero
	// the trust list and silently push every module to checksum-DB-only.
	policy, err := localfile.Parse([]byte("version: \"1\"\nstages:\n  fetch:\n    max_depth: 3\n"))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if policy.Stages["fetch"].AllowedVCSHosts != nil {
		t.Fatalf("absent allowed_vcs_hosts should stay nil, got %v", *policy.Stages["fetch"].AllowedVCSHosts)
	}
	hosts, err := policy.FetchStage().VCSHostAllowlist()
	if err != nil {
		t.Fatalf("resolving allowlist: %v", err)
	}
	if !hosts.IsDefault() {
		t.Errorf("expected the built-in default set, got %v", hosts.Hosts())
	}
	if !hosts.IsAllowed("gitlab.com") {
		t.Error("a policy that only sets max_depth must not narrow the VCS allowlist")
	}
}

func TestParse_AllowedVCSHostsPresentOverridesWholesale(t *testing.T) {
	src := "version: \"1\"\nstages:\n  fetch:\n    allowed_vcs_hosts:\n      - github.com\n      - git.example.org\n"
	policy, err := localfile.Parse([]byte(src))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	hosts, err := policy.FetchStage().VCSHostAllowlist()
	if err != nil {
		t.Fatalf("resolving allowlist: %v", err)
	}
	if !hosts.IsAllowed("git.example.org") {
		t.Error("a widened policy should trust the added forge")
	}
	if hosts.IsAllowed("gitlab.com") {
		t.Error("an override replaces the built-in set; it must not merge with it")
	}
}

func TestParse_AllowedVCSHostsEmptyIsALoadErrorNamingSkipFlag(t *testing.T) {
	src := "version: \"1\"\nstages:\n  fetch:\n    allowed_vcs_hosts: []\n"
	_, err := localfile.Parse([]byte(src))
	if err == nil {
		t.Fatal("expected an explicitly empty allowed_vcs_hosts to fail policy load")
	}
	if !strings.Contains(err.Error(), "--skip-vcs-verify") {
		t.Errorf("the error must point at --skip-vcs-verify, got %q", err)
	}
}

func TestParse_AllowedVCSHostsMalformedEntryIsALoadError(t *testing.T) {
	for _, bad := range []string{"https://github.com", "github.com:443", "*.github.com", "GitHub.com", "github.com/foo"} {
		t.Run(bad, func(t *testing.T) {
			src := "version: \"1\"\nstages:\n  fetch:\n    allowed_vcs_hosts:\n      - " + strconv.Quote(bad) + "\n"
			_, err := localfile.Parse([]byte(src))
			if err == nil {
				t.Fatalf("expected %q to fail policy load", bad)
			}
			if !strings.Contains(err.Error(), bad) {
				t.Errorf("error must name the offending entry %q, got %q", bad, err)
			}
			if !strings.Contains(err.Error(), "allowed_vcs_hosts") {
				t.Errorf("error must name the field, got %q", err)
			}
		})
	}
}

func TestParse_AllowedVCSHostsOnANonFetchStageIsALoadError(t *testing.T) {
	// Only the fetch stage cross-verifies, so the key elsewhere would load
	// cleanly and change nothing — an operator would read their policy as
	// narrowing trust while every forge stayed trusted. That silent weakening is
	// the failure this field exists to prevent, so it is refused.
	for _, stage := range []string{"license", "callgraph", "future_stage"} {
		t.Run(stage, func(t *testing.T) {
			src := "version: \"1\"\nstages:\n  " + stage + ":\n    allowed_vcs_hosts:\n      - github.com\n"
			_, err := localfile.Parse([]byte(src))
			if err == nil {
				t.Fatalf("expected allowed_vcs_hosts on the %q stage to fail load", stage)
			}
			if !strings.Contains(err.Error(), stage) {
				t.Errorf("error must name the offending stage, got %q", err)
			}
			if !strings.Contains(err.Error(), "fetch") {
				t.Errorf("error must name the stage the field belongs on, got %q", err)
			}
		})
	}
}

// A misplaced trust list is refused, but an unknown stage NAME on its own stays
// accepted for forward compatibility — the two rules must not be confused.
func TestParse_UnknownStageWithoutVCSHostsStillLoads(t *testing.T) {
	policy, err := localfile.Parse([]byte("version: \"1\"\nstages:\n  future_stage:\n    max_depth: 5\n"))
	if err != nil {
		t.Fatalf("an unknown stage without allowed_vcs_hosts must still load: %v", err)
	}
	if policy.Stages["future_stage"].MaxDepth != 5 {
		t.Error("the unknown stage was not preserved")
	}
}

func TestParse_AllowedVCSHostsIsCopiedFromTheYAMLSlice(t *testing.T) {
	src := "version: \"1\"\nstages:\n  fetch:\n    allowed_vcs_hosts:\n      - github.com\n"
	policy, err := localfile.Parse([]byte(src))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	hosts := *policy.Stages["fetch"].AllowedVCSHosts
	if len(hosts) != 1 || hosts[0] != "github.com" {
		t.Fatalf("unexpected parsed hosts: %v", hosts)
	}
}
