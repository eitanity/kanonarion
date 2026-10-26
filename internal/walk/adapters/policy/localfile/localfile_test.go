package localfile_test

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"code.eitanity.com/kanonarion/internal/coordinate"
	"code.eitanity.com/kanonarion/internal/coordinate/coordinatetest"

	"code.eitanity.com/kanonarion/internal/walk/adapters/policy/localfile"
	domain2 "code.eitanity.com/kanonarion/internal/walk/domain"

	fetchdomain "code.eitanity.com/kanonarion/internal/fetch/domain"
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

// A stage the walk does not run would load and change nothing, so it is
// refused, naming the file.
func TestLoadPolicy_UnknownStageIsRefused(t *testing.T) {
	yaml := "version: \"1\"\nstages:\n  future_stage:\n    max_depth: 5\n"
	path := writeTempFile(t, yaml)
	_, err := localfile.New(path).LoadPolicy(context.Background())
	if err == nil {
		t.Fatal("LoadPolicy accepted an unknown stage")
	}
	for _, want := range []string{path, `unknown key "stages.future_stage"`} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q does not contain %q", err, want)
		}
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

	target := coordinatetest.MustNew("example.com/m", "v1.0.0")
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

func TestParse_AllowedVCSHostsEmptyIsALoadErrorNamingNoFlag(t *testing.T) {
	src := "version: \"1\"\nstages:\n  fetch:\n    allowed_vcs_hosts: []\n"
	_, err := localfile.Parse([]byte(src))
	if err == nil {
		t.Fatal("expected an explicitly empty allowed_vcs_hosts to fail policy load")
	}
	if !errors.Is(err, fetchdomain.ErrEmptyVCSHostAllowlist) || strings.Contains(err.Error(), "--") {
		t.Errorf("the error must carry the empty-allowlist refusal and name no flag, got %q", err)
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
	for _, stage := range []string{"license", "interface", "callgraph", "example"} {
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

// A misspelt stage is refused before its fields are read, with the stage it
// most likely meant.
func TestParse_UnknownStageIsRefusedWithTheNearestStage(t *testing.T) {
	for src, want := range map[string]string{
		"stages:\n  fecth:\n    max_depth: 5\n":                     `unknown key "stages.fecth" (did you mean "fetch"?)`,
		"stages:\n  fecth:\n    allowed_vcs_hosts: [example.org]\n": `unknown key "stages.fecth" (did you mean "fetch"?)`,
		"stages:\n  future_stage:\n    max_depth: 5\n":              `unknown key "stages.future_stage"`,
	} {
		_, err := localfile.Parse([]byte("version: \"1\"\n" + src))
		if err == nil || err.Error() != want {
			t.Errorf("%q: err = %v, want %s", src, err, want)
		}
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

// A misspelt key at any level is refused with its full path, rather than
// loading and leaving the built-in forges in force.
func TestParse_UnknownKeyAtEveryLevelIsRefused(t *testing.T) {
	for _, tc := range []struct{ body, want string }{
		{"stage:\n  fetch:\n    allowed_vcs_hosts: [example.org]", `unknown key "stage" (did you mean "stages"?)`},
		{"verison: \"1\"", `unknown key "verison" (did you mean "version"?)`},
		{"stages:\n  fetch:\n    allowed_vcs_host: [example.org]", `unknown key "stages.fetch.allowed_vcs_host" (did you mean "allowed_vcs_hosts"?)`},
		{"stages:\n  license:\n    max_dept: 1", `unknown key "stages.license.max_dept" (did you mean "max_depth"?)`},
		{"stages:\n  callgraph:\n    follow_replce: true", `unknown key "stages.callgraph.follow_replce" (did you mean "follow_replace"?)`},
		{"stages:\n  licence:\n    max_depth: 1", `unknown key "stages.licence" (did you mean "license"?)`},
	} {
		_, err := localfile.Parse([]byte("version: \"1\"\n" + tc.body + "\n"))
		if err == nil || err.Error() != tc.want {
			t.Errorf("%q:\n got  %v\n want %s", tc.body, err, tc.want)
		}
	}
}

// Every stage the walk runs is accepted.
func TestParse_EveryKnownStageLoads(t *testing.T) {
	src := "version: \"1\"\nstages:\n"
	for name := range domain2.DefaultDepthPolicy().Stages {
		src += "  " + name + ":\n    max_depth: 2\n"
	}
	p, err := localfile.Parse([]byte(src))
	if err != nil {
		t.Fatal(err)
	}
	if len(p.Stages) != len(domain2.DefaultDepthPolicy().Stages) {
		t.Errorf("stages = %v", p.Stages)
	}
}

// A newer policy is told to upgrade, not refused for the keys it added.
func TestParse_NewerPolicyIsNotRefusedKeyByKey(t *testing.T) {
	_, err := localfile.Parse([]byte("version: \"2\"\nnew_key: 1\n"))
	if err == nil || !strings.Contains(err.Error(), "newer than supported") {
		t.Fatalf("err = %v", err)
	}
}
