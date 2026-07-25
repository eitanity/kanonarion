package domain_test

import (
	"bytes"
	"testing"

	domain3 "github.com/eitanity/kanonarion/internal/walk/domain"
)

// policyWithVCSHosts returns the default depth policy with the fetch stage's
// VCS forge allowlist overridden.
func policyWithVCSHosts(hosts []string) domain3.DepthPolicy {
	p := domain3.DefaultDepthPolicy()
	fetch := p.Stages["fetch"]
	fetch.AllowedVCSHosts = &hosts
	p.Stages["fetch"] = fetch
	return p
}

// TestWalkRecordHasher_VCSHostOverrideRoundTrip verifies a configured forge
// allowlist survives the canonical round-trip and is covered by the content
// hash, so the record says which forges the run was willing to clone from.
func TestWalkRecordHasher_VCSHostOverrideRoundTrip(t *testing.T) {
	hasher := domain3.WalkRecordHasher{}
	policy := policyWithVCSHosts([]string{"github.com", "git.example.org"})
	rec := domain3.NewWalkRecord("01ARZ3NDEKTSV4RRFFQ69G5FAV", "ci-bot", "0.2.0",
		domain3.WalkScopeCode, domain3.WalkDepthFull, buildOutcome(t), policy, "")

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
	if !bytes.Contains(data, []byte("allowed_vcs_hosts")) {
		t.Fatalf("a configured allowlist must be covered by the walk hash, got: %s", data)
	}
	back, err := hasher.Unmarshal(data)
	if err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	got := back.StageDepths["fetch"].AllowedVCSHosts
	if got == nil {
		t.Fatal("AllowedVCSHosts lost in the round-trip")
	}
	if len(*got) != 2 || (*got)[0] != "github.com" || (*got)[1] != "git.example.org" {
		t.Errorf("AllowedVCSHosts after round-trip = %v, want [github.com git.example.org]", *got)
	}
}

// TestWalkRecordHasher_AbsentVCSHostsOmitted verifies a policy that does not
// override the allowlist hashes exactly as it did before the field existed.
func TestWalkRecordHasher_AbsentVCSHostsOmitted(t *testing.T) {
	hasher := domain3.WalkRecordHasher{}
	rec, err := hasher.SetContentHash(
		domain3.NewWalkRecord("01ARZ3NDEKTSV4RRFFQ69G5FAV", "ci-bot", "0.2.0",
			domain3.WalkScopeCode, domain3.WalkDepthFull, buildOutcome(t), domain3.DefaultDepthPolicy(), ""),
	)
	if err != nil {
		t.Fatalf("SetContentHash: %v", err)
	}
	data, err := hasher.Marshal(rec)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	if bytes.Contains(data, []byte("allowed_vcs_hosts")) {
		t.Errorf("an absent allowlist must be omitted from canonical JSON, got: %s", data)
	}
	back, err := hasher.Unmarshal(data)
	if err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if back.StageDepths["fetch"].AllowedVCSHosts != nil {
		t.Error("an omitted allowlist must round-trip back to absent, not an empty list")
	}
}

// TestWalkRecordHasher_VCSHostOverrideChangesTheHash proves the override is not
// merely carried alongside the hash but genuinely covered by it: two otherwise
// identical walks with different trusted forges are different records.
func TestWalkRecordHasher_VCSHostOverrideChangesTheHash(t *testing.T) {
	hasher := domain3.WalkRecordHasher{}
	mk := func(policy domain3.DepthPolicy) string {
		rec, err := hasher.SetContentHash(
			domain3.NewWalkRecord("01ARZ3NDEKTSV4RRFFQ69G5FAV", "ci-bot", "0.2.0",
				domain3.WalkScopeCode, domain3.WalkDepthFull, buildOutcome(t), policy, ""),
		)
		if err != nil {
			t.Fatalf("SetContentHash: %v", err)
		}
		return rec.ContentHash
	}
	github := mk(policyWithVCSHosts([]string{"github.com"}))
	gitlab := mk(policyWithVCSHosts([]string{"gitlab.com"}))
	if github == gitlab {
		t.Error("walks trusting different forges must not share a content hash")
	}
}
