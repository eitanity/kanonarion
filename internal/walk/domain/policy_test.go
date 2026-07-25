package domain_test

import (
	"testing"

	"github.com/eitanity/kanonarion/internal/walk/domain"
)

func TestDefaultDepthPolicy(t *testing.T) {
	p := domain.DefaultDepthPolicy()
	if p.Version != domain.PolicySchemaVersion {
		t.Errorf("Version = %q, want %q", p.Version, domain.PolicySchemaVersion)
	}
	fetch := p.Stages["fetch"]
	if fetch.MaxDepth != 0 {
		t.Errorf("fetch.MaxDepth = %d, want 0 (unlimited)", fetch.MaxDepth)
	}
	if !fetch.FollowReplace {
		t.Error("fetch.FollowReplace = false, want true")
	}
	if fetch.FollowTest {
		t.Error("fetch.FollowTest = true, want false")
	}
	if !fetch.FollowIndirect {
		t.Error("fetch.FollowIndirect = false, want true")
	}
}

func TestDepthPolicy_FetchStage_Present(t *testing.T) {
	p := domain.DepthPolicy{
		Version: "1",
		Stages: map[string]domain.StageDepth{
			"fetch": {MaxDepth: 3, FollowReplace: false},
		},
	}
	sd := p.FetchStage()
	if sd.MaxDepth != 3 {
		t.Errorf("MaxDepth = %d, want 3", sd.MaxDepth)
	}
	if sd.FollowReplace {
		t.Error("FollowReplace = true, want false")
	}
}

func TestDepthPolicy_FetchStage_Absent(t *testing.T) {
	// A policy with no fetch stage falls back to defaults.
	p := domain.DepthPolicy{
		Version: "1",
		Stages:  map[string]domain.StageDepth{},
	}
	sd := p.FetchStage()
	defaults := domain.DefaultDepthPolicy().Stages["fetch"]
	if sd != defaults {
		t.Errorf("FetchStage() = %+v, want default %+v", sd, defaults)
	}
}

func TestStageDepth_VCSHostAllowlist_AbsentFieldYieldsBuiltInDefault(t *testing.T) {
	// The default policy does not pin the trust list, so every stage resolves to
	// the built-in set — the behaviour every pre-existing policy file relies on.
	hosts, err := domain.DefaultDepthPolicy().FetchStage().VCSHostAllowlist()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !hosts.IsDefault() {
		t.Errorf("expected the built-in default set, got %v", hosts.Hosts())
	}
}

func TestStageDepth_VCSHostAllowlist_PresentFieldOverrides(t *testing.T) {
	hostList := []string{"github.com"}
	sd := domain.StageDepth{AllowedVCSHosts: &hostList}
	hosts, err := sd.VCSHostAllowlist()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !hosts.IsAllowed("github.com") {
		t.Error("the configured forge should be allowed")
	}
	if hosts.IsAllowed("gitlab.com") {
		t.Error("a forge left out of the override must not be allowed")
	}
}

func TestStageDepth_VCSHostAllowlist_UnusableListIsAnErrorNotAFallback(t *testing.T) {
	// Falling back to the default would verify against a forge set the operator
	// did not authorise and report the run as clean.
	for name, hostList := range map[string][]string{
		"empty":     {},
		"malformed": {"https://github.com"},
	} {
		t.Run(name, func(t *testing.T) {
			list := hostList
			sd := domain.StageDepth{AllowedVCSHosts: &list}
			if _, err := sd.VCSHostAllowlist(); err == nil {
				t.Fatal("expected an unusable allowed_vcs_hosts list to error")
			}
		})
	}
}
