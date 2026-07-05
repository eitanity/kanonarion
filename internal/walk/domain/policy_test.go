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
