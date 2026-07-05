package domain_test

import (
	"testing"

	"github.com/eitanity/kanonarion/internal/directive/domain"
)

// TestClassify covers every rule, including the fail-safe:
// an exclude with an unknown/invalid resolved version must NOT be treated as
// the benign older-than case.
func TestClassify(t *testing.T) {
	tests := []struct {
		name     string
		d        domain.Directive
		resolved string
		want     domain.RiskClass
	}{
		{"local replace highest",
			domain.Directive{Kind: domain.KindReplace, IsLocal: true, LocalPath: "../x", OldPath: "x"},
			"", domain.RiskHighest},
		{"fork replace high",
			domain.Directive{Kind: domain.KindReplace, OldPath: "a", NewPath: "b", NewVersion: "v1.0.0"},
			"", domain.RiskHigh},
		{"version replace medium",
			domain.Directive{Kind: domain.KindReplace, OldPath: "a", NewPath: "a", NewVersion: "v1.2.0"},
			"", domain.RiskMedium},
		{"version replace medium (empty new path = same module)",
			domain.Directive{Kind: domain.KindReplace, OldPath: "a", NewVersion: "v1.2.0"},
			"", domain.RiskMedium},
		{"exclude newer than resolved high",
			domain.Directive{Kind: domain.KindExclude, OldPath: "a", OldVersion: "v1.3.0"},
			"v1.2.0", domain.RiskHigh},
		{"exclude older than resolved low",
			domain.Directive{Kind: domain.KindExclude, OldPath: "a", OldVersion: "v1.1.0"},
			"v1.2.0", domain.RiskLow},
		{"exclude unknown resolved fails safe to high",
			domain.Directive{Kind: domain.KindExclude, OldPath: "a", OldVersion: "v1.1.0"},
			"", domain.RiskHigh},
		{"exclude invalid semver fails safe to high",
			domain.Directive{Kind: domain.KindExclude, OldPath: "a", OldVersion: "not-semver"},
			"v1.2.0", domain.RiskHigh},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := domain.Classify(tt.d, tt.resolved); got != tt.want {
				t.Errorf("Classify() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestReachabilityTargetOf(t *testing.T) {
	cases := map[string]struct {
		d    domain.Directive
		want string
	}{
		"local":          {domain.Directive{Kind: domain.KindReplace, IsLocal: true, LocalPath: "../fork"}, "../fork"},
		"fork":           {domain.Directive{Kind: domain.KindReplace, OldPath: "a", NewPath: "b"}, "b"},
		"same":           {domain.Directive{Kind: domain.KindReplace, OldPath: "a"}, "a"},
		"exclude (none)": {domain.Directive{Kind: domain.KindExclude, OldPath: "a"}, ""},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			if got := domain.ReachabilityTargetOf(c.d); got != c.want {
				t.Errorf("ReachabilityTargetOf() = %q, want %q", got, c.want)
			}
		})
	}
}

// TestSortAndHashDeterministic guards the determinism invariant:
// the same directive set in any input order hashes identically after Sort.
func TestSortAndHashDeterministic(t *testing.T) {
	a := []domain.Directive{
		{Kind: domain.KindExclude, Source: "go.mod", Line: 9, OldPath: "z"},
		{Kind: domain.KindReplace, Source: "go.mod", Line: 3, OldPath: "a"},
	}
	b := []domain.Directive{
		{Kind: domain.KindReplace, Source: "go.mod", Line: 3, OldPath: "a"},
		{Kind: domain.KindExclude, Source: "go.mod", Line: 9, OldPath: "z"},
	}
	domain.Sort(a)
	domain.Sort(b)
	if domain.Hash(a) != domain.Hash(b) {
		t.Fatalf("hash not order-independent after Sort: %s vs %s", domain.Hash(a), domain.Hash(b))
	}
}
