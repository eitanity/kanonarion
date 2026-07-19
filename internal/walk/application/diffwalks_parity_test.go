package application

import (
	"strings"
	"testing"

	"github.com/eitanity/kanonarion/internal/walk/domain"
)

func walkWith(id string, scope domain.WalkScope, depth domain.WalkDepth) domain.WalkRecord {
	return domain.WalkRecord{ID: id, Scope: scope, Depth: depth}
}

// TestDiffRecords_CompletenessMismatch asserts the walk diff flags an asymmetric
// comparison when the two walks were resolved at a different scope or depth, and
// stays clean when they match.
func TestDiffRecords_CompletenessMismatch(t *testing.T) {
	cases := []struct {
		name       string
		a, b       domain.WalkRecord
		wantSubstr string // "" means no mismatch expected
	}{
		{
			name: "same scope and depth",
			a:    walkWith("a", domain.WalkScopeCode, domain.WalkDepthFull),
			b:    walkWith("b", domain.WalkScopeCode, domain.WalkDepthFull),
		},
		{
			name:       "scope differs",
			a:          walkWith("a", domain.WalkScopeCode, domain.WalkDepthFull),
			b:          walkWith("b", domain.WalkScopeComplete, domain.WalkDepthFull),
			wantSubstr: "walk scope differs",
		},
		{
			name:       "depth differs",
			a:          walkWith("a", domain.WalkScopeCode, domain.WalkDepthFull),
			b:          walkWith("b", domain.WalkScopeCode, domain.WalkDepthShallow),
			wantSubstr: "walk depth differs",
		},
		{
			name: "empty depth equals full",
			a:    walkWith("a", domain.WalkScopeCode, ""),
			b:    walkWith("b", domain.WalkScopeCode, domain.WalkDepthFull),
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := diffRecords(tc.a, tc.b).CompletenessMismatch
			if tc.wantSubstr == "" {
				if got != "" {
					t.Fatalf("expected no mismatch, got %q", got)
				}
				return
			}
			if !strings.Contains(got, tc.wantSubstr) {
				t.Fatalf("expected mismatch mentioning %q, got %q", tc.wantSubstr, got)
			}
		})
	}
}
