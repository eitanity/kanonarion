package reachability

import (
	"testing"

	"code.eitanity.com/kanonarion/internal/vuln/ports"
)

// A joined graph holds no lowering edge where either half holds none.
func TestJoinedLoweringGap(t *testing.T) {
	for _, tc := range []struct{ consumer, subject, want string }{
		{"", "", ""},
		{"a: gap", "", "a: gap"},
		{"", "b: gap", "b: gap"},
		{"a: gap", "b: gap", "a: gap; b: gap"},
	} {
		got := joinProjections(ports.CallGraphProjection{LoweringGap: tc.consumer}, ports.CallGraphProjection{LoweringGap: tc.subject}, nil, true).LoweringGap
		if got != tc.want {
			t.Errorf("join(%q, %q) = %q, want %q", tc.consumer, tc.subject, got, tc.want)
		}
	}
}
