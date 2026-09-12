package cli

import (
	"strings"
	"testing"

	extextractor "github.com/eitanity/kanonarion/internal/extract/adapters/extractor/local"
)

// TestDescribeCallgraphBound covers the run's own statement of the bound it
// adopted. The count on its own is not readable — four is the healthy default
// and is also what a starved host gets — so each arm must name what decided it.
func TestDescribeCallgraphBound(t *testing.T) {
	cases := []struct {
		name  string
		bound extextractor.CallgraphBound
		want  []string
		avoid []string
	}{
		{
			name:  "the operator's own value says so",
			bound: extextractor.CallgraphBound{Workers: 8, Requested: true, CPUCap: 4},
			want:  []string{"8 at once", "--callgraph-workers"},
			avoid: []string{"available"},
		},
		{
			name: "a host-sized bound names the reading and the budget",
			bound: extextractor.CallgraphBound{
				Workers: 4, BudgetBytes: 4 << 30, AvailableBytes: 55 << 30, AvailableKnown: true, CPUCap: 4,
			},
			want: []string{"4 at once", "55.0 GiB available", "4.0 GiB budgeted each", "CPU cap 4"},
		},
		{
			name:  "a host that cannot be read says that, not zero bytes",
			bound: extextractor.CallgraphBound{Workers: 4, BudgetBytes: 4 << 30, CPUCap: 4},
			want:  []string{"4 at once", "does not report available memory"},
			avoid: []string{"0.0 GiB available"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := describeCallgraphBound(tc.bound)
			for _, w := range tc.want {
				if !strings.Contains(got, w) {
					t.Errorf("the line does not say %q: %s", w, got)
				}
			}
			for _, a := range tc.avoid {
				if strings.Contains(got, a) {
					t.Errorf("the line says %q, which does not describe this bound: %s", a, got)
				}
			}
		})
	}
}
