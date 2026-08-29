package domain_test

import (
	"testing"

	"github.com/eitanity/kanonarion/internal/sbom/domain"
)

// TestComponentCompare_IsKeyedOnEveryField exercises the component comparator
// against every field a Component carries. The coordinate is not an identity: a
// graph can present one coordinate twice, once as itself and once as the target
// of a replace, and the two carry different licence facts.
func TestComponentCompare_IsKeyedOnEveryField(t *testing.T) {
	t.Parallel()

	cases := []struct {
		key          string
		lower, upper domain.Component
	}{
		{"module.path", domain.Component{Module: domain.ModuleRef{Path: "a"}}, domain.Component{Module: domain.ModuleRef{Path: "b"}}},
		{"module.version", domain.Component{Module: domain.ModuleRef{Version: "v1"}}, domain.Component{Module: domain.ModuleRef{Version: "v2"}}},
		{"license", domain.Component{License: "Apache-2.0"}, domain.Component{License: "MIT"}},
		{"copyright", domain.Component{Copyright: "a"}, domain.Component{Copyright: "b"}},
	}
	for _, tc := range cases {
		if got := domain.ComponentCompare(tc.lower, tc.upper); got >= 0 {
			t.Errorf("%s: the comparator does not order two components differing only here: got %d", tc.key, got)
		}
		if got := domain.ComponentCompare(tc.upper, tc.lower); got <= 0 {
			t.Errorf("%s: the comparator is not antisymmetric: got %d", tc.key, got)
		}
		if got := domain.ComponentCompare(tc.lower, tc.lower); got != 0 {
			t.Errorf("%s: the comparator does not report a component equal to itself: got %d", tc.key, got)
		}
	}
}
