package domain_test

import (
	"testing"

	"github.com/eitanity/kanonarion/internal/godebug/domain"
)

// TestSortDeterministicAndHashStable asserts Sort yields a total order and
// Hash is invariant to input permutation once sorted.
func TestSortDeterministicAndHashStable(t *testing.T) {
	a := []domain.Setting{
		{Name: "tlsrsakex", Source: "main.go", Line: 4, Tier: domain.TierRed},
		{Name: "http2client", Source: "main.go", Line: 4, Tier: domain.TierAmber},
		{Name: "asynctimerchan", Source: "a.go", Line: 2, Tier: domain.TierGreen},
	}
	b := []domain.Setting{a[2], a[0], a[1]}

	domain.Sort(a)
	domain.Sort(b)
	if domain.Hash(a) != domain.Hash(b) {
		t.Fatalf("hash not permutation-invariant after Sort:\n a=%v\n b=%v", a, b)
	}
	// a.go:2 sorts before main.go:4; within main.go:4, http2client < tlsrsakex.
	if a[0].Source != "a.go" || a[1].Name != "http2client" || a[2].Name != "tlsrsakex" {
		t.Errorf("unexpected order: %+v", a)
	}
}
