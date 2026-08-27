package domain_test

import (
	"testing"
	"time"

	"github.com/eitanity/kanonarion/internal/coordinate"
	"github.com/eitanity/kanonarion/internal/fetch/domain"
)

// assertOrders checks that less decides a pair differing in exactly one field,
// in both directions, and reports an element equal to itself. Together over
// every field the element carries, that is what "total order" means: no two
// DISTINCT elements compare equal, so the sort has no tie to resolve.
func assertOrders[T any](t *testing.T, key string, less func(a, b T) bool, lower, upper T) {
	t.Helper()
	if !less(lower, upper) {
		t.Errorf("%s: the comparator does not order two elements differing only in this field", key)
	}
	if less(upper, lower) {
		t.Errorf("%s: the comparator is not antisymmetric", key)
	}
	if less(lower, lower) {
		t.Errorf("%s: the comparator reports an element less than itself", key)
	}
}

// TestAttestationRecordLess_IsKeyedOnEveryField exercises the attestation
// comparator against every field a record carries. One subject can be attested
// more than once — a second signer, or the same signer after a key rotation —
// so the subject is not an identity.
func TestAttestationRecordLess_IsKeyedOnEveryField(t *testing.T) {
	t.Parallel()

	coordA, err := coordinate.NewModuleCoordinate("example.com/a", "v1.0.0")
	if err != nil {
		t.Fatal(err)
	}
	coordB, err := coordinate.NewModuleCoordinate("example.com/b", "v1.0.0")
	if err != nil {
		t.Fatal(err)
	}
	coordA2, err := coordinate.NewModuleCoordinate("example.com/a", "v2.0.0")
	if err != nil {
		t.Fatal(err)
	}
	early := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	late := time.Date(2026, 2, 1, 0, 0, 0, 0, time.UTC)

	assertOrders(t, "subject_kind", domain.AttestationRecordLess,
		domain.AttestationRecord{SubjectKind: "a"}, domain.AttestationRecord{SubjectKind: "b"})
	assertOrders(t, "subject_digest", domain.AttestationRecordLess,
		domain.AttestationRecord{SubjectDigest: "a"}, domain.AttestationRecord{SubjectDigest: "b"})
	assertOrders(t, "subject_algorithm", domain.AttestationRecordLess,
		domain.AttestationRecord{SubjectAlgorithm: "a"}, domain.AttestationRecord{SubjectAlgorithm: "b"})
	assertOrders(t, "coordinate.path", domain.AttestationRecordLess,
		domain.AttestationRecord{Coordinate: coordA}, domain.AttestationRecord{Coordinate: coordB})
	assertOrders(t, "coordinate.version", domain.AttestationRecordLess,
		domain.AttestationRecord{Coordinate: coordA}, domain.AttestationRecord{Coordinate: coordA2})
	assertOrders(t, "pipeline_version", domain.AttestationRecordLess,
		domain.AttestationRecord{PipelineVersion: "a"}, domain.AttestationRecord{PipelineVersion: "b"})
	assertOrders(t, "signed_at", domain.AttestationRecordLess,
		domain.AttestationRecord{SignedAt: early}, domain.AttestationRecord{SignedAt: late})
	assertOrders(t, "bundle", domain.AttestationRecordLess,
		domain.AttestationRecord{Bundle: []byte("a")}, domain.AttestationRecord{Bundle: []byte("b")})
}

// TestForkIndicatorLess_IsKeyedOnEveryField exercises the fork-indicator
// comparator against both fields it carries.
func TestForkIndicatorLess_IsKeyedOnEveryField(t *testing.T) {
	t.Parallel()

	assertOrders(t, "canonical", domain.ForkIndicatorLess,
		domain.ForkIndicator{Canonical: "a"}, domain.ForkIndicator{Canonical: "b"})
	assertOrders(t, "statement", domain.ForkIndicatorLess,
		domain.ForkIndicator{Statement: "a"}, domain.ForkIndicator{Statement: "b"})
}
