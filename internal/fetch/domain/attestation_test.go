package domain_test

import (
	"testing"

	"github.com/eitanity/kanonarion/internal/fetch/domain"
)

func TestContentDigest_Deterministic(t *testing.T) {
	t.Parallel()

	data := []byte("module zip bytes")
	got := domain.ContentDigest(data)

	if got != domain.ContentDigest(data) {
		t.Fatalf("ContentDigest not deterministic")
	}
	if got[:7] != "sha256:" {
		t.Errorf("ContentDigest = %q, want sha256: prefix", got)
	}
	if domain.ContentDigest([]byte("other")) == got {
		t.Errorf("distinct inputs produced the same digest")
	}
}

func TestSortAttestations_OrdersByKindThenDigest(t *testing.T) {
	t.Parallel()

	records := []domain.AttestationRecord{
		{SubjectKind: domain.SubjectFact, SubjectDigest: "bbbb"},
		{SubjectKind: domain.SubjectBlob, SubjectDigest: "cccc"},
		{SubjectKind: domain.SubjectFact, SubjectDigest: "aaaa"},
		{SubjectKind: domain.SubjectBlob, SubjectDigest: "aaaa"},
	}
	domain.SortAttestations(records)

	want := []struct {
		kind   domain.SubjectKind
		digest string
	}{
		{domain.SubjectBlob, "aaaa"},
		{domain.SubjectBlob, "cccc"},
		{domain.SubjectFact, "aaaa"},
		{domain.SubjectFact, "bbbb"},
	}
	for i, w := range want {
		if records[i].SubjectKind != w.kind || records[i].SubjectDigest != w.digest {
			t.Errorf("record[%d] = (%s, %s), want (%s, %s)",
				i, records[i].SubjectKind, records[i].SubjectDigest, w.kind, w.digest)
		}
	}
}
