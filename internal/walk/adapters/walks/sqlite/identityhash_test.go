package sqlite_test

import (
	"context"
	"testing"

	walkports "github.com/eitanity/kanonarion/internal/walk/ports"
)

// TestPutGetWalk_IdentityHashRoundTrips asserts the analysis identity survives
// storage. Like the project directory it rides in its own column rather than in
// the sealed blob, so nothing in the marshal/verify path carries it and this is
// the only thing that proves it comes back.
func TestPutGetWalk_IdentityHashRoundTrips(t *testing.T) {
	s := openMemStore(t)
	ctx := context.Background()

	rec := buildWalkRecord("01HZTEST00000000IDENTITY01")
	rec.IdentityHash = "sha256:1111111111111111111111111111111111111111111111111111111111111111"
	if err := s.PutWalk(ctx, rec); err != nil {
		t.Fatalf("PutWalk: %v", err)
	}

	got, err := s.GetWalk(ctx, rec.ID)
	if err != nil {
		t.Fatalf("GetWalk: %v", err)
	}
	if got.IdentityHash != rec.IdentityHash {
		t.Errorf("IdentityHash: got %q, want %q", got.IdentityHash, rec.IdentityHash)
	}
	// The column must not have disturbed the seal. If the identity ever joined
	// the content hash, the hash would cover a function of itself and every walk
	// written before the field existed would stop verifying.
	if got.ContentHash != rec.ContentHash {
		t.Errorf("ContentHash: got %q, want %q", got.ContentHash, rec.ContentHash)
	}
}

// TestListWalks_FiltersByIdentityHash is the lookup reuse depends on: given the
// identity of the analysis just performed, find the walk that already recorded
// it.
func TestListWalks_FiltersByIdentityHash(t *testing.T) {
	s := openMemStore(t)
	ctx := context.Background()

	const wanted = "sha256:2222222222222222222222222222222222222222222222222222222222222222"

	match := buildWalkRecord("01HZTEST00000000IDENTITY02")
	match.IdentityHash = wanted
	if err := s.PutWalk(ctx, match); err != nil {
		t.Fatalf("PutWalk: %v", err)
	}
	other := buildWalkRecord("01HZTEST00000000IDENTITY03")
	other.IdentityHash = "sha256:3333333333333333333333333333333333333333333333333333333333333333"
	if err := s.PutWalk(ctx, other); err != nil {
		t.Fatalf("PutWalk: %v", err)
	}

	identity := wanted
	got, err := s.ListWalks(ctx, walkports.WalkFilter{IdentityHash: &identity})
	if err != nil {
		t.Fatalf("ListWalks: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("ListWalks returned %d walks, want 1", len(got))
	}
	if got[0].ID != match.ID {
		t.Errorf("ListWalks returned %s, want %s", got[0].ID, match.ID)
	}
	if got[0].IdentityHash != wanted {
		t.Errorf("summary IdentityHash = %q, want %q", got[0].IdentityHash, wanted)
	}
}

// TestPutGetWalk_NoIdentityHashReadsEmpty covers every row written before the
// column existed. Empty is an ABSENT identity, never a matching one — a lookup
// that treated it as a hit would serve an arbitrary old walk for any analysis.
func TestPutGetWalk_NoIdentityHashReadsEmpty(t *testing.T) {
	s := openMemStore(t)
	ctx := context.Background()

	rec := buildWalkRecord("01HZTEST0000000NOIDENTITY0")
	if err := s.PutWalk(ctx, rec); err != nil {
		t.Fatalf("PutWalk: %v", err)
	}

	got, err := s.GetWalk(ctx, rec.ID)
	if err != nil {
		t.Fatalf("GetWalk: %v", err)
	}
	if got.IdentityHash != "" {
		t.Errorf("IdentityHash: got %q, want empty", got.IdentityHash)
	}
}
