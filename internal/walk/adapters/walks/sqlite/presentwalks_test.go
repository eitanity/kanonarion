package sqlite_test

import (
	"context"
	"fmt"
	"testing"
)

// PresentWalks is the probe a reader of something that REFERENCES a walk uses
// to say whether the reference still resolves. Nothing in the schema ties a scan
// run to its walk, so a run can outlive the walk it analysed, and the reader has
// to be able to tell.
func TestPresentWalks_SeparatesHeldFromPurged(t *testing.T) {
	s := openMemStore(t)
	ctx := context.Background()

	held := buildWalkRecord("01HZTEST00000000PRESENT001")
	if err := s.PutWalk(ctx, held); err != nil {
		t.Fatalf("PutWalk: %v", err)
	}

	got, err := s.PresentWalks(ctx, []string{held.ID, "01HZTEST00000000PURGED0001"})
	if err != nil {
		t.Fatalf("PresentWalks: %v", err)
	}
	if !got[held.ID] {
		t.Errorf("a stored walk reports as absent")
	}
	// Every id asked about is a key of the result, so a caller never has to read
	// absence out of a missing map entry.
	present, asked := got["01HZTEST00000000PURGED0001"]
	if !asked {
		t.Errorf("an id that was asked about is missing from the result")
	}
	if present {
		t.Errorf("a walk that was never stored reports as present")
	}
}

func TestPresentWalks_EmptyInputAsksNothing(t *testing.T) {
	s := openMemStore(t)
	got, err := s.PresentWalks(context.Background(), nil)
	if err != nil {
		t.Fatalf("PresentWalks: %v", err)
	}
	if len(got) != 0 {
		t.Errorf("got %v, want an empty result", got)
	}
}

// The probe is chunked under SQLite's bound-parameter cap, so a listing larger
// than one chunk must still classify every id.
func TestPresentWalks_ChunksBeyondTheParameterLimit(t *testing.T) {
	s := openMemStore(t)
	ctx := context.Background()

	const total = 900
	ids := make([]string, 0, total)
	for i := range total {
		id := fmt.Sprintf("01HZTESTCHUNK%013d", i)
		ids = append(ids, id)
		// Every other walk is stored, so a chunk boundary cannot hide behind a
		// uniform answer.
		if i%2 == 0 {
			rec := buildWalkRecord(id)
			if err := s.PutWalk(ctx, rec); err != nil {
				t.Fatalf("PutWalk %s: %v", id, err)
			}
		}
	}

	got, err := s.PresentWalks(ctx, ids)
	if err != nil {
		t.Fatalf("PresentWalks: %v", err)
	}
	if len(got) != total {
		t.Fatalf("classified %d ids, want %d", len(got), total)
	}
	for i, id := range ids {
		want := i%2 == 0
		if got[id] != want {
			t.Fatalf("%s: present = %v, want %v", id, got[id], want)
		}
	}
}
