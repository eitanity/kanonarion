package sqlite_test

import (
	"context"
	"fmt"
	"testing"

	walkports "github.com/eitanity/kanonarion/internal/walk/ports"
)

// walk-list can now be paged, and the walk listing is ordered started_at DESC.
// Walks of one batch share that timestamp to the second, so without a tiebreak
// the order within a group of equal timestamps is whatever the query plan
// produced: a page boundary falling inside such a group can show a row twice, or
// not at all, while the row counts still look correct. id is the table's primary
// key, so ordering on it after started_at makes the ordering total.
func TestListWalks_PagesPartitionATiedOrdering(t *testing.T) {
	s := openMemStore(t)
	ctx := context.Background()

	const population = 6
	for i := range population {
		// buildWalkRecord fixes started_at, so every one of these ties.
		rec := buildWalkRecord(fmt.Sprintf("01HZTESTPAGING%011d", i))
		if err := s.PutWalk(ctx, rec); err != nil {
			t.Fatalf("PutWalk: %v", err)
		}
	}

	full, err := s.ListWalks(ctx, walkports.WalkFilter{})
	if err != nil {
		t.Fatalf("ListWalks: %v", err)
	}
	if len(full) != population {
		t.Fatalf("unpaged listing holds %d walks, want %d", len(full), population)
	}

	var paged []string
	for offset := 0; offset < population; offset += 2 {
		page, perr := s.ListWalks(ctx, walkports.WalkFilter{Limit: 2, Offset: offset})
		if perr != nil {
			t.Fatalf("page at offset %d: %v", offset, perr)
		}
		for _, w := range page {
			paged = append(paged, w.ID)
		}
	}
	if len(paged) != population {
		t.Fatalf("paging returned %d walks, want %d", len(paged), population)
	}
	for i := range full {
		if paged[i] != full[i].ID {
			t.Errorf("paged walk %d = %s, want %s (the unpaged order)", i, paged[i], full[i].ID)
		}
	}
}

// An offset with no limit is "everything from row N", and the walk listing has
// always spelled the absent cap as LIMIT -1 so SQLite accepts the OFFSET.
func TestListWalks_OffsetWithoutALimit(t *testing.T) {
	s := openMemStore(t)
	ctx := context.Background()

	for i := range 4 {
		if err := s.PutWalk(ctx, buildWalkRecord(fmt.Sprintf("01HZTESTNOLIMIT%010d", i))); err != nil {
			t.Fatalf("PutWalk: %v", err)
		}
	}
	got, err := s.ListWalks(ctx, walkports.WalkFilter{Offset: 2})
	if err != nil {
		t.Fatalf("paging with no limit: %v", err)
	}
	if len(got) != 2 {
		t.Errorf("got %d walks from offset 2 of 4, want 2", len(got))
	}
}
