package sqlite_test

import (
	"context"
	"testing"
)

// TestPutGetWalk_ProjectDirRoundTrips asserts the directory a walk was taken
// from survives storage. It rides in its own column rather than in the sealed
// blob, so nothing in the marshal/verify path carries it and this is the only
// thing that proves it comes back.
func TestPutGetWalk_ProjectDirRoundTrips(t *testing.T) {
	s := openMemStore(t)
	ctx := context.Background()

	rec := buildWalkRecord("01HZTEST0000000000PROJDIR")
	rec.ProjectDir = "/home/alice/src/proj"
	if err := s.PutWalk(ctx, rec); err != nil {
		t.Fatalf("PutWalk: %v", err)
	}

	got, err := s.GetWalk(ctx, rec.ID)
	if err != nil {
		t.Fatalf("GetWalk: %v", err)
	}
	if got.ProjectDir != rec.ProjectDir {
		t.Errorf("ProjectDir: got %q, want %q", got.ProjectDir, rec.ProjectDir)
	}
	// The column must not have disturbed the seal: the record still verifies, and
	// a directory that changed the stored hash would mean the field had become
	// identity after all.
	if got.ContentHash != rec.ContentHash {
		t.Errorf("ContentHash: got %q, want %q", got.ContentHash, rec.ContentHash)
	}
}

// TestPutGetWalk_NoProjectDirReadsEmpty covers the walk of a published
// coordinate, which has no project root, and every row written before the
// column existed. Both mean "no project directory", and neither may fail to
// read.
func TestPutGetWalk_NoProjectDirReadsEmpty(t *testing.T) {
	s := openMemStore(t)
	ctx := context.Background()

	rec := buildWalkRecord("01HZTEST000000000NOPROJDIR")
	if err := s.PutWalk(ctx, rec); err != nil {
		t.Fatalf("PutWalk: %v", err)
	}

	got, err := s.GetWalk(ctx, rec.ID)
	if err != nil {
		t.Fatalf("GetWalk: %v", err)
	}
	if got.ProjectDir != "" {
		t.Errorf("ProjectDir: got %q, want empty", got.ProjectDir)
	}
}
