package sqlite_test

import (
	"context"
	"slices"
	"testing"
	"time"

	domain2 "github.com/eitanity/kanonarion/internal/example/domain"
)

// PipelinesHeld names every pipeline one coordinate is held at, in version
// order rather than text order, and nothing another coordinate holds.
func TestPipelinesHeld(t *testing.T) {
	ctx := context.Background()
	s := openTestStore(t)
	coord := mustCoord(t, "example.com/mod", "v1.0.0")
	other := mustCoord(t, "example.com/mod", "v1.1.0")
	for _, put := range []struct {
		coord    string
		pipeline string
	}{{"mod", "0.10.0"}, {"mod", "0.9.0"}, {"mod", "0.9.0"}, {"other", "1.4.0"}} {
		c := coord
		if put.coord == "other" {
			c = other
		}
		r := buildRecord(t, c, 1, domain2.ExampleStatusFound)
		r.PipelineVersion = put.pipeline
		r.ExtractedAt = r.ExtractedAt.Add(time.Duration(len(put.pipeline)) * time.Second)
		var h domain2.ExampleRecordHasher
		r, err := h.SetContentHash(r)
		if err != nil {
			t.Fatal(err)
		}
		if err := s.PutExampleRecord(ctx, r); err != nil {
			t.Fatalf("Put: %v", err)
		}
	}
	got, err := s.PipelinesHeld(ctx, coord)
	if err != nil || !slices.Equal(got, []string{"0.9.0", "0.10.0"}) {
		t.Errorf("PipelinesHeld = %v, %v; want [0.9.0 0.10.0]", got, err)
	}
	if got, err := s.PipelinesHeld(ctx, mustCoord(t, "example.com/absent", "v1.0.0")); err != nil || len(got) != 0 {
		t.Errorf("an absent coordinate holds %v, %v", got, err)
	}
	cancelled, cancel := context.WithCancel(ctx)
	cancel()
	if _, err := s.PipelinesHeld(cancelled, coord); err == nil {
		t.Error("a read that cannot run reported no error")
	}
}
