package domain_test

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/eitanity/kanonarion/internal/vuln/domain"
	"github.com/eitanity/kanonarion/internal/vuln/vulntest"
)

// A count is a measurement, and only a positive one is a measurement worth
// recording. Zero is what every snapshot written before the field existed
// already carries, so admitting a measured zero would make an empty advisory
// database indistinguishable from an unmeasured one on the way back out.
func TestWithAdvisoryCount_OnlyAdmitsAPositiveCount(t *testing.T) {
	t.Parallel()

	base := vulntest.MustNew("vuln.go.dev", "2026-07-30T00:00:00Z")

	t.Run("a positive count is recorded", func(t *testing.T) {
		t.Parallel()
		counted, err := base.WithAdvisoryCount(6027)
		if err != nil {
			t.Fatalf("WithAdvisoryCount: %v", err)
		}
		if got := counted.AdvisoryCount(); got != 6027 {
			t.Errorf("expected the count to be readable back, got %d", got)
		}
		if base.AdvisoryCount() != 0 {
			t.Error("the receiver must not be mutated: a value object returns a new value")
		}
	})

	for _, count := range []int{0, -1} {
		t.Run(fmt.Sprintf("a count of %d is refused", count), func(t *testing.T) {
			t.Parallel()
			if _, err := base.WithAdvisoryCount(count); err == nil {
				t.Fatalf("a count of %d must be refused: it is indistinguishable from never having measured", count)
			}
		})
	}

	t.Run("the zero snapshot cannot be counted", func(t *testing.T) {
		t.Parallel()
		var zero domain.DatabaseSnapshot
		if _, err := zero.WithAdvisoryCount(10); err == nil {
			t.Fatal("stating a measurement about a value that names no database describes nothing")
		}
	})
}

// The count is a reading of the bytes the content hash already pins, so it is
// not identity: it must not reach the keyed spelling, the parser, or Equal. If
// it did, one snapshot would key two composition groups depending on whether the
// run that wrote it happened to have measured the database.
func TestAdvisoryCount_IsNotIdentity(t *testing.T) {
	t.Parallel()

	at := time.Date(2026, 7, 30, 12, 0, 0, 0, time.UTC)
	base := vulntest.MustNewAt("vuln.go.dev", "2026-07-30T00:00:00Z", at)
	counted, err := base.WithAdvisoryCount(6027)
	if err != nil {
		t.Fatalf("WithAdvisoryCount: %v", err)
	}

	if base.String() != counted.String() {
		t.Errorf("the keyed spelling must not change with the count:\n  uncounted %q\n  counted   %q", base.String(), counted.String())
	}
	if !base.Equal(counted) {
		t.Error("two readings of one snapshot's bytes must compare equal whether or not one of them was counted")
	}
	round, err := domain.ParseDatabaseSnapshot(counted.String())
	if err != nil {
		t.Fatalf("ParseDatabaseSnapshot: %v", err)
	}
	if round.AdvisoryCount() != 0 {
		t.Errorf("the parser must not invent a count the spelling never carried, got %d", round.AdvisoryCount())
	}
}

// The sealed shape is what every stored record's content hash was taken over, so
// an uncounted snapshot must marshal to exactly the four fields it always did. A
// counted one adds the fifth and reads it back, which is what lets a later
// reader tell a clean scan against six thousand advisories from one against
// three.
func TestAdvisoryCount_IsHashTransparentUntilMeasured(t *testing.T) {
	t.Parallel()

	at := time.Date(2026, 7, 30, 12, 0, 0, 0, time.UTC)
	hash := domain.HashSnapshotContent([]byte("advisories"))
	base := vulntest.MustSeal("vuln.go.dev", "2026-07-30T00:00:00Z", at, hash)

	uncounted, err := json.Marshal(base)
	if err != nil {
		t.Fatalf("marshalling the uncounted snapshot: %v", err)
	}
	want := fmt.Sprintf(
		`{"source":"vuln.go.dev","version":"2026-07-30T00:00:00Z","retrieved_at":"2026-07-30T12:00:00Z","content_hash":%q}`,
		hash)
	if string(uncounted) != want {
		t.Errorf("shape drift: an unmeasured snapshot must emit exactly the four fields it always did, or every already-sealed record stops verifying\n got %s\nwant %s", uncounted, want)
	}

	counted, err := base.WithAdvisoryCount(6027)
	if err != nil {
		t.Fatalf("WithAdvisoryCount: %v", err)
	}
	encoded, err := json.Marshal(counted)
	if err != nil {
		t.Fatalf("marshalling the counted snapshot: %v", err)
	}
	if !strings.Contains(string(encoded), `"advisory_count":6027`) {
		t.Errorf("a measured snapshot must carry its count into the sealed bytes: %s", encoded)
	}

	var back domain.DatabaseSnapshot
	if err := json.Unmarshal(encoded, &back); err != nil {
		t.Fatalf("unmarshalling the counted snapshot: %v", err)
	}
	if back.AdvisoryCount() != 6027 {
		t.Errorf("a stored record must read its count back, got %d", back.AdvisoryCount())
	}
	if !back.Equal(counted) {
		t.Error("the counted snapshot must round-trip through its persisted form")
	}
}
