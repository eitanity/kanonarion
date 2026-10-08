package fetchtest

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"testing"
	"time"

	"github.com/eitanity/kanonarion/internal/fetch/domain"
)

// Respelt returns the row a build spelling fetched_at as a trimmed fraction
// would have stored for r, a whole-second record: the stored text, and the seal
// taken over it. Its stored values hash to that seal, and this build, which
// spells the parsed time at full width, cannot reproduce it.
func Respelt(t testing.TB, r domain.FactRecord) (fetchedAt, seal string) {
	t.Helper()
	if r.FetchedAt.Nanosecond() != 0 {
		t.Fatalf("fetchtest: Respelt needs a whole-second record, got %s", r.FetchedAt)
	}
	unsealed := r
	unsealed.ContentHash = ""
	raw, err := domain.CanonicalHasher{}.Marshal(unsealed)
	if err != nil {
		t.Fatalf("fetchtest: marshalling: %v", err)
	}
	stored := r.FetchedAt.UTC().Format(time.RFC3339)
	fetchedAt = stored[:len(stored)-1] + ".5Z"
	from := []byte(`"fetched_at":"` + stored + `"`)
	if bytes.Count(raw, from) != 1 {
		t.Fatalf("fetchtest: record has %d fetched_at fields, want 1", bytes.Count(raw, from))
	}
	sum := sha256.Sum256(bytes.Replace(raw, from, []byte(`"fetched_at":"`+fetchedAt+`"`), 1))
	return fetchedAt, "sha256:" + hex.EncodeToString(sum[:])
}
