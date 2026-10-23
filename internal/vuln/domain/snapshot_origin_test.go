package domain_test

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/eitanity/kanonarion/internal/vuln/domain"
	"github.com/eitanity/kanonarion/internal/vuln/vulntest"
)

// The origin is where the bytes came from, not which database they are: it is
// recorded and read back, but the keyed spelling, the parser and Equal ignore
// it, and a snapshot without one marshals to the bytes it always did.
func TestOrigin_IsRecordedButIsNotIdentity(t *testing.T) {
	t.Parallel()

	at := time.Date(2026, 10, 21, 0, 0, 0, 0, time.UTC)
	hash := domain.HashSnapshotContent([]byte("advisories"))
	base := vulntest.MustSeal("vuln.go.dev", "2026-10-21T00:27:29Z", at, hash)
	const mirror = "https://mirror.example.com/go"

	mirrored, err := base.WithOrigin(mirror)
	if err != nil {
		t.Fatalf("WithOrigin: %v", err)
	}
	if mirrored.Origin() != mirror || base.Origin() != "" {
		t.Fatalf("origins: mirrored %q, base %q", mirrored.Origin(), base.Origin())
	}
	if mirrored.String() != base.String() || !mirrored.Equal(base) {
		t.Error("the origin must not change the keyed spelling or equality")
	}
	if round, perr := domain.ParseDatabaseSnapshot(mirrored.String()); perr != nil || round.Origin() != "" {
		t.Errorf("the parser must not invent an origin: %v, %q", perr, round.Origin())
	}

	plain, err := json.Marshal(base)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(plain), "origin") {
		t.Errorf("a snapshot with no origin must emit the bytes it always did: %s", plain)
	}
	encoded, err := json.Marshal(mirrored)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasSuffix(string(encoded), `,"origin":"`+mirror+`"}`) {
		t.Errorf("the origin must reach the sealed bytes: %s", encoded)
	}
	var back domain.DatabaseSnapshot
	if err := json.Unmarshal(encoded, &back); err != nil {
		t.Fatal(err)
	}
	if back.Origin() != mirror {
		t.Errorf("a stored record must read its origin back, got %q", back.Origin())
	}
}

// Neither the zero snapshot nor an empty origin states where any bytes came from.
func TestWithOrigin_RefusesWhatNamesNothing(t *testing.T) {
	t.Parallel()
	var zero domain.DatabaseSnapshot
	if _, err := zero.WithOrigin("https://mirror.example.com"); err == nil {
		t.Error("the zero snapshot was given an origin")
	}
	if _, err := vulntest.MustNew("vuln.go.dev", "2026-10-21T00:27:29Z").WithOrigin(""); err == nil {
		t.Error("an empty origin was recorded")
	}
}
