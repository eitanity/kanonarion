package sqlite_test

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/eitanity/kanonarion/internal/tinygo/adapters/store/sqlite"
	"github.com/eitanity/kanonarion/internal/tinygo/domain"
)

const hexA = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

func open(t *testing.T) *sqlite.Store {
	t.Helper()
	s, err := sqlite.Open(":memory:")
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() }) //nolint:errcheck // test teardown
	return s
}

func measurement(at time.Time) domain.Measurement {
	return domain.Measurement{
		Version: "0.42.0", Asset: "tinygo0.42.0.linux-amd64.tar.gz", URL: "https://example.invalid/tgz",
		PublishedDigest: hexA, ObservedDigest: hexA, Outcome: domain.DigestMatched, MeasuredAt: at,
		Manifest: []domain.ManifestEntry{{Path: "device/rp/rp2040.go", SHA256: hexA}, {Path: "machine/machine.go", SHA256: hexA}},
	}
}

func TestStore_RoundTrip(t *testing.T) {
	s, ctx := open(t), context.Background()
	if _, ok, err := s.Latest(ctx, "0.42.0", "tinygo0.42.0.linux-amd64.tar.gz"); ok || err != nil {
		t.Fatalf("an empty store answered %v, %v", ok, err)
	}
	first := measurement(time.Date(2026, 10, 23, 2, 0, 0, 123, time.UTC))
	second := first
	second.MeasuredAt, second.Outcome, second.ObservedDigest, second.Manifest = first.MeasuredAt.Add(time.Hour), domain.DigestMismatch, strings.Repeat("b", 64), nil
	second.Reason = "hashes to b…"
	for _, m := range []domain.Measurement{first, first, second} {
		if err := s.Append(ctx, m); err != nil {
			t.Fatalf("Append: %v", err)
		}
	}
	got, ok, err := s.Latest(ctx, first.Version, first.Asset)
	if err != nil || !ok || !reflect.DeepEqual(got, second) {
		t.Errorf("Latest = %+v, %v, %v; want the measurement appended last %+v", got, ok, err, second)
	}
	if _, ok, err := s.Latest(ctx, "0.41.0", first.Asset); ok || err != nil {
		t.Errorf("another release answered: %v, %v", ok, err)
	}
}

func TestStore_ServesTheLatestMatch(t *testing.T) {
	s, ctx := open(t), context.Background()
	m := measurement(time.Date(2026, 10, 23, 2, 0, 0, 0, time.UTC))
	if err := s.Append(ctx, m); err != nil {
		t.Fatal(err)
	}
	got, _, err := s.Latest(ctx, m.Version, m.Asset)
	if err != nil || !reflect.DeepEqual(got, m) {
		t.Errorf("Latest = %+v, %v; want %+v", got, err, m)
	}
}

func TestStore_RefusesAnIncompleteMeasurement(t *testing.T) {
	if err := open(t).Append(context.Background(), domain.Measurement{}); !errors.Is(err, domain.ErrIncomplete) {
		t.Errorf("Append(zero) = %v, want ErrIncomplete", err)
	}
}

func TestStore_ReportsAClosedDatabase(t *testing.T) {
	s, err := sqlite.Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	if err := s.Append(context.Background(), measurement(time.Date(2026, 10, 23, 0, 0, 0, 0, time.UTC))); err == nil {
		t.Error("Append on a closed store succeeded")
	}
	if _, _, err := s.Latest(context.Background(), "0.42.0", "a"); err == nil {
		t.Error("Latest on a closed store succeeded")
	}
	if err := s.Close(); err != nil {
		t.Logf("second close: %v", err)
	}
}

func TestOpen_RefusesAnUnopenableDSN(t *testing.T) {
	if _, err := sqlite.Open("/nonexistent-dir/x/mirror.db"); err == nil {
		t.Error("Open of an unopenable path succeeded")
	}
}

// TestStore_KeepsAPermanentOutcome: a release that publishes no digest is a
// fact about the release, held with its reason and time, no digests and no
// manifest.
func TestStore_KeepsAPermanentOutcome(t *testing.T) {
	s, ctx := open(t), context.Background()
	m := domain.Measurement{Version: "0.42.0", Asset: "tinygo0.42.0.linux-amd64.tar.gz", URL: "https://example.invalid/tgz",
		Outcome: domain.NoDigest, Reason: "publishes no SHA-256 digest", MeasuredAt: time.Date(2026, 10, 23, 2, 0, 0, 5, time.UTC)}
	if err := s.Append(ctx, m); err != nil {
		t.Fatal(err)
	}
	got, ok, err := s.Latest(ctx, m.Version, m.Asset)
	if err != nil || !ok || !reflect.DeepEqual(got, m) {
		t.Errorf("Latest = %+v, %v, %v; want %+v", got, ok, err, m)
	}
}
