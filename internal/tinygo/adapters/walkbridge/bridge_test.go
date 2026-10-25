package walkbridge_test

import (
	"context"
	"io"
	"log/slog"
	"testing"
	"time"

	"github.com/eitanity/kanonarion/internal/tinygo/adapters/walkbridge"
	"github.com/eitanity/kanonarion/internal/tinygo/application"
	"github.com/eitanity/kanonarion/internal/tinygo/domain"
	walkdomain "github.com/eitanity/kanonarion/internal/walk/domain"
)

const hexA = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

var at = time.Date(2026, 10, 23, 2, 0, 0, 0, time.UTC)

type heldStore struct{ m domain.Measurement }

func (s heldStore) Latest(context.Context, string, string) (domain.Measurement, bool, error) {
	return s.m, s.m.Version != "", nil
}
func (heldStore) Append(context.Context, domain.Measurement) error { return nil }

type clock struct{}

func (clock) Now() time.Time { return at }

func TestBridge_MapsTheMeasurement(t *testing.T) {
	held := domain.Measurement{Version: "0.42.0", Asset: "tinygo0.42.0.linux-amd64.tar.gz", PublishedDigest: hexA,
		ObservedDigest: hexA, Outcome: domain.DigestMatched, MeasuredAt: at,
		Manifest: []domain.ManifestEntry{{Path: "device/rp/rp2040.go", SHA256: hexA}}}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	got := walkbridge.New(application.NewOfflineAcquirer(heldStore{held}, clock{}, logger)).
		AcquireTinyGoRelease(context.Background(), "0.42.0", "linux", "amd64", false)
	if got.Asset != held.Asset || got.Outcome != walkdomain.TinyGoReleaseDigestMatched || got.PublishedDigest != hexA ||
		got.ObservedDigest != hexA || !got.MeasuredAt.Equal(at) || got.Manifest["device/rp/rp2040.go"] != hexA {
		t.Errorf("mapped = %+v", got)
	}
	none := walkbridge.New(application.NewOfflineAcquirer(heldStore{}, clock{}, logger)).
		AcquireTinyGoRelease(context.Background(), "0.42.0", "linux", "amd64", false)
	if none.Outcome != walkdomain.TinyGoReleaseUnavailable || none.Reason != domain.ReasonOffline || none.Manifest != nil {
		t.Errorf("offline with nothing held = %+v", none)
	}
}
