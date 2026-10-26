package application_test

import (
	"bytes"
	"context"
	"errors"
	"io"
	"log/slog"
	"strings"
	"testing"
	"time"

	"code.eitanity.com/kanonarion/internal/tinygo/application"
	"code.eitanity.com/kanonarion/internal/tinygo/domain"
	"code.eitanity.com/kanonarion/internal/tinygo/ports"
)

const (
	asset  = "tinygo0.42.0.linux-amd64.tar.gz"
	digest = "b87688fa2e19cee7d813cad7fd7dadb71dff3198e47125aba66ba4af5e490438"
	other  = "2082c4762fea6d5cc4cd1f4a243eaacf07b12f576717d4c6b74828bd163cb563"
	fileA  = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
)

var now = time.Date(2026, 10, 23, 2, 0, 0, 0, time.UTC)

type clock struct{}

func (clock) Now() time.Time { return now }

// network records every call that would leave the machine.
type network struct {
	assets    []ports.Asset
	found     bool
	indexErr  error
	archive   ports.Archive
	readErr   error
	calls     []string
	readNames []string
}

func (n *network) Assets(_ context.Context, tag string) ([]ports.Asset, bool, error) {
	n.calls = append(n.calls, "assets "+tag)
	return n.assets, n.found, n.indexErr
}

func (n *network) Read(_ context.Context, url, name string) (ports.Archive, error) {
	n.calls = append(n.calls, "read "+url)
	n.readNames = append(n.readNames, name)
	return n.archive, n.readErr
}

func published() *network {
	return &network{
		found: true,
		assets: []ports.Asset{
			{Name: "tinygo_0.42.0_amd64.deb", URL: "https://example.invalid/deb", Digest: "sha256:" + other},
			{Name: asset, URL: "https://example.invalid/tgz", Digest: "sha256:" + digest},
		},
		archive: ports.Archive{SHA256: digest, Manifest: []domain.ManifestEntry{{Path: "z.go", SHA256: fileA}, {Path: "device/rp/rp2040.go", SHA256: fileA}}},
	}
}

type memStore struct {
	rows      []domain.Measurement
	latestErr error
	appendErr error
}

func (s *memStore) Latest(_ context.Context, version, asset string) (domain.Measurement, bool, error) {
	if s.latestErr != nil {
		return domain.Measurement{}, false, s.latestErr
	}
	for i := len(s.rows) - 1; i >= 0; i-- {
		if s.rows[i].Version == version && s.rows[i].Asset == asset {
			return s.rows[i], true, nil
		}
	}
	return domain.Measurement{}, false, nil
}

func (s *memStore) Append(_ context.Context, m domain.Measurement) error {
	if s.appendErr != nil {
		return s.appendErr
	}
	s.rows = append(s.rows, m)
	return nil
}

func logger(buf *bytes.Buffer) *slog.Logger { return slog.New(slog.NewTextHandler(buf, nil)) }

func quiet() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

func held() domain.Measurement {
	return domain.Measurement{Version: "0.42.0", Asset: asset, URL: "https://example.invalid/tgz", PublishedDigest: digest,
		ObservedDigest: digest, Outcome: domain.DigestMatched, MeasuredAt: now.Add(-time.Hour),
		Manifest: []domain.ManifestEntry{{Path: "device/rp/rp2040.go", SHA256: fileA}}}
}

func TestAcquire_MeasuresAndKeepsAMatchedArchive(t *testing.T) {
	net, store := published(), &memStore{}
	m := application.NewAcquirer(net, net, store, clock{}, quiet()).Acquire(context.Background(), "0.42.0", "linux", "amd64", false)

	if m.Outcome != domain.DigestMatched || m.PublishedDigest != digest || m.ObservedDigest != digest || !m.MeasuredAt.Equal(now) {
		t.Errorf("measurement = %+v", m)
	}
	if len(m.Manifest) != 2 || m.Manifest[0].Path != "device/rp/rp2040.go" {
		t.Errorf("manifest = %+v, want it sorted", m.Manifest)
	}
	if len(store.rows) != 1 || net.readNames[0] != asset || net.calls[0] != "assets v0.42.0" {
		t.Errorf("kept %d rows; calls %v", len(store.rows), net.calls)
	}
}

func TestAcquire_ServesAHeldMeasurementWithoutTheNetwork(t *testing.T) {
	net, store := published(), &memStore{rows: []domain.Measurement{held()}}
	m := application.NewAcquirer(net, net, store, clock{}, quiet()).Acquire(context.Background(), "0.42.0", "linux", "amd64", false)
	if !m.MeasuredAt.Equal(held().MeasuredAt) || len(net.calls) != 0 {
		t.Errorf("measurement %+v after calls %v, want the held one and no request", m, net.calls)
	}
}

func TestAcquire_ForceReacquires(t *testing.T) {
	net, store := published(), &memStore{rows: []domain.Measurement{held()}}
	m := application.NewAcquirer(net, net, store, clock{}, quiet()).Acquire(context.Background(), "0.42.0", "linux", "amd64", true)
	if !m.MeasuredAt.Equal(now) || len(net.calls) != 2 || len(store.rows) != 2 {
		t.Errorf("force served %+v after %v with %d rows", m, net.calls, len(store.rows))
	}
}

func TestAcquire_Outcomes(t *testing.T) {
	for name, tc := range map[string]struct {
		change  func(*network)
		goos    string
		outcome domain.Outcome
		reason  string
		kept    int
		reads   int
	}{
		"digest mismatch": {
			change:  func(n *network) { n.archive.SHA256 = other },
			outcome: domain.DigestMismatch, reason: "hashes to " + other + ", not the published " + digest, kept: 1, reads: 1,
		},
		"no digest published": {
			change:  func(n *network) { n.assets[1].Digest = "" },
			outcome: domain.NoDigest, reason: "publishes no SHA-256 digest for " + asset, kept: 1,
		},
		"another algorithm only": {
			change:  func(n *network) { n.assets[1].Digest = "sha512:abc" },
			outcome: domain.NoDigest, reason: "publishes no SHA-256 digest", kept: 1,
		},
		"asset absent": {
			change:  func(n *network) { n.assets = n.assets[:1] },
			outcome: domain.AssetAbsent, reason: "has no asset " + asset, kept: 1,
		},
		"release absent": {
			change:  func(n *network) { n.found, n.assets = false, nil },
			outcome: domain.AssetAbsent, reason: "publishes no release v0.42.0", kept: 1,
		},
		"API failure": {
			change:  func(n *network) { n.indexErr = errors.New("403 rate limited") },
			outcome: domain.Unavailable, reason: "could not be read: 403 rate limited",
		},
		"download failure": {
			change:  func(n *network) { n.readErr = errors.New("connection reset") },
			outcome: domain.Unavailable, reason: "could not be read: connection reset", reads: 1,
		},
		"windows asset naming": {
			change: func(n *network) {
				n.assets = append(n.assets, ports.Asset{Name: "tinygo0.42.0.windows-amd64.zip", URL: "u", Digest: "sha256:" + digest})
			},
			goos: "windows", outcome: domain.DigestMatched, kept: 1, reads: 1,
		},
		"no host platform": {
			change: func(*network) {}, goos: "-", outcome: domain.Unavailable, reason: "reported no host platform",
		},
	} {
		t.Run(name, func(t *testing.T) {
			net, store := published(), &memStore{}
			tc.change(net)
			goos := tc.goos
			switch goos {
			case "":
				goos = "linux"
			case "-":
				goos = ""
			}
			m := application.NewAcquirer(net, net, store, clock{}, quiet()).Acquire(context.Background(), "0.42.0", goos, "amd64", false)
			if m.Outcome != tc.outcome || !strings.Contains(m.Reason, tc.reason) {
				t.Errorf("outcome %s, reason %q; want %s containing %q", m.Outcome, m.Reason, tc.outcome, tc.reason)
			}
			if len(store.rows) != tc.kept || len(net.readNames) != tc.reads {
				t.Errorf("kept %d (want %d), read %v (want %d)", len(store.rows), tc.kept, net.readNames, tc.reads)
			}
			if m.Outcome.Kept() == m.MeasuredAt.IsZero() {
				t.Errorf("outcome %s carries time %v: a kept outcome is timed, a transient one is not", m.Outcome, m.MeasuredAt)
			}
			if tc.outcome == domain.DigestMismatch && (m.Manifest != nil || m.ObservedDigest != other) {
				t.Errorf("a mismatch kept %d manifest entries or lost its digest: %+v", len(m.Manifest), m)
			}
		})
	}
}

// TestAcquire_APermanentOutcomeIsServedWithoutTheNetwork is the recorder for
// the kept outcomes: a release that publishes no digest, or has no such asset
// or release, is asked once; the next acquisition makes no request, and force
// asks again. A transient failure is asked again every time.
func TestAcquire_APermanentOutcomeIsServedWithoutTheNetwork(t *testing.T) {
	for name, tc := range map[string]struct {
		change   func(*network)
		outcome  domain.Outcome
		requests [3]int
	}{
		"no digest":       {func(n *network) { n.assets[1].Digest = "" }, domain.NoDigest, [3]int{1, 0, 1}},
		"asset absent":    {func(n *network) { n.assets = n.assets[:1] }, domain.AssetAbsent, [3]int{1, 0, 1}},
		"release absent":  {func(n *network) { n.found, n.assets = false, nil }, domain.AssetAbsent, [3]int{1, 0, 1}},
		"API unreachable": {func(n *network) { n.indexErr = errors.New("dial tcp: i/o timeout") }, domain.Unavailable, [3]int{1, 1, 1}},
	} {
		t.Run(name, func(t *testing.T) {
			net, store := published(), &memStore{}
			tc.change(net)
			acq := application.NewAcquirer(net, net, store, clock{}, quiet())
			for i, force := range []bool{false, false, true} {
				before := len(net.calls)
				m := acq.Acquire(context.Background(), "0.42.0", "linux", "amd64", force)
				if got := len(net.calls) - before; got != tc.requests[i] || m.Outcome != tc.outcome {
					t.Errorf("acquisition %d (force=%v): %d release-API request(s), outcome %s; want %d, %s",
						i+1, force, got, m.Outcome, tc.requests[i], tc.outcome)
				}
			}
		})
	}
}

// TestAcquire_OfflineReachesNothing is the recorder: offline, with or without
// a held measurement and even under force, no request is made.
func TestAcquire_OfflineReachesNothing(t *testing.T) {
	for name, rows := range map[string][]domain.Measurement{"held": {held()}, "none": nil} {
		t.Run(name, func(t *testing.T) {
			store := &memStore{rows: rows}
			acq := application.NewOfflineAcquirer(store, clock{}, quiet())
			for _, force := range []bool{false, true} {
				m := acq.Acquire(context.Background(), "0.42.0", "linux", "amd64", force)
				switch {
				case rows != nil && m.Outcome != domain.DigestMatched:
					t.Errorf("force=%v: offline did not serve the held measurement: %+v", force, m)
				case rows == nil && (m.Outcome != domain.Unavailable || m.Reason != domain.ReasonOffline):
					t.Errorf("force=%v: offline with nothing held = %+v", force, m)
				}
			}
		})
	}
}

func TestAcquire_StoreFailuresAreLoggedNotFatal(t *testing.T) {
	var buf bytes.Buffer
	net := published()
	store := &memStore{latestErr: errors.New("locked"), appendErr: errors.New("disk full")}
	m := application.NewAcquirer(net, net, store, clock{}, logger(&buf)).Acquire(context.Background(), "0.42.0", "linux", "amd64", false)
	if m.Outcome != domain.DigestMatched {
		t.Errorf("a store failure changed the measurement: %+v", m)
	}
	for _, want := range []string{"tinygo.release.store_unreadable", "locked", "tinygo.release.not_recorded", "disk full"} {
		if !strings.Contains(buf.String(), want) {
			t.Errorf("log lacks %q:\n%s", want, buf.String())
		}
	}
}

func TestAcquire_NilStoreKeepsNothing(t *testing.T) {
	net := published()
	m := application.NewAcquirer(net, net, nil, clock{}, quiet()).Acquire(context.Background(), "0.42.0", "linux", "amd64", false)
	if m.Outcome != domain.DigestMatched {
		t.Errorf("measurement = %+v", m)
	}
	if off := application.NewOfflineAcquirer(nil, clock{}, quiet()).Acquire(context.Background(), "0.42.0", "linux", "amd64", false); off.Reason != domain.ReasonOffline {
		t.Errorf("offline with no store = %+v", off)
	}
}
