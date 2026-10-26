package consumer_test

import (
	"context"
	"encoding/pem"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"sync"
	"testing"
	"time"

	"code.eitanity.com/kanonarion/pkg/kanonarion"
)

// The module the upstream knows: one version at its v1 path, nothing above.
const (
	staleModule  = "example.com/stale"
	staleLatest  = "v1.4.0"
	stalePublish = "2024-01-02T03:04:05Z"
)

var stalePublished = time.Date(2024, 1, 2, 3, 4, 5, 0, time.UTC)

// testUpstream answers as the proxy below does: the v1 path's latest, an
// absent path for anything else. failWith makes every lookup fail instead.
type testUpstream struct {
	mu       sync.Mutex
	asked    []string
	failWith error
}

func (u *testUpstream) LatestInfo(_ context.Context, path string) (kanonarion.LatestInfo, error) {
	u.mu.Lock()
	defer u.mu.Unlock()
	u.asked = append(u.asked, path)
	if u.failWith != nil {
		return kanonarion.LatestInfo{}, u.failWith
	}
	if path != staleModule {
		return kanonarion.LatestInfo{}, fmt.Errorf("%s: %w", path, kanonarion.ErrPathAbsent)
	}
	return kanonarion.LatestInfo{Version: staleLatest, Time: stalePublished}, nil
}

// memoryLedger is a StalenessLedger a consumer supplies, counting writes.
type memoryLedger struct {
	mu   sync.Mutex
	rows map[string]kanonarion.StalenessRecord
	puts int
}

func (l *memoryLedger) GetStaleness(_ context.Context, path string) (kanonarion.StalenessRecord, bool, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	rec, ok := l.rows[path]
	return rec, ok, nil
}

func (l *memoryLedger) PutStaleness(_ context.Context, rec kanonarion.StalenessRecord) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.rows == nil {
		l.rows = map[string]kanonarion.StalenessRecord{}
	}
	l.rows[rec.ModulePath] = rec
	l.puts++
	return nil
}

type fixedClock struct{ now time.Time }

func (c fixedClock) Now() time.Time { return c.now }

// staleProxy serves testUpstream's answers as a module proxy over TLS, so the
// CLI can be asked the same question; the returned environment trusts it.
func staleProxy(t *testing.T) []string {
	t.Helper()
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/"+staleModule+"/@latest" {
			_, _ = fmt.Fprintf(w, `{"Version":%q,"Time":%q}`, staleLatest, stalePublish)
			return
		}
		http.NotFound(w, r)
	}))
	t.Cleanup(srv.Close)
	certFile := filepath.Join(t.TempDir(), "proxy.pem")
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw})
	if err := os.WriteFile(certFile, pemBytes, 0o600); err != nil {
		t.Fatal(err)
	}
	return []string{"GOPROXY=" + srv.URL, "SSL_CERT_FILE=" + certFile, "GONOPROXY=", "GOPRIVATE=", "GOFLAGS="}
}

// The record the public resolver writes through a supplied ledger, from a
// test upstream, is the record `kanonarion latest` writes from a proxy giving
// the same answers. LookedUpAt is excluded: it is when each lookup ran.
func TestConsumer_StalenessResolverWritesWhatLatestWrites(t *testing.T) {
	cliRoot := t.TempDir()
	if _, stderr, code := runKanonarion(t, cliRoot, staleProxy(t), "latest", staleModule, "--no-progress"); code != 0 {
		t.Fatalf("kanonarion latest exited %d: %s", code, stderr)
	}

	ledger := &memoryLedger{}
	now := time.Date(2026, 10, 23, 12, 0, 0, 0, time.UTC)
	resolver, err := kanonarion.NewStalenessResolver(ledger, kanonarion.StalenessResolverConfig{
		Upstream: &testUpstream{}, Clock: fixedClock{now: now}, TTL: time.Hour,
	})
	if err != nil {
		t.Fatalf("NewStalenessResolver: %v", err)
	}
	answer, err := resolver.Resolve(t.Context(), staleModule, "")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if answer.Served || ledger.puts != 1 || !reflect.DeepEqual(ledger.rows[staleModule], answer.Record) {
		t.Fatalf("served=%v puts=%d; the answer was not written through the supplied ledger", answer.Served, ledger.puts)
	}

	cliRecord := storedStaleness(t, cliRoot)
	if cliRecord.LatestVersion != staleLatest || !cliRecord.NewerMajor.Probed {
		t.Fatalf("latest wrote %+v; the comparison would be vacuous", cliRecord)
	}
	got, want := answer.Record, cliRecord
	got.LookedUpAt, want.LookedUpAt = time.Time{}, time.Time{}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("public resolver wrote\n  %+v\nlatest wrote\n  %+v", got, want)
	}
}

// storedStaleness reads the row `latest` wrote into the store at root, by
// asking the driver's resolver with an upstream that must not be asked.
func storedStaleness(t *testing.T, root string) kanonarion.StalenessRecord {
	t.Helper()
	drv, cleanup, err := kanonarion.OpenDriver(root)
	if err != nil {
		t.Fatalf("OpenDriver: %v", err)
	}
	defer closeStore(t, cleanup)
	never := &testUpstream{failWith: errors.New("the stored row should have answered")}
	resolver, err := drv.StalenessResolver(kanonarion.StalenessResolverConfig{Upstream: never, TTL: 1000 * time.Hour})
	if err != nil {
		t.Fatalf("Driver.StalenessResolver: %v", err)
	}
	answer, err := resolver.Resolve(t.Context(), staleModule, "")
	if err != nil || !answer.Served || len(never.asked) != 0 {
		t.Fatalf("reading latest's row: served=%v asked=%v err=%v", answer.Served, never.asked, err)
	}
	return answer.Record
}

// An absent newer major ends the probe after one question and is stored as a
// negative; a second call inside the TTL is the ledger's answer alone.
func TestConsumer_StalenessResolverStoresAnAbsentMajorAndServesInsideTheTTL(t *testing.T) {
	ledger, up := &memoryLedger{}, &testUpstream{}
	clock := fixedClock{now: time.Date(2026, 10, 23, 12, 0, 0, 0, time.UTC)}
	resolver, err := kanonarion.NewStalenessResolver(ledger, kanonarion.StalenessResolverConfig{Upstream: up, Clock: clock, TTL: time.Hour})
	if err != nil {
		t.Fatalf("NewStalenessResolver: %v", err)
	}
	first, err := resolver.Resolve(t.Context(), staleModule, "v1.0.0")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if want := []string{staleModule, staleModule + "/v2"}; !reflect.DeepEqual(up.asked, want) {
		t.Errorf("upstream asked %v, want %v: the absent /v2 must end the probe", up.asked, want)
	}
	nm := first.NewerMajor
	if !nm.Probed || nm.Path != "" || ledger.puts != 1 || !ledger.rows[staleModule].NewerMajor.Probed {
		t.Errorf("newer major = %+v, puts %d; want a probed negative, stored", nm, ledger.puts)
	}

	second, err := resolver.Resolve(t.Context(), staleModule, "v1.0.0")
	if err != nil || !second.Served || len(up.asked) != 2 || ledger.puts != 1 {
		t.Errorf("second call: served=%v asked=%v puts=%d err=%v; want the ledger's answer alone", second.Served, up.asked, ledger.puts, err)
	}
}

// A failed lookup is reported and writes nothing.
func TestConsumer_StalenessResolverReportsAFailedLookupAndWritesNothing(t *testing.T) {
	ledger := &memoryLedger{}
	up := &testUpstream{failWith: fmt.Errorf("upstream 503: %w", kanonarion.ErrLookupFailed)}
	resolver, err := kanonarion.NewStalenessResolver(ledger, kanonarion.StalenessResolverConfig{Upstream: up})
	if err != nil {
		t.Fatalf("NewStalenessResolver: %v", err)
	}
	if _, err := resolver.Resolve(t.Context(), staleModule, ""); !errors.Is(err, kanonarion.ErrLookupFailed) {
		t.Errorf("Resolve = %v, want ErrLookupFailed", err)
	}
	if ledger.puts != 0 {
		t.Errorf("a failed lookup wrote %d row(s)", ledger.puts)
	}
}
