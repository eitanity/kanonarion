package cli

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	staledomain "github.com/eitanity/kanonarion/internal/staleness/domain"
	staleports "github.com/eitanity/kanonarion/internal/staleness/ports"
	vulnapp "github.com/eitanity/kanonarion/internal/vuln/application"
	vulndomain "github.com/eitanity/kanonarion/internal/vuln/domain"
	"github.com/eitanity/kanonarion/internal/vuln/vulntest"
)

// TestAuditDerivation_SaysTheDatabaseWasCheckedAndUnchanged is the reporting
// half of the cheap refresh. "Nothing was downloaded" is the answer the operator
// asked for, and a refresh that reported nothing would be indistinguishable from
// one that never ran.
func TestAuditDerivation_SaysTheDatabaseWasCheckedAndUnchanged(t *testing.T) {
	var out bytes.Buffer
	err := writeAuditDerivation(&out, auditDerivation{
		refreshed: true,
		refresh: vulnapp.SnapshotRefresh{
			Outcome:          vulnapp.RefreshUnchanged,
			Snapshot:         vulntest.MustNew("vuln.go.dev", "2026-07-27T20:14:16Z"),
			PriorVersion:     "2026-07-27T20:14:16Z",
			PublishedVersion: "2026-07-27T20:14:16Z",
		},
		scanReused: true,
		scanRun: vulndomain.WalkScanRun{
			ID:          "vscan-1",
			CompletedAt: time.Date(2026, 8, 2, 4, 14, 9, 0, time.UTC),
			Snapshot:    vulntest.MustNew("vuln.go.dev", "2026-07-27T20:14:16Z"),
		},
	})
	if err != nil {
		t.Fatalf("writeAuditDerivation: %v", err)
	}

	got := out.String()
	for _, want := range []string{
		"advisory database",
		"unchanged",
		"nothing was downloaded",
		"2026-07-27T20:14:16Z",
		"reused run vscan-1",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("the derivation statement does not say %q:\n%s", want, got)
		}
	}
}

// TestAuditDerivation_SaysTheDatabaseAdvanced covers the other outcome: the
// statement must name both generations, because "downloaded" alone does not say
// what the run is now judged against.
func TestAuditDerivation_SaysTheDatabaseAdvanced(t *testing.T) {
	var out bytes.Buffer
	err := writeAuditDerivation(&out, auditDerivation{
		refreshed: true,
		refresh: vulnapp.SnapshotRefresh{
			Outcome:          vulnapp.RefreshDownloaded,
			Snapshot:         vulntest.MustNew("vuln.go.dev", "2026-08-01T09:00:00Z"),
			PriorVersion:     "2026-07-27T20:14:16Z",
			PublishedVersion: "2026-08-01T09:00:00Z",
		},
	})
	if err != nil {
		t.Fatalf("writeAuditDerivation: %v", err)
	}

	got := out.String()
	for _, want := range []string{"2026-08-01T09:00:00Z", "2026-07-27T20:14:16Z", "downloaded"} {
		if !strings.Contains(got, want) {
			t.Errorf("the derivation statement does not say %q:\n%s", want, got)
		}
	}
	if strings.Contains(got, "unchanged") {
		t.Errorf("an advanced database was reported as unchanged:\n%s", got)
	}
}

// TestAuditDerivation_SaysTheGenerationReadFailed pins the fail-closed report. A
// refresh that fell back to a blind download must not read as one that found a
// new generation.
func TestAuditDerivation_SaysTheGenerationReadFailed(t *testing.T) {
	var out bytes.Buffer
	err := writeAuditDerivation(&out, auditDerivation{
		refreshed: true,
		refresh: vulnapp.SnapshotRefresh{
			Outcome:      vulnapp.RefreshDownloaded,
			Snapshot:     vulntest.MustNew("vuln.go.dev", "2026-07-27T20:14:16Z"),
			PriorVersion: "2026-07-27T20:14:16Z",
			StampErr:     errors.New("dial tcp: connection refused"),
		},
	})
	if err != nil {
		t.Fatalf("writeAuditDerivation: %v", err)
	}

	got := out.String()
	for _, want := range []string{"unreadable", "connection refused", "downloaded"} {
		if !strings.Contains(got, want) {
			t.Errorf("the derivation statement does not say %q:\n%s", want, got)
		}
	}
}

// TestAuditDerivation_SaysNothingAboutADatabaseItDidNotCheck: without --fresh
// the run reads the stored database and makes no claim about its currency.
func TestAuditDerivation_SaysNothingAboutADatabaseItDidNotCheck(t *testing.T) {
	var out bytes.Buffer
	if err := writeAuditDerivation(&out, auditDerivation{}); err != nil {
		t.Fatalf("writeAuditDerivation: %v", err)
	}
	if got := out.String(); strings.Contains(got, "advisory database") {
		t.Errorf("a run that made no check claimed one:\n%s", got)
	}
}

// stubLatestResolver stands in for the module proxy. Every call is a live
// network answer in production, so a test that must prove the ledger was served
// asserts on Calls being zero.
type stubLatestResolver struct {
	calls int
	path  string
	info  staleports.LatestInfo
}

// LatestInfo answers for s.path alone. Every major-suffixed candidate is absent,
// which is the sentinel that ends the newer-major probe after one request.
func (s *stubLatestResolver) LatestInfo(_ context.Context, path string) (staleports.LatestInfo, error) {
	s.calls++
	if path != s.path {
		return staleports.LatestInfo{}, staleports.ErrPathAbsent
	}
	return s.info, nil
}

// stubLedger serves one prepared row for every path.
type stubLedger struct{ rec staledomain.Record }

func (l *stubLedger) GetStaleness(_ context.Context, path string) (staledomain.Record, bool, error) {
	rec := l.rec
	rec.ModulePath = path
	return rec, true, nil
}

func (l *stubLedger) PutStaleness(_ context.Context, _ staledomain.Record) error { return nil }

// TestAuditStalenessResolver_ServesTheLedgerUnderItsTTL is the audit half of the
// --fresh narrowing: the latest column is governed by the staleness TTL, so an
// audit serves a row inside it and does not re-query the proxy — whatever else
// the invocation asked to refresh.
func TestAuditStalenessResolver_ServesTheLedgerUnderItsTTL(t *testing.T) {
	proxy := &stubLatestResolver{path: "example.com/mod", info: staleports.LatestInfo{Version: "v2.0.0"}}
	ledger := &stubLedger{rec: staledomain.Record{
		LatestVersion: "v1.9.0",
		LookedUpAt:    time.Now().Add(-time.Minute),
		NewerMajor:    staledomain.NewerMajor{Probed: true, FromMajor: 2},
	}}

	resolver := newAuditStalenessResolver(proxy, ledger, time.Hour)
	answer, err := resolver.Resolve(context.Background(), "example.com/mod", "v1.8.0")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if proxy.calls != 0 {
		t.Errorf("the audit re-queried the proxy %d times for a row inside the staleness TTL", proxy.calls)
	}
	if !answer.Served {
		t.Error("a row inside the TTL was not served from the ledger")
	}
	if answer.LatestVersion != "v1.9.0" {
		t.Errorf("latest = %s, want the ledger's v1.9.0", answer.LatestVersion)
	}
}

// TestStalenessResolver_FreshReQueriesTheProxy is the counterpart, and the
// behaviour `latest --fresh` keeps: there, the latest answer IS the subject, so
// asking for a fresh one bypasses the ledger.
func TestStalenessResolver_FreshReQueriesTheProxy(t *testing.T) {
	proxy := &stubLatestResolver{path: "example.com/mod", info: staleports.LatestInfo{Version: "v2.0.0"}}
	ledger := &stubLedger{rec: staledomain.Record{
		LatestVersion: "v1.9.0",
		LookedUpAt:    time.Now().Add(-time.Minute),
		NewerMajor:    staledomain.NewerMajor{Probed: true, FromMajor: 2},
	}}

	resolver := newStalenessResolver(proxy, ledger, time.Hour, true)
	answer, err := resolver.Resolve(context.Background(), "example.com/mod", "v1.8.0")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if proxy.calls == 0 {
		t.Error("--fresh served the ledger instead of re-querying the proxy")
	}
	if answer.LatestVersion != "v2.0.0" {
		t.Errorf("latest = %s, want the re-queried v2.0.0", answer.LatestVersion)
	}
}

// TestAdvisoryRefreshLine_DistinguishesEveryOutcome: the line is the whole
// report of the refresh, so each outcome has to be readable as itself — and the
// two that keep the stored answer have to be readable as different claims.
func TestAdvisoryRefreshLine_DistinguishesEveryOutcome(t *testing.T) {
	held := vulntest.MustNew("vuln.go.dev", "2026-07-27T20:14:16Z")
	newer := vulntest.MustNew("vuln.go.dev", "2026-08-01T09:00:00Z")

	cases := []struct {
		name    string
		refresh vulnapp.SnapshotRefresh
		err     error
		want    []string
		notWant []string
	}{
		{
			name: "generation unchanged",
			refresh: vulnapp.SnapshotRefresh{
				Outcome: vulnapp.RefreshUnchanged, Snapshot: held,
				PriorVersion: held.Version(), PublishedVersion: held.Version(),
			},
			want:    []string{"unchanged", "nothing was downloaded"},
			notWant: []string{"failed", "advanced"},
		},
		{
			name: "generation advanced, walk unaffected",
			refresh: vulnapp.SnapshotRefresh{
				Outcome: vulnapp.RefreshIndexUnchanged, Snapshot: held,
				PriorVersion: held.Version(), PublishedVersion: newer.Version(),
				ModulesCompared: 322,
			},
			want: []string{
				"advanced " + held.Version() + " -> " + newer.Version(),
				"all 322 modules in this walk",
				"remains current for this walk",
				"nothing was downloaded",
			},
		},
		{
			name: "generation advanced, walk affected",
			refresh: vulnapp.SnapshotRefresh{
				Outcome: vulnapp.RefreshDownloaded, Snapshot: newer,
				PriorVersion: held.Version(), PublishedVersion: newer.Version(),
			},
			want:    []string{"advanced " + held.Version() + " -> " + newer.Version(), "downloaded the new database"},
			notWant: []string{"remains current"},
		},
		{
			name: "index unreadable",
			refresh: vulnapp.SnapshotRefresh{
				Outcome: vulnapp.RefreshDownloaded, Snapshot: newer,
				PriorVersion: held.Version(), PublishedVersion: newer.Version(),
				IndexErr: errors.New("503 Service Unavailable"),
			},
			want:    []string{"could not be compared", "503 Service Unavailable", "downloaded"},
			notWant: []string{"remains current"},
		},
		{
			name: "first refresh",
			refresh: vulnapp.SnapshotRefresh{
				Outcome: vulnapp.RefreshDownloaded, Snapshot: newer,
			},
			want: []string{"no snapshot was stored", newer.Version()},
		},
		{
			name: "refresh failed",
			err:  errors.New("dial tcp: connection refused"),
			want: []string{"refresh failed", "connection refused", "stored database is unchanged"},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := advisoryRefreshLine(tc.refresh, tc.err)
			for _, want := range tc.want {
				if !strings.Contains(got, want) {
					t.Errorf("line does not say %q: %s", want, got)
				}
			}
			for _, notWant := range tc.notWant {
				if strings.Contains(got, notWant) {
					t.Errorf("line wrongly says %q: %s", notWant, got)
				}
			}
		})
	}
}
