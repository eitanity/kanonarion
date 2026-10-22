package application_test

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/eitanity/kanonarion/internal/staleness/application"
	"github.com/eitanity/kanonarion/internal/staleness/domain"
	"github.com/eitanity/kanonarion/internal/staleness/ports"
)

func corpPrivate(path string) bool { return strings.HasPrefix(path, "corp.example.com") }

// privateSetup is a go.mod-scoped resolver over one private and one public
// module, with a ledger already holding a false "current" row for the private
// path and a batch that reports it with no update, exit 0.
func privateSetup(private ports.LatestResolver) (*application.Resolver, *fakeProxy, *fakeBatch, *fakeLedger) {
	now := time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)
	proxy := &fakeProxy{versions: map[string]string{"example.org/pub": "v1.0.0", "corp.example.com/a": "v1.0.0"}}
	batch := &fakeBatch{answers: map[string]ports.BatchLatest{
		"example.org/pub":    batchAnswer("v1.0.0", 1, ""),
		"corp.example.com/a": batchAnswer("v1.0.0", 1, ""),
	}}
	ledger := newFakeLedger()
	ledger.rows["corp.example.com/a"] = domain.Record{ModulePath: "corp.example.com/a", LatestVersion: "v1.0.0",
		LookedUpAt: now, NewerMajor: domain.NewerMajor{Probed: true, FromMajor: 2}}
	r := application.NewResolver(proxy, ledger, &fixedClock{t: now}, time.Hour, false).
		WithPrivate(corpPrivate, private).
		WithBatch(batch, pins("corp.example.com/a@v1.0.0", "example.org/pub@v1.0.0"), 4)
	return r, proxy, batch, ledger
}

// TestResolve_PrivatePathNeverReachesTheProxyOrTheLedger: when the go command
// cannot resolve a private module, the answer is ErrPrivateModule and nothing
// else spoke for it — not the batch row, not the stored row, not a probe.
func TestResolve_PrivatePathNeverReachesTheProxyOrTheLedger(t *testing.T) {
	failing := &fakeProxy{fail: map[string]bool{"corp.example.com/a": true}}
	r, proxy, batch, ledger := privateSetup(failing)
	ctx := context.Background()

	if _, err := r.Resolve(ctx, "example.org/pub", "v1.0.0"); err != nil {
		t.Fatalf("public Resolve: %v", err)
	}
	writesBefore := ledger.writes
	ans, err := r.Resolve(ctx, "corp.example.com/a", "v1.0.0")
	if !errors.Is(err, ports.ErrPrivateModule) {
		t.Fatalf("err = %v, want ErrPrivateModule", err)
	}
	if ans.LatestVersion != "" || ans.Served {
		t.Errorf("answer = %+v, want nothing measured", ans)
	}
	for _, p := range append(append([]string{}, proxy.calls...), batch.asked...) {
		if strings.HasPrefix(p, "corp.example.com") {
			t.Errorf("a private path reached the proxy or the batch: %q", p)
		}
	}
	if ledger.writes != writesBefore {
		t.Errorf("the ledger was written for a private path")
	}
	if len(failing.calls) != 1 || failing.calls[0] != "corp.example.com/a" {
		t.Errorf("private resolver asked %v, want the module path once", failing.calls)
	}
}

// TestResolve_PrivatePathAnsweredByTheGoCommandIsUnprobed: a resolved private
// latest is reported with the newer-major question unasked and nothing written.
func TestResolve_PrivatePathAnsweredByTheGoCommandIsUnprobed(t *testing.T) {
	answering := &fakeProxy{versions: map[string]string{"corp.example.com/a": "v1.2.0"}}
	r, _, _, ledger := privateSetup(answering)
	ans, err := r.Resolve(context.Background(), "corp.example.com/a", "v1.0.0")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if ans.LatestVersion != "v1.2.0" || ans.NewerMajor.Probed || ans.Served || ans.LookedUpAt.IsZero() {
		t.Errorf("answer = %+v, want v1.2.0, unprobed, live", ans)
	}
	if ledger.writes != 0 {
		t.Errorf("ledger writes = %d, want 0", ledger.writes)
	}
}

// TestResolve_PrivateFailureIsAlwaysErrPrivateModule: a resolver that neither
// names a version nor marks its failure still yields the private reason.
func TestResolve_PrivateFailureIsAlwaysErrPrivateModule(t *testing.T) {
	for name, private := range map[string]ports.LatestResolver{
		"no version": &fakeProxy{versions: map[string]string{"corp.example.com/a": ""}},
		"bare error": &fakeProxy{fail: map[string]bool{"corp.example.com/a": true}},
	} {
		r := application.NewResolver(&fakeProxy{}, nil, &fixedClock{t: time.Now()}, time.Hour, false).WithPrivate(corpPrivate, private)
		if _, err := r.Resolve(context.Background(), "corp.example.com/a", ""); !errors.Is(err, ports.ErrPrivateModule) {
			t.Errorf("%s: err = %v, want ErrPrivateModule", name, err)
		}
	}
}
