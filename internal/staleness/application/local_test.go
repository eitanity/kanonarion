package application_test

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"code.eitanity.com/kanonarion/internal/staleness/application"
	"code.eitanity.com/kanonarion/internal/staleness/domain"
	"code.eitanity.com/kanonarion/internal/staleness/ports"
)

func corpLocal(path string) bool { return strings.HasPrefix(path, "corp.example.com/") }

// TestResolve_LocalPathIsNeverAskedAnywhere: a path the scope compiles from a
// directory is refused with ErrLocalModule and is left out of the batch and the
// prefetch, even when it also matches the private patterns and the ledger holds
// a row for it.
func TestResolve_LocalPathIsNeverAskedAnywhere(t *testing.T) {
	now := time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)
	proxy := &fakeProxy{versions: map[string]string{"example.org/pub": "v1.0.0", "corp.example.com/lib": "v0.0.0"}}
	private := &fakeProxy{versions: map[string]string{"corp.example.com/lib": "v0.0.0"}}
	batch := &fakeBatch{answers: map[string]ports.BatchLatest{"example.org/pub": batchAnswer("v1.0.0", 1, "")}}
	ledger := newFakeLedger()
	ledger.rows["corp.example.com/lib"] = domain.Record{ModulePath: "corp.example.com/lib", LatestVersion: "v0.0.0", LookedUpAt: now}
	r := application.NewResolver(proxy, ledger, &fixedClock{t: now}, time.Hour, false).
		WithLocal(corpLocal).
		WithPrivate(corpPrivate, private).
		WithBatch(batch, pins("corp.example.com/lib@v0.0.0", "corp.example.com/lib/v2@v2.0.0", "example.org/pub@v1.0.0"), 4)
	ctx := context.Background()

	if _, err := r.Resolve(ctx, "example.org/pub", "v1.0.0"); err != nil {
		t.Fatalf("public Resolve: %v", err)
	}
	for _, path := range []string{"corp.example.com/lib", "corp.example.com/lib/v2"} {
		ans, err := r.Resolve(ctx, path, "v0.0.0")
		if !errors.Is(err, ports.ErrLocalModule) || ans.LatestVersion != "" || ans.Served {
			t.Errorf("%s: answer %+v, err %v; want nothing measured and ErrLocalModule", path, ans, err)
		}
	}
	for _, p := range append(append(append([]string{}, proxy.calls...), batch.asked...), private.calls...) {
		if strings.HasPrefix(p, "corp.example.com/") {
			t.Errorf("a local path was asked: %q", p)
		}
	}
	if ledger.writes != 1 {
		t.Errorf("ledger writes = %d, want the public module's one", ledger.writes)
	}
}
