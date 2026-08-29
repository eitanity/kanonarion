package cli

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	proxyadapter "github.com/eitanity/kanonarion/internal/adapters/proxy/direct"
	configdomain "github.com/eitanity/kanonarion/internal/config/domain"
)

// A staleness probe that waits out a transient proxy answer says so, on the
// stream the operator is watching, through the wiring `audit` composes: the
// reporter its progress rules build, handed to the resolver its lookup builds.
//
// The transient failure is a FAKE — an httptest proxy answering one empty 200,
// the shape a loaded proxy answers with. The live condition cannot be summoned
// on demand and a test that waits for one is a flake.
func TestStalenessRetry_NarratesAndIsSilencedByNoProgress(t *testing.T) {
	on := configdomain.Config{Preferences: configdomain.Preferences{Progress: true}}

	for _, tc := range []struct {
		name       string
		noProgress bool
		want       string
	}{
		{
			name: "narrated",
			want: "staleness progress: retrying example.com/mod (attempt 2 of 4)\n",
		},
		{
			name:       "--no-progress",
			noProgress: true,
			want:       "",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var calls atomic.Int64
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				if calls.Add(1) == 1 {
					w.WriteHeader(http.StatusOK)
					return
				}
				_, _ = io.WriteString(w, `{"Version":"v1.3.0","Time":"2025-06-01T00:00:00Z"}`)
			}))
			defer srv.Close()

			proxy, err := proxyadapter.New(srv.URL, true)
			if err != nil {
				t.Fatalf("building proxy client: %v", err)
			}
			var stderr strings.Builder
			progress := newStalenessProgressReporter(&stderr, tc.noProgress, on, "warn")
			latest := newProxyLatestResolver(proxy, discardLogger(), progress)

			info, err := latest.LatestInfo(context.Background(), "example.com/mod")
			if err != nil {
				t.Fatalf("LatestInfo after one empty response: %v", err)
			}
			// The answer is the same either way: the flag governs the narration
			// and nothing else.
			if info.Version != "v1.3.0" {
				t.Errorf("version = %q, want v1.3.0", info.Version)
			}
			if got := calls.Load(); got != 2 {
				t.Errorf("proxy asked %d times, want 2", got)
			}
			if got := stderr.String(); got != tc.want {
				t.Errorf("stderr = %q, want %q", got, tc.want)
			}
		})
	}
}

// The control: a lookup that answers on sight narrates nothing. This is what
// makes the line invisible on a run with nothing slow in it — every audit that
// does not hit a transient failure writes exactly the bytes it wrote before.
func TestStalenessRetry_SilentWhenNothingRetries(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, `{"Version":"v1.3.0","Time":"2025-06-01T00:00:00Z"}`)
	}))
	defer srv.Close()

	proxy, err := proxyadapter.New(srv.URL, true)
	if err != nil {
		t.Fatalf("building proxy client: %v", err)
	}
	var stderr strings.Builder
	on := configdomain.Config{Preferences: configdomain.Preferences{Progress: true}}
	latest := newProxyLatestResolver(proxy, discardLogger(), newStalenessProgressReporter(&stderr, false, on, "warn"))

	if _, err := latest.LatestInfo(context.Background(), "example.com/mod"); err != nil {
		t.Fatalf("LatestInfo: %v", err)
	}
	if stderr.String() != "" {
		t.Errorf("a lookup that did not retry wrote %q, want nothing", stderr.String())
	}
}
