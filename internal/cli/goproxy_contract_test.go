package cli

import (
	"bytes"
	"context"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	proxyadapter "github.com/eitanity/kanonarion/internal/adapters/proxy/direct"
	"github.com/eitanity/kanonarion/internal/coordinate/coordinatetest"
)

// dialRecorder replaces the process's default dialer for the duration of one
// test and records every address a command actually connected to.
//
// The point is that "did not reach the network" is asserted at the socket, not
// at the error text. A refusal that still dialled would print exactly the same
// sentence as one that did not, and the defect this file exists for was a
// silent redirection to a proxy that answered perfectly well — the message
// would never have shown it. Only the dial does.
type dialRecorder struct {
	t     *testing.T
	mu    sync.Mutex
	addrs []string
	// forbidden makes any dial an immediate test failure, so a regression is
	// caught at the moment of the connection rather than by a later count.
	forbidden bool
}

// installDialRecorder swaps http.DefaultTransport's dialer — which is the one
// the proxy adapter's client uses — and restores it when the test ends.
func installDialRecorder(t *testing.T, forbidden bool) *dialRecorder {
	t.Helper()
	transport, ok := http.DefaultTransport.(*http.Transport)
	if !ok {
		t.Fatalf("http.DefaultTransport is %T, not *http.Transport; the dial assertion cannot be installed", http.DefaultTransport)
	}
	rec := &dialRecorder{t: t, forbidden: forbidden}
	original := transport.DialContext
	transport.DialContext = rec.dial
	t.Cleanup(func() { transport.DialContext = original })
	return rec
}

func (r *dialRecorder) dial(ctx context.Context, network, addr string) (net.Conn, error) {
	r.mu.Lock()
	r.addrs = append(r.addrs, addr)
	forbidden := r.forbidden
	r.mu.Unlock()
	if forbidden {
		r.t.Errorf("network dial to %s: the environment declares no module fetching, so nothing may be contacted", addr)
	}
	var d net.Dialer
	conn, err := d.DialContext(ctx, network, addr)
	if err != nil {
		return nil, err //nolint:wrapcheck // test dialer stands in for net.Dialer
	}
	return conn, nil
}

func (r *dialRecorder) dialed() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]string(nil), r.addrs...)
}

// fetchCapableInvocations are the command lines that can acquire a module over
// the network. Each is run with a dial-failing transport installed, so the
// assertion is that none of them opens a socket — not that each of them
// produces some error.
func fetchCapableInvocations() []struct {
	name string
	args []string
} {
	return []struct {
		name string
		args []string
	}{
		{"fetch a pinned version", []string{"fetch", "example.com/mod@v1.0.0"}},
		{"fetch @latest", []string{"fetch", "example.com/mod@latest"}},
		{"fetch --list-versions", []string{"fetch", "example.com/mod", "--list-versions"}},
		{"latest", []string{"latest", "example.com/mod"}},
		{"walk @latest", []string{"walk", "example.com/mod@latest"}},
	}
}

// TestGOPROXYOff_EveryFetchCapableCommandRefusesBeforeAnyNetworkIO is this
// file's reason to exist: GOPROXY=off is an operator declaring an air gap, and
// a fetch that crosses it writes network-acquired evidence into a store that is
// supposed to hold only what the enclave can see. Every fetch-capable command
// must stop before the socket and say how to proceed offline.
func TestGOPROXYOff_EveryFetchCapableCommandRefusesBeforeAnyNetworkIO(t *testing.T) {
	for _, tc := range fetchCapableInvocations() {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("GOPROXY", "off")
			rec := installDialRecorder(t, true)

			var stdout, stderr bytes.Buffer
			err := Run(tc.args, &stdout, &stderr)
			if err == nil {
				t.Fatalf("%v: expected a refusal, got nil", tc.args)
			}
			if got := ExitCodeForError(err); got != ExitConfig {
				t.Errorf("exit code = %d, want ExitConfig(%d): %v", got, ExitConfig, err)
			}
			// The refusal has to name the contract it is honouring and the
			// ways to proceed without the network; an operator who is told
			// only "no" has to guess.
			for _, want := range []string{"GOPROXY=off", "--from-modcache", "use --recursive"} {
				if !strings.Contains(err.Error(), want) {
					t.Errorf("refusal does not mention %q: %v", want, err)
				}
			}
			if dialed := rec.dialed(); len(dialed) != 0 {
				t.Errorf("dialled %v under GOPROXY=off", dialed)
			}
		})
	}
}

// TestGOPROXYDirect_NeverContactsTheDefaultProxy: `direct` means VCS-origin
// fetching, which this build has not got. It refuses and names the mode. What
// it must never do is quietly become proxy.golang.org — the one destination
// the operator who wrote `direct` was specifically avoiding.
func TestGOPROXYDirect_NeverContactsTheDefaultProxy(t *testing.T) {
	for _, tc := range fetchCapableInvocations() {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("GOPROXY", "direct")
			rec := installDialRecorder(t, true)

			var stdout, stderr bytes.Buffer
			err := Run(tc.args, &stdout, &stderr)
			if err == nil {
				t.Fatalf("%v: expected a refusal, got nil", tc.args)
			}
			if got := ExitCodeForError(err); got != ExitConfig {
				t.Errorf("exit code = %d, want ExitConfig(%d): %v", got, ExitConfig, err)
			}
			if !strings.Contains(err.Error(), "GOPROXY=direct") {
				t.Errorf("refusal does not name the unsupported mode: %v", err)
			}
			if dialed := rec.dialed(); len(dialed) != 0 {
				t.Errorf("dialled %v under GOPROXY=direct", dialed)
			}
		})
	}
}

// TestGOPROXYSet_StillFetches is the zero-pair. Without it the tests above are
// satisfied by a build that refuses everything, which is not a fix. A GOPROXY
// pointing at a proxy — here a local test server, never the real one — is
// contacted exactly as before.
func TestGOPROXYSet_StillFetches(t *testing.T) {
	var hits int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits++
		if strings.HasSuffix(r.URL.Path, "/@v/list") {
			if _, err := w.Write([]byte("v1.0.0\nv1.1.0\n")); err != nil {
				t.Errorf("writing version list: %v", err)
			}
			return
		}
		http.NotFound(w, r)
	}))
	defer srv.Close()

	t.Setenv("GOPROXY", srv.URL)
	rec := installDialRecorder(t, false)

	var stdout, stderr bytes.Buffer
	// --insecure because the test server is http://; the point of the case is
	// the dial, not the scheme.
	if err := Run([]string{"fetch", "example.com/mod", "--list-versions", "--insecure"}, &stdout, &stderr); err != nil {
		t.Fatalf("fetch --list-versions against a live proxy: %v", err)
	}
	if !strings.Contains(stdout.String(), "v1.1.0") {
		t.Errorf("expected the proxy's versions on stdout, got: %q", stdout.String())
	}
	if hits == 0 {
		t.Error("the test proxy was never asked")
	}
	if len(rec.dialed()) == 0 {
		t.Error("no dial recorded; the zero-pair proves nothing if the command did not reach the network")
	}
}

// TestGOPROXYOff_ReadingAWarmStoreStillWorks guards the other half of the
// contract. The refusal withdraws fetching, not the store: an operator inside
// an air gap runs callgraph, licence, interface and the rest against material
// already measured, and every one of those wires a proxy it never uses. A
// container that failed to build would take the whole product away on the
// declaration that is meant to protect it.
func TestGOPROXYOff_ReadingAWarmStoreStillWorks(t *testing.T) {
	t.Setenv("GOPROXY", "off")
	rec := installDialRecorder(t, true)

	logger := slog.New(slog.NewTextHandler(&bytes.Buffer{}, nil))
	ctr, cleanup, err := NewContainer(t.TempDir(), "", "", false, activeConfig, logger)
	if err != nil {
		t.Fatalf("NewContainer under GOPROXY=off: %v", err)
	}
	defer func() {
		if cerr := cleanup(); cerr != nil {
			t.Errorf("cleanup: %v", cerr)
		}
	}()
	if ctr.FetchModule == nil || ctr.ExecuteWalk == nil {
		t.Fatal("container built without its use cases")
	}
	if dialed := rec.dialed(); len(dialed) != 0 {
		t.Errorf("dialled %v under GOPROXY=off", dialed)
	}
}

// TestRefusingProxy_AnswersEveryPortMethod pins the adapter itself: a port
// method added later must not silently acquire a fetching implementation while
// the environment forbids one.
func TestRefusingProxy_AnswersEveryPortMethod(t *testing.T) {
	p := proxyadapter.Refusing(proxyadapter.ErrProxyOff)
	coord := coordinatetest.MustNew("example.com/mod", "v1.0.0")
	ctx := context.Background()

	if _, err := p.Info(ctx, coord); err == nil {
		t.Error("Info did not refuse")
	}
	if _, err := p.Download(ctx, coord); err == nil {
		t.Error("Download did not refuse")
	}
	if _, err := p.DownloadGoMod(ctx, coord); err == nil {
		t.Error("DownloadGoMod did not refuse")
	}
}
