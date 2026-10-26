package cli

import (
	"archive/zip"
	"bytes"
	"crypto/tls"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/mod/sumdb/dirhash"

	proxyadapter "code.eitanity.com/kanonarion/internal/adapters/proxy/direct"
	staleretry "code.eitanity.com/kanonarion/internal/staleness/adapters/proxy/retrying"
	staleports "code.eitanity.com/kanonarion/internal/staleness/ports"
)

// shortenStalenessSchedule swaps the shared 20s/240s re-ask schedule for a
// millisecond one for the rest of the test; the schedule itself is pinned in
// the decorator's own tests.
func shortenStalenessSchedule(t *testing.T) {
	t.Helper()
	prev := stalenessRetryOptions
	stalenessRetryOptions = []staleretry.Option{staleretry.WithSchedule(time.Millisecond, time.Minute)}
	t.Cleanup(func() { stalenessRetryOptions = prev })
}

func shortenedProxyLatestResolver(t *testing.T, proxy *proxyadapter.Proxy) staleports.LatestResolver {
	t.Helper()
	shortenStalenessSchedule(t)
	return newProxyLatestResolver(proxy, discardLogger(), nil)
}

const narrationModGoMod = "module example.com/mod\n\ngo 1.21\n"

// narrationProxy serves example.com/mod@v1.0.0 as a module proxy does. Its
// @latest and its /v2 major each answer the way an unfinished origin lookup
// does on the first ask (an empty 200), and definitively after it.
//
// asks counts requests per transient path, so a silent run can be shown to have
// hit the wait it did not narrate.
type narrationAsks struct{ latest, v2 atomic.Int64 }

func narrationProxy(t *testing.T, asks *narrationAsks) http.Handler {
	t.Helper()
	var zipBuf bytes.Buffer
	zw := zip.NewWriter(&zipBuf)
	w, err := zw.Create("example.com/mod@v1.0.0/go.mod")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := io.WriteString(w, narrationModGoMod); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	info := `{"Version":"v1.0.0","Time":"2025-06-01T00:00:00Z"}`
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/example.com/mod/@v/list":
			_, _ = io.WriteString(w, "v1.0.0\n") //nolint:errcheck // a failed write is seen by the client under test
		case "/example.com/mod/@v/v1.0.0.info":
			_, _ = io.WriteString(w, info) //nolint:errcheck // as above
		case "/example.com/mod/@latest":
			if asks.latest.Add(1) == 1 {
				w.WriteHeader(http.StatusOK)
				return
			}
			_, _ = io.WriteString(w, info) //nolint:errcheck // as above
		case "/example.com/mod/@v/v1.0.0.mod":
			_, _ = io.WriteString(w, narrationModGoMod) //nolint:errcheck // as above
		case "/example.com/mod/@v/v1.0.0.zip":
			_, _ = w.Write(zipBuf.Bytes()) //nolint:errcheck // as above
		case "/example.com/mod/v2/@latest":
			if asks.v2.Add(1) == 1 {
				w.WriteHeader(http.StatusOK)
				return
			}
			http.NotFound(w, r)
		default:
			http.NotFound(w, r)
		}
	})
}

const (
	retryNarration  = "staleness progress: retrying example.com/mod/v2 (attempt 2,"
	noteNarration   = "staleness progress: retrying example.com/mod (attempt 2,"
	settleNarration = "staleness progress: waiting on 1 module path(s) the proxy has not finished"
)

// `fetch` narrates the re-ask on its staleness note, and --no-progress silences
// it. Driven end to end through the command; the enforcing host list keeps the
// VCS leg off the network.
func TestFetchNarratesAStalenessRetry(t *testing.T) {
	for _, tc := range []struct {
		name  string
		extra []string
		want  bool
	}{
		{"narrated", nil, true},
		{"--no-progress", []string{"--no-progress"}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			shortenStalenessSchedule(t)
			var asks narrationAsks
			srv := httptest.NewServer(narrationProxy(t, &asks))
			defer srv.Close()
			dir := t.TempDir()
			policy := filepath.Join(dir, "policy.yaml")
			if err := os.WriteFile(policy, []byte("version: \"1\"\nstages:\n  fetch:\n    follow_replace: true\n    follow_indirect: true\n    allowed_vcs_hosts:\n      - github.com\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			args := append([]string{"fetch", "example.com/mod@v1.0.0", "--insecure", "--goproxy", srv.URL,
				"--skip-vcs-verify", "--policy", policy, "--store-root", filepath.Join(dir, "store")}, tc.extra...)
			var stdout, stderr bytes.Buffer
			if err := Run(args, &stdout, &stderr); err != nil {
				t.Fatalf("fetch: %v\nstderr:\n%s", err, stderr.String())
			}
			if got := strings.Contains(stderr.String(), noteNarration); got != tc.want {
				t.Errorf("retry narrated = %v, want %v; stdout:\n%s\nstderr:\n%s", got, tc.want, stdout.String(), stderr.String())
			}
			if n := asks.latest.Load(); n != 2 {
				t.Errorf("@latest asked %d times, want 2 (the unfinished answer, then the real one)", n)
			}
		})
	}
}

// latestNarrationHelperEnv re-executes this test binary as `kanonarion latest`
// against a TLS fake proxy. A child process is needed because `latest` refuses
// a plain-HTTP proxy and the system root pool, which SSL_CERT_FILE extends, is
// loaded once per process.
const latestNarrationHelperEnv = "KANON_CLI_LATEST_NARRATION_HELPER"

// `latest` narrates both waits — the settle pass after a --gomod round, and the
// single-path retry of a positional lookup — and --no-progress silences both.
func TestLatestNarratesStalenessWaits(t *testing.T) {
	if args := os.Getenv(latestNarrationHelperEnv); args != "" {
		stalenessRetryOptions = []staleretry.Option{staleretry.WithSchedule(time.Millisecond, time.Minute)}
		err := Run(strings.Split(args, "\n"), os.Stdout, os.Stderr)
		if err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
		}
		os.Exit(ExitCodeForError(err))
	}

	for _, tc := range []struct {
		name  string
		gomod bool
		quiet bool
		want  string
	}{
		{"gomod settle pass", true, false, settleNarration},
		{"gomod --no-progress", true, true, settleNarration},
		{"positional retry", false, false, retryNarration},
		{"positional --no-progress", false, true, retryNarration},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var asks narrationAsks
			srv := httptest.NewTLSServer(narrationProxy(t, &asks))
			defer srv.Close()
			dir := t.TempDir()
			certFile := filepath.Join(dir, "proxy.pem")
			writeServerCert(t, srv.TLS, certFile)

			args := []string{"latest", "--fresh", "--goproxy", srv.URL, "--store-root", filepath.Join(dir, "store")}
			if tc.gomod {
				writeNarrationProject(t, dir)
				args = append(args, "--gomod", filepath.Join(dir, "go.mod"), "--project")
			} else {
				args = append(args, "example.com/mod")
			}
			if tc.quiet {
				args = append(args, "--no-progress")
			}
			cmd := exec.Command(os.Args[0], "-test.run=^TestLatestNarratesStalenessWaits$") // #nosec G204 G702 -- re-execs this very test binary; the args are literals
			cmd.Dir = dir
			cmd.Env = append(os.Environ(), latestNarrationHelperEnv+"="+strings.Join(args, "\n"),
				"SSL_CERT_FILE="+certFile, "GOSUMDB=off", "GONOSUMDB=*", "GOFLAGS=-modcacherw",
				"GOMODCACHE="+filepath.Join(dir, "modcache"), "GOWORK=off", "GOTOOLCHAIN=local",
				"GOPROXY="+srv.URL, "TMPDIR="+t.TempDir())
			var stdout, stderr bytes.Buffer
			cmd.Stdout, cmd.Stderr = &stdout, &stderr
			if err := cmd.Run(); err != nil {
				t.Fatalf("latest helper: %v\nstderr:\n%s", err, stderr.String())
			}
			if !strings.Contains(stdout.String(), "example.com/mod") {
				t.Fatalf("no row for example.com/mod; stdout:\n%s\nstderr:\n%s", stdout.String(), stderr.String())
			}
			if n := asks.v2.Load(); n != 2 {
				t.Errorf("/v2 asked %d times, want 2 (the unfinished answer, then the 404)", n)
			}
			if got := strings.Contains(stderr.String(), tc.want); got == tc.quiet {
				t.Errorf("narrated = %v under quiet=%v, want %q present only when not quiet; stderr:\n%s",
					got, tc.quiet, tc.want, stderr.String())
			}
		})
	}
}

func writeServerCert(t *testing.T, cfg *tls.Config, path string) {
	t.Helper()
	var pemBuf bytes.Buffer
	for _, der := range cfg.Certificates[0].Certificate {
		if err := pem.Encode(&pemBuf, &pem.Block{Type: "CERTIFICATE", Bytes: der}); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(path, pemBuf.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
}

// writeNarrationProject writes a project requiring example.com/mod@v1.0.0, with
// the go.sum line its go.mod hashes to, so `go list` resolves it from the fake.
func writeNarrationProject(t *testing.T, dir string) {
	t.Helper()
	h, err := dirhash.Hash1([]string{"go.mod"}, func(string) (io.ReadCloser, error) {
		return io.NopCloser(strings.NewReader(narrationModGoMod)), nil
	})
	if err != nil {
		t.Fatal(err)
	}
	gomod := "module example.com/app\n\ngo 1.21\n\nrequire example.com/mod v1.0.0\n"
	if err := os.WriteFile(filepath.Join(dir, "go.mod"), []byte(gomod), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "go.sum"), []byte("example.com/mod v1.0.0/go.mod "+h+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
}
