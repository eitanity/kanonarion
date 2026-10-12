package cli

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"sync"
	"testing"

	"github.com/eitanity/kanonarion/internal/adapters/goenv"
	proxyadapter "github.com/eitanity/kanonarion/internal/adapters/proxy/direct"
	"github.com/eitanity/kanonarion/internal/adapters/sumdb/gosum"
	"github.com/eitanity/kanonarion/internal/adapters/vcs/gitexec"
	"github.com/eitanity/kanonarion/internal/coordinate/coordinatetest"
	stalegolist "github.com/eitanity/kanonarion/internal/staleness/adapters/golist"
	"github.com/eitanity/kanonarion/internal/stdlib/adapters/gitlsremote"
	"github.com/eitanity/kanonarion/internal/stdlib/adapters/godev"
	stdlibdomain "github.com/eitanity/kanonarion/internal/stdlib/domain"
	osvdb "github.com/eitanity/kanonarion/internal/vuln/adapters/vulndb/osv"
)

// flagAirGapFixture is a one-module project whose module is published to a file
// proxy and held in its own module cache, so every command can get as far as
// its egress decisions without the network and without the host's cache.
type flagAirGapFixture struct {
	proxy, modcache, project, store string
	gitLog, goLog                   string
	// live is a TLS module proxy serving the fixture: the route an environment
	// names when the network is permitted. Its address is the one dial allowed.
	live, liveAddr string
}

// buildFlagAirGapFixture publishes example.com/mod@v1.0.0, writes a project
// requiring it, and puts recording `git` and `go` stubs at the front of PATH:
// git answers nothing and logs its argv; go logs the GOPROXY it was given and
// runs the real toolchain.
func buildFlagAirGapFixture(t *testing.T) *flagAirGapFixture {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("the recording stubs are shell scripts")
	}
	realGo, err := exec.LookPath("go")
	if err != nil {
		t.Skip("go toolchain not on PATH")
	}
	root := t.TempDir()
	fx := &flagAirGapFixture{
		proxy:    filepath.Join(root, "proxy"),
		modcache: filepath.Join(root, "modcache"),
		project:  filepath.Join(root, "project"),
		store:    filepath.Join(root, "store"),
		gitLog:   filepath.Join(root, "git.log"),
		goLog:    filepath.Join(root, "go.log"),
	}
	bin := filepath.Join(root, "bin")
	for _, d := range []string{fx.proxy, fx.modcache, fx.project, bin} {
		if err := os.MkdirAll(d, 0o750); err != nil {
			t.Fatalf("creating %s: %v", d, err)
		}
	}
	publishAirGapModule(t, fx.proxy)
	writeAirGapFile(t, filepath.Join(fx.project, "go.mod"),
		"module example.com/app\n\ngo 1.24\n\nrequire example.com/mod v1.0.0\n")
	writeAirGapFile(t, filepath.Join(fx.project, "main.go"),
		"package main\n\nimport \"example.com/mod\"\n\nfunc main() { mod.Handle() }\n")
	publish := []string{"GOPROXY=file://" + fx.proxy, "GOMODCACHE=" + fx.modcache,
		"GOSUMDB=off", "GOFLAGS=-mod=mod -modcacherw", "GOTOOLCHAIN=local", "GOENV=off"}
	for _, args := range [][]string{{"mod", "tidy"}, {"list", "-m", "-json", "all"}} {
		cmd := exec.Command(realGo, args...) // #nosec G204 -- literal arguments, test fixture only
		cmd.Dir = fx.project
		cmd.Env = append(os.Environ(), publish...)
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("go %s: %v\n%s", strings.Join(args, " "), err, out)
		}
	}

	writeAirGapExec(t, filepath.Join(bin, "git"), "#!/bin/sh\nprintf '%s\\n' \"$*\" >> "+fx.gitLog+"\nexit 1\n")
	writeAirGapExec(t, filepath.Join(bin, "go"),
		"#!/bin/sh\nprintf '%s|%s\\n' \"$GOPROXY\" \"$*\" >> "+fx.goLog+"\nexec "+realGo+" \"$@\"\n")
	t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))
	t.Setenv("GOMODCACHE", fx.modcache)
	t.Setenv("GOENV", "off")
	t.Setenv("GOTOOLCHAIN", "local")
	t.Setenv("GOFLAGS", "")
	t.Setenv("GOSUMDB", "")
	t.Setenv("GONOSUMDB", "")
	t.Setenv("GOPRIVATE", "")
	t.Setenv("GONOSUMCHECK", "")
	t.Setenv("KANONARION_STORE", fx.store)

	srv := httptest.NewTLSServer(http.FileServer(http.Dir(fx.proxy)))
	t.Cleanup(srv.Close)
	fx.live, fx.liveAddr = srv.URL, srv.Listener.Addr().String()
	transport, ok := http.DefaultTransport.(*http.Transport)
	if !ok {
		t.Fatalf("http.DefaultTransport is %T", http.DefaultTransport)
	}
	pool := x509.NewCertPool()
	pool.AddCert(srv.Certificate())
	originalTLS := transport.TLSClientConfig
	transport.TLSClientConfig = &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}
	t.Cleanup(func() { transport.TLSClientConfig = originalTLS })
	return fx
}

// airGapRun is one invocation and every egress it attempted.
type airGapRun struct {
	stdout, stderr string
	exit           int
	dials, git     []string
	// goNotOff lists the go children that were not handed GOPROXY=off.
	goNotOff []string
}

// run executes args from the project directory against a fresh store at the
// fixture's one store path, with GOPROXY set to envProxy.
func (fx *flagAirGapFixture) run(t *testing.T, envProxy string, args ...string) airGapRun {
	t.Helper()
	for _, p := range []string{fx.store, fx.gitLog, fx.goLog} {
		if err := os.RemoveAll(p); err != nil {
			t.Fatalf("resetting %s: %v", p, err)
		}
	}
	if err := os.MkdirAll(fx.store, 0o750); err != nil {
		t.Fatalf("creating store: %v", err)
	}
	t.Setenv("GOPROXY", envProxy)
	t.Chdir(fx.project)
	dials := refuseEveryDial(t, fx.liveAddr)

	var stdout, stderr bytes.Buffer
	err := Run(args, &stdout, &stderr)
	if err != nil {
		// What main prints, so stderr is the operator's stream.
		stderr.WriteString("error: " + err.Error() + "\n")
	}
	r := airGapRun{stdout: stdout.String(), stderr: stderr.String(), exit: ExitCodeForError(err),
		dials: dials.addrs(), git: readAirGapLog(t, fx.gitLog)}
	for _, line := range readAirGapLog(t, fx.goLog) {
		if proxy, _, _ := strings.Cut(line, "|"); proxy != "off" {
			r.goNotOff = append(r.goNotOff, line)
		}
	}
	if got := os.Getenv("GOPROXY"); got != envProxy {
		t.Errorf("GOPROXY is %q after the run, want the %q it started with", got, envProxy)
	}
	return r
}

// TestGoproxyFlagOff_IsTheEnvironmentAirGap: `--goproxy off` declares the same
// air gap as GOPROXY=off. Under the flag, with the environment naming a live
// route, no command dials, spawns git, or hands a go child anything but
// GOPROXY=off — and each prints what the environment form prints.
func TestGoproxyFlagOff_IsTheEnvironmentAirGap(t *testing.T) {
	fx := buildFlagAirGapFixture(t)
	gomod := filepath.Join(fx.project, "go.mod")
	cases := []struct {
		name string
		args []string
	}{
		{"audit", []string{"audit", "--gomod", gomod, "--no-progress"}},
		// Bytes from the cache, so the checksum database and VCS verification
		// are reached rather than stopped behind a refused module fetch.
		{"audit --from-modcache", []string{"audit", "--gomod", gomod, "--from-modcache=" + fx.modcache, "--no-progress"}},
		{"fetch", []string{"fetch", "example.com/mod@v1.0.0"}},
		{"inspect", []string{"inspect", "example.com/mod@v1.0.0", "--no-progress"}},
		{"inspect @latest", []string{"inspect", "example.com/mod@latest", "--no-progress"}},
		{"latest", []string{"latest", "example.com/mod"}},
		{"walk --gomod", []string{"walk", "--gomod", gomod, "--no-progress"}},
		{"walk --gomod --from-modcache", []string{"walk", "--gomod", gomod, "--from-modcache=" + fx.modcache, "--no-progress"}},
		{"walk positional", []string{"walk", "example.com/mod@v1.0.0", "--no-progress"}},
	}
	live := fx.live
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			flag := fx.run(t, live, append(append([]string{}, tc.args...), "--goproxy", "off")...)
			env := fx.run(t, "off", tc.args...)
			for form, r := range map[string]airGapRun{"--goproxy off": flag, "GOPROXY=off": env} {
				if len(r.dials) != 0 {
					t.Errorf("%s dialled %v", form, r.dials)
				}
				if len(r.git) != 0 {
					t.Errorf("%s spawned git %v", form, r.git)
				}
				if len(r.goNotOff) != 0 {
					t.Errorf("%s handed go children another GOPROXY: %v", form, r.goNotOff)
				}
			}
			if flag.exit != env.exit {
				t.Errorf("exit: --goproxy off %d, GOPROXY=off %d", flag.exit, env.exit)
			}
			if a, b := normaliseRun(flag.stdout), normaliseRun(env.stdout); a != b {
				t.Errorf("stdout differs\n--goproxy off:\n%s\nGOPROXY=off:\n%s", a, b)
			}
			if a, b := normaliseRun(flag.stderr), normaliseRun(env.stderr); a != b {
				t.Errorf("stderr differs\n--goproxy off:\n%s\nGOPROXY=off:\n%s", a, b)
			}
		})
	}
}

// TestGoproxyFlagOff_ControlReachesEveryInstrument is the non-zero half: the
// same audit with no air gap declared reaches each egress member, so the zeros
// above are refusals and not blind instruments.
func TestGoproxyFlagOff_ControlReachesEveryInstrument(t *testing.T) {
	fx := buildFlagAirGapFixture(t)
	r := fx.run(t, fx.live, "audit", "--gomod", filepath.Join(fx.project, "go.mod"), "--no-progress")
	dialled := strings.Join(r.dials, " ")
	for member, host := range map[string]string{
		"checksum database": "sum.golang.org:443",
		"go.dev/dl stdlib":  "go.dev:443",
		"advisory database": "vuln.go.dev:443",
	} {
		if !strings.Contains(dialled, host) {
			t.Errorf("%s: no dial to %s with the network permitted (dials %v)", member, host, r.dials)
		}
	}
	if len(r.git) == 0 {
		t.Error("VCS verification: no git spawn with the network permitted")
	}
	if len(r.goNotOff) == 0 {
		t.Error("go children: none saw the live GOPROXY with the network permitted")
	}
}

// TestGoproxyFlag_MixedFormsAgree: when the flag and the environment disagree,
// the flag is the one GOPROXY for the whole process. Under env GOPROXY=off with
// a proxy URL flag, the in-process egress members go to the network and every go
// child is handed that URL, not off. The opposite mix, env URL with an off flag,
// is TestGoproxyFlagOff_IsTheEnvironmentAirGap.
func TestGoproxyFlag_MixedFormsAgree(t *testing.T) {
	fx := buildFlagAirGapFixture(t)
	r := fx.run(t, "off", "audit", "--gomod", filepath.Join(fx.project, "go.mod"), "--no-progress", "--goproxy", fx.live)
	children := readAirGapLog(t, fx.goLog)
	if len(children) == 0 {
		t.Fatal("no go child recorded")
	}
	for _, line := range children {
		if proxy, _, _ := strings.Cut(line, "|"); proxy != fx.live {
			t.Errorf("a go child was handed GOPROXY=%q, want the flag's %q: %s", proxy, fx.live, line)
		}
	}
	dialled := strings.Join(r.dials, " ")
	for member, host := range map[string]string{
		"checksum database": "sum.golang.org:443",
		"advisory database": "vuln.go.dev:443",
	} {
		if !strings.Contains(dialled, host) {
			t.Errorf("%s: no dial to %s under a proxy-URL flag (dials %v)", member, host, r.dials)
		}
	}
	if len(r.git) == 0 {
		t.Error("VCS verification: no git spawn under a proxy-URL flag")
	}
}

// TestGoproxyFlagDirect_KeepsTheEnvironmentAirGap: `--goproxy direct` declares
// nothing, so under env GOPROXY=off no command dials, spawns git, or hands a go
// child anything but off.
func TestGoproxyFlagDirect_KeepsTheEnvironmentAirGap(t *testing.T) {
	fx := buildFlagAirGapFixture(t)
	gomod := filepath.Join(fx.project, "go.mod")
	for _, args := range [][]string{
		{"audit", "--gomod", gomod, "--no-progress"},
		{"fetch", "example.com/mod@v1.0.0"},
		{"inspect", "example.com/mod@v1.0.0", "--no-progress"},
		{"latest", "example.com/mod"},
		{"walk", "--gomod", gomod, "--no-progress"},
		{"walk", "example.com/mod@v1.0.0", "--no-progress"},
	} {
		t.Run(strings.Join(args[:1], " "), func(t *testing.T) {
			r := fx.run(t, "off", append(append([]string{}, args...), "--goproxy", "direct")...)
			if len(r.dials) != 0 {
				t.Errorf("%v dialled %v", args, r.dials)
			}
			if len(r.git) != 0 {
				t.Errorf("%v spawned git %v", args, r.git)
			}
			if len(r.goNotOff) != 0 {
				t.Errorf("%v handed go children another GOPROXY: %v", args, r.goNotOff)
			}
		})
	}
}

// TestGoproxyFlagDirect_Unchanged: `--goproxy direct` is not an air gap. The
// environment's route stays in force for everything but the module proxy, which
// refuses the mode as before.
func TestGoproxyFlagDirect_Unchanged(t *testing.T) {
	fx := buildFlagAirGapFixture(t)
	r := fx.run(t, fx.live, "fetch", "example.com/mod@v1.0.0", "--goproxy", "direct")
	if r.exit != ExitConfig || !strings.Contains(r.stderr, "GOPROXY=direct") {
		t.Errorf("fetch --goproxy direct: exit %d, stderr %q; want the direct-mode refusal", r.exit, r.stderr)
	}
	if strings.Contains(r.stderr, "GOPROXY=off") {
		t.Errorf("--goproxy direct reported as an air gap: %q", r.stderr)
	}
}

var (
	runTimestamp = regexp.MustCompile(`time=\S+`)
	runULID      = regexp.MustCompile(`\b[0-9A-HJKMNP-TV-Z]{26}\b`)
	runDuration  = regexp.MustCompile(`\b\d+(\.\d+)?(ms|s|µs)\b`)
)

// normaliseRun removes what differs between any two runs: log timestamps, minted
// identifiers and elapsed times.
func normaliseRun(s string) string {
	s = runTimestamp.ReplaceAllString(s, "time=T")
	s = runULID.ReplaceAllString(s, "ULID")
	return runDuration.ReplaceAllString(s, "DUR")
}

// dialLog refuses every dial through http.DefaultTransport but the fixture
// proxy's, and records where it was going. Every in-process egress here (module proxy, checksum database,
// advisory database, go.dev/dl) builds its client on that transport.
type dialLog struct {
	mu   sync.Mutex
	seen []string
}

func refuseEveryDial(t *testing.T, allowed string) *dialLog {
	t.Helper()
	transport, ok := http.DefaultTransport.(*http.Transport)
	if !ok {
		t.Fatalf("http.DefaultTransport is %T", http.DefaultTransport)
	}
	l := &dialLog{}
	original := transport.DialContext
	transport.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
		if addr == allowed {
			var d net.Dialer
			return d.DialContext(ctx, network, addr) //nolint:wrapcheck // stands in for net.Dialer
		}
		l.mu.Lock()
		l.seen = append(l.seen, addr)
		l.mu.Unlock()
		return nil, errors.New("dial refused by the test")
	}
	t.Cleanup(func() { transport.DialContext = original })
	return l
}

func (l *dialLog) addrs() []string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return append([]string(nil), l.seen...)
}

func readAirGapLog(t *testing.T, path string) []string {
	t.Helper()
	data, err := os.ReadFile(path) // #nosec G304 -- this test's own temp file
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		t.Fatalf("reading %s: %v", path, err)
	}
	var out []string
	for line := range strings.SplitSeq(strings.TrimSpace(string(data)), "\n") {
		if line != "" {
			out = append(out, line)
		}
	}
	return out
}

// publishAirGapModule writes example.com/mod@v1.0.0 into a file proxy.
func publishAirGapModule(t *testing.T, proxy string) {
	t.Helper()
	dir := filepath.Join(proxy, "example.com", "mod", "@v")
	if err := os.MkdirAll(dir, 0o750); err != nil {
		t.Fatalf("creating proxy dir: %v", err)
	}
	gomod := "module example.com/mod\n\ngo 1.24\n"
	writeAirGapFile(t, filepath.Join(dir, "v1.0.0.mod"), gomod)
	writeAirGapFile(t, filepath.Join(dir, "v1.0.0.info"), `{"Version":"v1.0.0","Time":"2025-06-01T00:00:00Z"}`)
	writeAirGapFile(t, filepath.Join(dir, "list"), "v1.0.0\n")
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for _, e := range []struct{ name, body string }{
		{"go.mod", gomod},
		{"mod.go", "package mod\n\n// Handle is called by the fixture project.\nfunc Handle() {}\n"},
	} {
		w, err := zw.Create("example.com/mod@v1.0.0/" + e.name)
		if err != nil {
			t.Fatalf("zip entry %s: %v", e.name, err)
		}
		if _, err := w.Write([]byte(e.body)); err != nil {
			t.Fatalf("zip entry %s: %v", e.name, err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatalf("closing zip: %v", err)
	}
	writeAirGapFile(t, filepath.Join(dir, "v1.0.0.zip"), buf.String())
}

func writeAirGapFile(t *testing.T, path, body string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("writing %s: %v", path, err)
	}
}

func writeAirGapExec(t *testing.T, path, body string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(body), 0o700); err != nil { // #nosec G306 -- a stub must be executable
		t.Fatalf("writing %s: %v", path, err)
	}
}

// TestGoproxyFlagOff_EveryEgressMemberRefuses asserts each egress member, one by
// one, after each of the five commands' pre-run has read its own --goproxy flag, with the environment naming a live route. In-process members
// are held to zero dials, git members to zero spawns, and a go child's
// environment must carry GOPROXY=off.
func TestGoproxyFlagOff_EveryEgressMemberRefuses(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("the recording git stub is a shell script")
	}
	bin := t.TempDir()
	gitLog := filepath.Join(bin, "git.log")
	writeAirGapExec(t, filepath.Join(bin, "git"), "#!/bin/sh\nprintf '%s\\n' \"$*\" >> "+gitLog+"\nexit 1\n")
	t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))
	for _, k := range []string{"GOSUMDB", "GONOSUMDB", "GOPRIVATE", "GONOSUMCHECK"} {
		t.Setenv(k, "")
	}
	t.Setenv("GOENV", "off")
	const live = "https://proxy.example.com"
	t.Setenv("GOPROXY", live)

	for _, name := range []string{"audit", "fetch", "inspect", "latest", "walk"} {
		t.Run(name, func(t *testing.T) {
			preRunWithGoproxyOff(t, name)
			dials := refuseEveryDial(t, "")
			for _, failure := range egressMemberFailures(t) {
				t.Error(failure)
			}
			if got := os.Getenv("GOPROXY"); got != "off" {
				t.Errorf("a go child would inherit GOPROXY=%q", got)
			}
			if got := dials.addrs(); len(got) != 0 {
				t.Errorf("dialled %v", got)
			}
			if got := readAirGapLog(t, gitLog); len(got) != 0 {
				t.Errorf("spawned git %v", got)
			}

			resetInvocationState()
			if got := os.Getenv("GOPROXY"); got != live {
				t.Errorf("GOPROXY after the invocation = %q, want %q restored", got, live)
			}
			if _, err := proxyadapter.New("", false); err != nil {
				t.Errorf("the declaration outlived its invocation: %v", err)
			}
		})
	}
}

// preRunWithGoproxyOff runs the root pre-run for one command given --goproxy off,
// which is where a command line's flags become the invocation's state.
func preRunWithGoproxyOff(t *testing.T, name string) {
	t.Helper()
	root := newRootCmd(io.Discard, io.Discard)
	installDefaultSubcommands(root)
	cmd, _, err := root.Find([]string{name})
	if err != nil || cmd.Name() != name {
		t.Fatalf("finding %s: %v", name, err)
	}
	if err := cmd.Flags().Set("goproxy", "off"); err != nil {
		t.Fatalf("setting --goproxy: %v", err)
	}
	t.Setenv("KANONARION_STORE", t.TempDir())
	if err := root.PersistentPreRunE(cmd, nil); err != nil {
		t.Fatalf("pre-run with --goproxy off: %v", err)
	}
}

// egressMemberFailures asks each egress member to reach the network and returns
// a line for every one that did not refuse with the no-network fact.
func egressMemberFailures(t *testing.T) []string {
	t.Helper()
	ctx := context.Background()
	coord := coordinatetest.MustNew("example.com/mod", "v1.0.0")
	var out []string
	refused := func(member string, err, want error) {
		if !errors.Is(err, want) {
			out = append(out, fmt.Sprintf("%s: %v, want %v", member, err, want))
		}
	}
	if res := gosum.New(t.TempDir()).Lookup(ctx, coord); res.Available || res.LookupFailed() {
		out = append(out, fmt.Sprintf("checksum database: available=%v failed=%v, want disabled", res.Available, res.LookupFailed()))
	}
	_, err := osvdb.New(nil, nil, nil).LatestVersion(ctx)
	refused("advisory database", err, goenv.ErrNetworkForbidden)
	_, err = godev.New().FetchReleases(ctx)
	refused("go.dev/dl", err, goenv.ErrNetworkForbidden)
	if !offlineStdlibAnchor(false) {
		out = append(out, "stdlib: the go.dev/dl acquirer is still selected")
	}
	_, err = gitexec.New().ResolveTag(ctx, "https://example.com/mod", "refs/tags/v1.0.0")
	refused("VCS verification", err, goenv.ErrNetworkForbidden)
	_, err = gitlsremote.New().ResolveCommit(ctx, stdlibdomain.VCSRepoURL, "go1.26.4")
	refused("stdlib git anchor", err, goenv.ErrNetworkForbidden)
	_, err = stalegolist.New(t.TempDir(), "").LatestBatch(ctx, []string{"example.com/mod"})
	refused("staleness batch", err, stalegolist.ErrNoUpdateCheck)
	_, err = proxyadapter.New("", false)
	refused("module proxy", err, proxyadapter.ErrProxyOff)
	return out
}
