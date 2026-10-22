package golist_test

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/eitanity/kanonarion/internal/adapters/goenv"
	"github.com/eitanity/kanonarion/internal/staleness/adapters/golist"
	"github.com/eitanity/kanonarion/internal/staleness/ports"
)

// fakeGo puts a `go` on PATH that logs its argv and runs body.
func fakeGo(t *testing.T, body string) string {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("the fake go command is a shell script")
	}
	dir := t.TempDir()
	log := filepath.Join(dir, "argv")
	script := "#!/bin/sh\nprintf '%s\\n' \"$*\" >> " + log + "\n" + body + "\n"
	if err := os.WriteFile(filepath.Join(dir, "go"), []byte(script), 0o700); err != nil { // #nosec G306 -- a stub must be executable
		t.Fatal(err)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
	t.Setenv("GOPROXY", "https://proxy.example.com")
	return log
}

// TestPrivateResolver_AsksTheGoCommandForThePathAtLatest.
func TestPrivateResolver_AsksTheGoCommandForThePathAtLatest(t *testing.T) {
	log := fakeGo(t, `echo '{"Path":"corp.example.com/a","Version":"v1.2.0","Time":"2026-03-04T00:00:00Z"}'`)
	info, err := golist.NewPrivate(t.TempDir(), "").LatestInfo(context.Background(), "corp.example.com/a")
	if err != nil {
		t.Fatalf("LatestInfo: %v", err)
	}
	if info.Version != "v1.2.0" || info.Time.IsZero() {
		t.Errorf("info = %+v, want v1.2.0 with its date", info)
	}
	argv, err := os.ReadFile(log) // #nosec G304 -- this test's own file
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.TrimSpace(string(argv)); got != "list -m -json -mod=readonly corp.example.com/a@latest" {
		t.Errorf("go was run with %q", got)
	}
}

// TestPrivateResolver_FailuresAreErrPrivateModule: a go command that fails, or
// names no version, is the private reason with the go command's own words.
func TestPrivateResolver_FailuresAreErrPrivateModule(t *testing.T) {
	for name, body := range map[string]string{
		"exit 1":     `echo 'go: corp.example.com/a@latest: unrecognized import path' >&2; exit 1`,
		"no version": `echo '{"Path":"corp.example.com/a"}'`,
		"not json":   `echo 'garbage'`,
	} {
		t.Run(name, func(t *testing.T) {
			fakeGo(t, body)
			_, err := golist.NewPrivate("", "").LatestInfo(context.Background(), "corp.example.com/a")
			if !errors.Is(err, ports.ErrPrivateModule) {
				t.Fatalf("err = %v, want ErrPrivateModule", err)
			}
			if name == "exit 1" && !strings.Contains(err.Error(), "unrecognized import path") {
				t.Errorf("err = %v, want the go command's stderr", err)
			}
		})
	}
}

// TestPrivateResolver_RefusesWithoutTheNetwork: under GOPROXY=off, or
// --goproxy off, the go command is not run at all.
func TestPrivateResolver_RefusesWithoutTheNetwork(t *testing.T) {
	for name, override := range map[string]string{"env": "", "flag": "off"} {
		t.Run(name, func(t *testing.T) {
			log := fakeGo(t, "exit 0")
			if override == "" {
				t.Setenv("GOPROXY", "off")
			}
			_, err := golist.NewPrivate("", override).LatestInfo(context.Background(), "corp.example.com/a")
			if !errors.Is(err, ports.ErrPrivateModule) || !errors.Is(err, goenv.ErrNetworkForbidden) {
				t.Fatalf("err = %v, want ErrPrivateModule wrapping the no-network fact", err)
			}
			if _, serr := os.Stat(log); serr == nil {
				t.Error("the go command ran with the network forbidden")
			}
		})
	}
}

// TestPrivateResolver_CancelledIsNotAPrivateAnswer.
func TestPrivateResolver_CancelledIsNotAPrivateAnswer(t *testing.T) {
	fakeGo(t, "sleep 5")
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := golist.NewPrivate("", "").LatestInfo(ctx, "corp.example.com/a")
	if !errors.Is(err, context.Canceled) {
		t.Errorf("err = %v, want the cancellation", err)
	}
}
