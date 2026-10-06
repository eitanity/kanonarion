//go:build unix

package cli

import (
	"bytes"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"testing"
	"time"
)

// interruptHelperEnv switches a re-exec of this test binary into the CLI's
// entry point, exiting as cmd/kanonarion/main.go does so the exit code is the
// product's.
const interruptHelperEnv = "KANON_CLI_INTERRUPT_HELPER"

// TestInterruptedRunExitsCancelledWithOneStatement drives a real fetch into a
// proxy that never answers, signals the process the way an operator does, and
// reads what the operator is told.
func TestInterruptedRunExitsCancelledWithOneStatement(t *testing.T) {
	if args := os.Getenv(interruptHelperEnv); args != "" {
		err := Run(strings.Split(args, "\n"), os.Stdout, os.Stderr)
		if err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
		}
		os.Exit(ExitCodeForError(err))
	}

	for _, tc := range []struct {
		sig   syscall.Signal
		cause string
	}{
		{syscall.SIGINT, "interrupt signal received"},
		{syscall.SIGTERM, "terminated signal received"},
	} {
		t.Run(tc.sig.String(), func(t *testing.T) {
			asked := make(chan struct{}, 1)
			proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				select {
				case asked <- struct{}{}:
				default:
				}
				<-r.Context().Done()
			}))
			defer proxy.Close()

			args := strings.Join([]string{"fetch", "example.com/mod@v1.0.0", "--insecure", "--store-root", t.TempDir()}, "\n")
			cmd := exec.Command(os.Args[0], "-test.run=^TestInterruptedRunExitsCancelledWithOneStatement$") // #nosec G204 G702 -- re-execs this very test binary; the args are literals
			// The helper exits from inside the CLI, so its own temp files are never
			// removed by it; a TMPDIR under this test's temp dir is removed for it.
			cmd.Env = append(os.Environ(), interruptHelperEnv+"="+args,
				"GOPROXY="+proxy.URL, "GOSUMDB=off", "GONOSUMDB=*", "GOFLAGS=", "TMPDIR="+t.TempDir())
			var stdout, stderr bytes.Buffer
			cmd.Stdout, cmd.Stderr = &stdout, &stderr
			if err := cmd.Start(); err != nil {
				t.Fatalf("start helper: %v", err)
			}
			done := make(chan error, 1)
			go func() { done <- cmd.Wait() }()
			select {
			case <-asked:
			case werr := <-done:
				t.Fatalf("the run ended (%v) before its fetch reached the proxy; stderr:\n%s", werr, stderr.String())
			case <-time.After(30 * time.Second):
				_ = cmd.Process.Kill()
				<-done
				t.Fatalf("the fetch never reached the proxy; stderr:\n%s", stderr.String())
			}
			if err := cmd.Process.Signal(tc.sig); err != nil {
				t.Fatalf("signal helper: %v", err)
			}
			werr := <-done
			var ee *exec.ExitError
			if !errors.As(werr, &ee) || ee.ExitCode() != ExitCancelled {
				t.Fatalf("interrupted run exited %v, want %d (Cancelled); stderr:\n%s", werr, ExitCancelled, stderr.String())
			}

			var statements []string
			for line := range strings.SplitSeq(stderr.String(), "\n") {
				if strings.HasPrefix(line, "interrupted") {
					statements = append(statements, line)
				}
				if strings.Contains(line, "level=WARN") || strings.Contains(line, "level=ERROR") {
					t.Errorf("an interrupted run logged a warning: %s", line)
				}
			}
			if len(statements) != 1 || !strings.Contains(statements[0], tc.cause) {
				t.Errorf("want exactly one interruption statement naming %q; got %q\nstderr:\n%s", tc.cause, statements, stderr.String())
			}
			if !strings.Contains(stderr.String(), "\nerror: ") {
				t.Errorf("the closing error line saying what was not done is missing; stderr:\n%s", stderr.String())
			}
			t.Logf("stderr:\n%s", stderr.String())
			if stdout.Len() != 0 {
				t.Errorf("an interrupted fetch wrote to stdout: %q", stdout.String())
			}
		})
	}
}
