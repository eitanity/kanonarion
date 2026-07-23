package cli

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// logMessage is the message NewContainer emits on the orphaned-blob-temp
// cleanup path (container.go). It is the one log statement every query
// command reaches unconditionally, so it is the lever these tests pull to
// make a logger emit during an otherwise silent read-only query.
const logMessage = "orphaned blob temp files"

// poisonBlobTemps makes the orphaned-temp cleanup fail, so NewContainer logs
// at Warn — the default level. A .tmp-* *directory* with a file inside cannot
// be removed by os.Remove, and the failure is neither IsNotExist nor
// suppressed, so CleanOrphanedTemps returns an error. Nothing outside the
// caller's temp root is touched.
func poisonBlobTemps(t *testing.T, root string) {
	t.Helper()
	dir := filepath.Join(root, "blobs", ".tmp-unremovable")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatalf("creating poisoned temp dir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "occupant"), []byte("x"), 0o600); err != nil {
		t.Fatalf("occupying poisoned temp dir: %v", err)
	}
}

// TestQueryCommands_LogsGoToStderrNotStdout guards the invariant that stdout
// is reserved for a command's data output: when a logger emits during a query
// command, the line must land on stderr, leaving stdout parseable by the
// caller. Before the writer was threaded through these constructors the logger
// was built against stdout, so this WARN was interleaved into the --json
// document at the default verbosity with no flags set.
//
// The test asserts the log line actually fired on stderr as well as being
// absent from stdout: an assertion that stdout is clean is worthless if
// nothing logged at all.
func TestQueryCommands_LogsGoToStderrNotStdout(t *testing.T) {
	for _, tc := range []struct {
		name string
		args []string
	}{
		{"dependents", []string{"dependents", "example.com/mod@v1.0.0", "--walk-id", "absent"}},
		{"sbom-show", []string{"sbom-show", "absent"}},
		{"sbom-list", []string{"sbom-list"}},
		{"vuln", []string{"vuln", "example.com/mod@v1.0.0"}},
		{"vuln-show", []string{"vuln-show", "example.com/mod@v1.0.0"}},
		{"vuln-by-id", []string{"vuln-by-id", "GO-9999-0000"}},
		{"vuln-scan-list", []string{"vuln-scan-list"}},
		{"vuln-scan-show", []string{"vuln-scan-show", "absent"}},
		{"vuln-scan-history", []string{"vuln-scan-history", "absent"}},
		{"vuln-scan-diff", []string{"vuln-scan-diff", "absent-a", "absent-b"}},
		{"vuln-snapshot-list", []string{"vuln-snapshot-list"}},
		{"vuln-snapshot-show", []string{"vuln-snapshot-show", "govulndb", "v0"}},
		{"walk-show", []string{"walk-show", "absent"}},
		{"walk-diff", []string{"walk-diff", "absent-a", "absent-b"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			poisonBlobTemps(t, root)

			var stdout, stderr bytes.Buffer
			args := append(append([]string{}, tc.args...), "--json", "--store-root", root)
			// The query itself is expected to fail — the store is empty. The
			// invariant under test is where the log line went, not whether the
			// record was found.
			_ = Run(args, &stdout, &stderr)

			// Checked before the vacuity guard below, so a line that went to
			// the wrong writer is reported as the defect it is rather than as
			// a log that never fired.
			if strings.Contains(stdout.String(), logMessage) {
				t.Errorf("%s: log line written to stdout, corrupting the data channel: %q",
					tc.name, stdout.String())
			} else if !strings.Contains(stderr.String(), logMessage) {
				t.Fatalf("%s: the cleanup log never fired on either writer, so this case proves nothing",
					tc.name)
			}
			// stdout must be the caller's channel and nothing else: whatever
			// the command emitted under --json has to parse, including on the
			// empty-result path.
			if out := strings.TrimSpace(stdout.String()); out != "" {
				var v any
				if err := json.Unmarshal([]byte(out), &v); err != nil {
					t.Errorf("%s: stdout is not parseable JSON: %q", tc.name, out)
				}
			}
		})
	}
}

var (
	// A logger built against the stdout writer, in any command.
	loggerToStdoutRe = regexp.MustCompile(`buildLogger\([^,)]+,\s*stdout\b`)
	// A command constructor that takes the stderr writer and throws it away.
	// Discarding it leaves stdout as the only writer in scope, which is what
	// put the logger there in the first place.
	discardedWriterRe = regexp.MustCompile(`func new\w*Cmd\(stdout, _ io\.Writer\)`)
)

// TestNoCommandBuildsItsLoggerAgainstStdout guards the invariant across the
// whole package rather than only the commands enumerated above, so a command
// added later cannot reintroduce the defect in a path no behavioural test
// covers yet.
func TestNoCommandBuildsItsLoggerAgainstStdout(t *testing.T) {
	sources, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatalf("globbing package sources: %v", err)
	}
	if len(sources) == 0 {
		t.Fatal("no package sources found: the guard would pass vacuously")
	}

	for _, path := range sources {
		if strings.HasSuffix(path, "_test.go") {
			continue
		}
		data, rerr := os.ReadFile(path) /* #nosec G304 -- package-local source file */
		if rerr != nil {
			t.Fatalf("reading %s: %v", path, rerr)
		}
		for i, line := range strings.Split(string(data), "\n") {
			if loggerToStdoutRe.MatchString(line) {
				t.Errorf("%s:%d builds the logger against stdout; logs belong on stderr: %s",
					path, i+1, strings.TrimSpace(line))
			}
			if discardedWriterRe.MatchString(line) {
				t.Errorf("%s:%d discards the stderr writer; thread it through so logs have somewhere to go: %s",
					path, i+1, strings.TrimSpace(line))
			}
		}
	}
}
