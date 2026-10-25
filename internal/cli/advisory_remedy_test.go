package cli

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	osvdb "github.com/eitanity/kanonarion/internal/vuln/adapters/vulndb/osv"
	vuldomain "github.com/eitanity/kanonarion/internal/vuln/domain"
)

// withSnapshotsHeld makes the store report held as its snapshots, newest first.
func withSnapshotsHeld(t *testing.T, held []vuldomain.DatabaseSnapshot, err error) {
	t.Helper()
	orig := storedSnapshots
	t.Cleanup(func() { storedSnapshots = orig })
	storedSnapshots = func(context.Context) ([]vuldomain.DatabaseSnapshot, error) { return held, err }
}

// govulncheckStubOnPath puts a stub govulncheck first on PATH, so the scanner
// pre-flight passes on a host without one and the test reaches what it asserts.
func govulncheckStubOnPath(t *testing.T) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("the govulncheck stub is a POSIX shell script")
	}
	dir := t.TempDir()
	writeStub(t, filepath.Join(dir, "govulncheck"), "#!/bin/sh\nexit 1\n")
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
}

// The advisory-database refusal names only what the command that hit it
// accepts: --fresh only when it was given, the pin only on the re-scan, and no
// pin at all from a store that holds no snapshot.
func TestAdvisoryRefusal_NamesWhatTheCommandAccepts(t *testing.T) {
	govulncheckStubOnPath(t)
	seeded := seedOneWalkStore(t)
	held := []vuldomain.DatabaseSnapshot{fixtureSnap}
	pin := "kanonarion vuln-scan-rescan " + nsWalkID + " --snapshot-source govulndb --snapshot-version v2025-01-01T00-00-00"
	for _, tc := range []struct {
		name     string
		args     []string
		held     []vuldomain.DatabaseSnapshot
		want     []string
		mustNot  []string
		wantCode int
	}{
		{"vuln-scan, nothing held", []string{"vuln-scan", nsWalkID}, nil,
			[]string{"the store holds no advisory-database snapshot"}, []string{"--fresh", "--snapshot-source", "vuln-snapshot-list"}, ExitConfig},
		{"vuln-scan, one held", []string{"vuln-scan", nsWalkID}, held,
			[]string{"the store holds 1 snapshot(s)", "kanonarion vuln-snapshot-list"}, []string{"--fresh", "--snapshot-source"}, ExitConfig},
		{"vuln-scan --fresh, nothing held", []string{"vuln-scan", nsWalkID, "--fresh"}, nil,
			[]string{"the store holds no advisory-database snapshot"}, []string{"drop --fresh", "--snapshot-source"}, ExitConfig},
		{"vuln-scan --fresh, one held", []string{"vuln-scan", nsWalkID, "--fresh"}, held,
			[]string{"drop --fresh and the scan is judged against the newest, govulndb@v2025-01-01T00-00-00", "kanonarion vuln-snapshot-list"},
			[]string{"--snapshot-source"}, ExitConfig},
		{"vuln-scan-rescan, nothing held", []string{"vuln-scan-rescan", nsWalkID}, nil,
			[]string{"the store holds no advisory-database snapshot"}, []string{"--fresh", "--snapshot-source"}, ExitConfig},
		{"vuln-scan-rescan, one held", []string{"vuln-scan-rescan", nsWalkID}, held,
			[]string{pin, "kanonarion vuln-snapshot-list"}, []string{"--fresh"}, ExitConfig},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("GOPROXY", "off")
			withSnapshotsHeld(t, tc.held, nil)
			var stdout, stderr bytes.Buffer
			err := Run(append(tc.args, "--store-root", seeded, "--no-progress"), &stdout, &stderr)
			if err == nil {
				t.Fatal("a scan with no advisory database and no network succeeded")
			}
			if code := ExitCodeForError(err); code != tc.wantCode {
				t.Errorf("exit %d, want %d", code, tc.wantCode)
			}
			msg := err.Error()
			for _, w := range tc.want {
				if !strings.Contains(msg, w) {
					t.Errorf("the refusal is missing %q:\n%s", w, msg)
				}
			}
			for _, w := range tc.mustNot {
				if strings.Contains(msg, w) {
					t.Errorf("the refusal names %q, which this command was not given or does not take:\n%s", w, msg)
				}
			}
		})
	}
}

// Without --fresh a store holding snapshots is stated, not given a flag to drop.
func TestScanOffline_NamesFreshOnlyWhenGiven(t *testing.T) {
	held := []vuldomain.DatabaseSnapshot{fixtureSnap}
	if got := scanOffline(false)(held); strings.Contains(got, "--fresh") {
		t.Errorf("scanOffline(false) = %q, names a flag that was not given", got)
	}
	if got := scanOffline(true)(held); !strings.Contains(got, "drop --fresh") {
		t.Errorf("scanOffline(true) = %q, want it to drop --fresh", got)
	}
}

// Any other error passes through untouched, and a store whose snapshots cannot
// be counted says so instead of guessing a remedy.
func TestWithAdvisoryRemedy_LeavesOtherErrorsAndNamesACountFailure(t *testing.T) {
	other := errors.New("unrelated")
	if got := withAdvisoryRemedy(context.Background(), other, scanOffline(true)); !errors.Is(got, other) || got.Error() != other.Error() {
		t.Errorf("an unrelated error was changed: %v", got)
	}
	withSnapshotsHeld(t, nil, errors.New("planted count failure"))
	refusal := fmt.Errorf("%w: https://vuln.go.dev/vulndb.zip not fetched", osvdb.ErrNetworkForbidden)
	got := withAdvisoryRemedy(context.Background(), refusal, scanOffline(true))
	if !errors.Is(got, refusal) || !strings.Contains(got.Error(), "could not be counted: planted count failure") {
		t.Errorf("a failed count is not stated beside the refusal: %v", got)
	}
}

// The count is the store's own snapshot read, opened for inspection: a store
// holding none answers none, and a root holding no store answers none without
// creating one.
func TestStoredSnapshots_ReadsTheStoreWithoutCreatingOne(t *testing.T) {
	t.Cleanup(func() { storeRoot = defaultStoreRoot() })
	storeRoot = seedOneWalkStore(t)
	if held, err := storedSnapshots(context.Background()); err != nil || len(held) != 0 {
		t.Errorf("a store holding no snapshot answered %v, %v", held, err)
	}
	storeRoot = filepath.Join(t.TempDir(), "never")
	if held, err := storedSnapshots(context.Background()); err != nil || len(held) != 0 {
		t.Errorf("a root holding no store answered %v, %v", held, err)
	}
}
