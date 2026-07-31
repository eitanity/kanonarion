package cli

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/eitanity/kanonarion/internal/cli/testfakes"
	"github.com/eitanity/kanonarion/internal/coordinate/coordinatetest"
	licapp "github.com/eitanity/kanonarion/internal/license/application"
	licdomain "github.com/eitanity/kanonarion/internal/license/domain"
	walkdomain "github.com/eitanity/kanonarion/internal/walk/domain"
	walkports "github.com/eitanity/kanonarion/internal/walk/ports"
)

// ---- symbol-context positional grammar ------------------------------------

// Every sibling record command takes <module>@<version> positionally, so that
// is the form a caller tries first. Accepting it here costs nothing and removes
// a failed round trip; the bare-name form stays primary.
func TestSymbolContextArgs_AcceptsBothPositionalForms(t *testing.T) {
	for _, tc := range []struct {
		name       string
		args       []string
		flagModule string
		wantName   string
		wantModule string
		wantOK     bool
		wantErr    bool
	}{
		{name: "bare name", args: []string{"ToStringE"}, wantName: "ToStringE", wantOK: true},
		{
			name: "coordinate then name", args: []string{"github.com/spf13/cast@v1.4.1", "ToStringE"},
			wantName: "ToStringE", wantModule: "github.com/spf13/cast@v1.4.1", wantOK: true,
		},
		{
			name: "coordinate positional agrees with --module", args: []string{"github.com/spf13/cast@v1.4.1", "ToStringE"},
			flagModule: "github.com/spf13/cast@v1.4.1",
			wantName:   "ToStringE", wantModule: "github.com/spf13/cast@v1.4.1", wantOK: true,
		},
		{
			name: "coordinate positional disagrees with --module", args: []string{"github.com/spf13/cast@v1.4.1", "ToStringE"},
			flagModule: "github.com/spf13/cobra@v1.8.1",
			wantErr:    true,
		},
		{
			// A '@'-less first argument of two is not a coordinate, so the
			// two-argument grammar does not apply and usage is the answer.
			name: "two bare names", args: []string{"cast", "ToStringE"},
		},
		{
			// '@' in a lone argument stays a symbol name: guessing it was a
			// truncated coordinate would swallow the name the caller gave.
			name: "lone argument containing @", args: []string{"weird@name"},
			wantName: "weird@name", wantOK: true,
		},
		{name: "no arguments", args: nil},
		{name: "three arguments", args: []string{"a@v1", "b", "c"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := symbolContextFlags{module: tc.flagModule}
			name, conflict, ok := symbolContextArgs(tc.args, &f)
			if tc.wantErr {
				if conflict == nil {
					t.Fatalf("want a named conflict, got name=%q ok=%v", name, ok)
				}
				if !strings.Contains(conflict.Error(), "module given twice") {
					t.Errorf("conflict must name the disagreement, got: %v", conflict)
				}
				return
			}
			if conflict != nil {
				t.Fatalf("unexpected conflict: %v", conflict)
			}
			if ok != tc.wantOK {
				t.Fatalf("ok: want %v, got %v", tc.wantOK, ok)
			}
			if !ok {
				return
			}
			if name != tc.wantName {
				t.Errorf("name: want %q, got %q", tc.wantName, name)
			}
			if f.module != tc.wantModule {
				t.Errorf("module: want %q, got %q", tc.wantModule, f.module)
			}
		})
	}
}

// The two-argument form must be exactly the one-argument form plus --module,
// not a second code path that can drift from it.
func TestSymbolContextArgs_TwoArgFormEqualsModuleFlag(t *testing.T) {
	positional := symbolContextFlags{}
	nameA, conflict, ok := symbolContextArgs([]string{"github.com/spf13/cast@v1.4.1", "ToStringE"}, &positional)
	if conflict != nil || !ok {
		t.Fatalf("two-arg form rejected: conflict=%v ok=%v", conflict, ok)
	}

	flagged := symbolContextFlags{module: "github.com/spf13/cast@v1.4.1"}
	nameB, conflict, ok := symbolContextArgs([]string{"ToStringE"}, &flagged)
	if conflict != nil || !ok {
		t.Fatalf("one-arg form rejected: conflict=%v ok=%v", conflict, ok)
	}

	if nameA != nameB || positional.module != flagged.module {
		t.Errorf("the two forms must resolve identically: (%q,%q) vs (%q,%q)",
			nameA, positional.module, nameB, flagged.module)
	}
}

// ---- reachability argument-error ordering ---------------------------------

// The default branch offers --local as a peer target, so '--local . --vuln X'
// is what a caller who read that message types next. Reporting a missing module
// there answers a question nobody asked, and makes the conflict message
// unreachable in the one case where it is the accurate one.
func TestReachabilityCmd_LocalPlusVulnReportsTheConflict(t *testing.T) {
	for _, tc := range []struct {
		name string
		args []string
		want string
	}{
		{
			name: "--local with --vuln reports mutual exclusion",
			args: []string{"--local", ".", "--vuln", "GO-2021-0113"},
			want: "mutually exclusive",
		},
		{
			name: "--vuln alone still reports the missing coordinate",
			args: []string{"--vuln", "GO-2021-0113"},
			want: "requires a <module>@<version> argument",
		},
		{
			name: "neither target names both options",
			args: nil,
			want: "specify a target",
		},
		{
			name: "--local with a module argument refuses the argument",
			args: []string{"--local", ".", "example.com/m@v1.0.0"},
			want: "does not take a module argument",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cmd := newReachabilityCmd(&bytes.Buffer{}, &bytes.Buffer{})
			cmd.SetOut(&bytes.Buffer{})
			cmd.SetErr(&bytes.Buffer{})
			cmd.SetArgs(tc.args)
			err := cmd.Execute()
			if err == nil {
				t.Fatalf("want an argument error, got nil")
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("want the message to contain %q, got: %v", tc.want, err)
			}
		})
	}
}

// ---- notice --output ------------------------------------------------------

// notice gains --output with sbom's semantics, through the same helper: the
// document lands in the file and stdout stays empty, so an operator can capture
// the document and the commentary separately without shell gymnastics.
func TestNoticeWith_OutputWritesFileAndLeavesStdoutEmpty(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "THIRD-PARTY-LICENSES")

	ctr := noticeCleanContainer()

	var stdout, stderr bytes.Buffer
	if err := noticeWith(context.Background(), ctr, "W1", "", "", "", path, &stdout, &stderr); err != nil {
		t.Fatalf("noticeWith: %v", err)
	}

	if stdout.Len() != 0 {
		t.Errorf("stdout must stay empty when --output is given, got: %q", stdout.String())
	}
	content, err := os.ReadFile(path) //nolint:gosec // path is this test's own TempDir
	if err != nil {
		t.Fatalf("reading the written document: %v", err)
	}
	if !strings.Contains(string(content), "THIRD-PARTY-LICENSES") {
		t.Errorf("the written file is not the notice document: %q", content)
	}
	if !strings.Contains(stderr.String(), "NOTICE written to "+path) {
		t.Errorf("stderr must acknowledge the path, got: %q", stderr.String())
	}
}

// Without --output the document still streams to stdout, unchanged.
func TestNoticeWith_NoOutputStreamsToStdout(t *testing.T) {
	ctr := noticeCleanContainer()

	var stdout, stderr bytes.Buffer
	if err := noticeWith(context.Background(), ctr, "W1", "", "", "", "", &stdout, &stderr); err != nil {
		t.Fatalf("noticeWith: %v", err)
	}
	if !strings.Contains(stdout.String(), "THIRD-PARTY-LICENSES") {
		t.Errorf("want the document on stdout, got: %q", stdout.String())
	}
}

// sbom and notice must not drift: one helper, one shape of acknowledgement.
func TestWriteArtefactFile_NamesKindAndPath(t *testing.T) {
	path := filepath.Join(t.TempDir(), "out.json")
	var notify bytes.Buffer
	if err := writeArtefactFile("SBOM", path, []byte(`{"x":1}`), &notify); err != nil {
		t.Fatalf("writeArtefactFile: %v", err)
	}
	if got := notify.String(); got != "SBOM written to "+path+"\n" {
		t.Errorf("acknowledgement: got %q", got)
	}
	got, err := os.ReadFile(path) //nolint:gosec // path is this test's own TempDir
	if err != nil {
		t.Fatalf("reading back: %v", err)
	}
	if string(got) != `{"x":1}` {
		t.Errorf("content: got %q", got)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Errorf("permissions: want 0600, got %o", perm)
	}
}

// An unwritable path is reported naming the path, not swallowed.
func TestWriteArtefactFile_ReportsTheFailingPath(t *testing.T) {
	path := filepath.Join(t.TempDir(), "no-such-dir", "out.json")
	err := writeArtefactFile("NOTICE", path, []byte("x"), &bytes.Buffer{})
	if err == nil {
		t.Fatal("want an error writing into a missing directory")
	}
	if !strings.Contains(err.Error(), path) {
		t.Errorf("the error must name the path, got: %v", err)
	}
}

// noticeCleanContainer holds one walk with one module that needs no review, so
// the --output branch is exercised on the success path.
func noticeCleanContainer() *Container {
	coord := coordinatetest.MustNew("example.com/dep", "v1.0.0")
	return &Container{
		QueryWalks: walksWithNodes("W1", coord),
		GenerateNotice: &testfakes.FakeGenerateNotice{Result: licapp.NoticeResult{
			Entries: []licdomain.NoticeEntry{{Coordinate: coord, SPDX: "MIT"}},
		}},
	}
}

// ---- vuln-by-id / vuln-show: newer-walk note ------------------------------

// The remedy names the walk the operator passed — that stays the subject. But a
// fresher succeeded walk of the same root means scanning the named one produces
// a second scan surface for an outdated resolution, so one advisory line is
// appended.
func TestVulnShow_NamesANewerSucceededWalkOfTheSameRoot(t *testing.T) {
	root := coordinatetest.MustNew("example.com/app", "v1.0.0")
	module := coordinatetest.MustNew("example.com/dep", "v1.0.0")
	const namedWalk = "01JWALKOLD000000000000001"
	const newerWalk = "01JWALKNEW000000000000001"

	old := time.Now().Add(-48 * time.Hour)

	walks := testfakes.NewFakeQueryWalks()
	walks.AddWalk(walkdomain.WalkRecord{ID: namedWalk, Target: root, StartedAt: old})
	walks.SetSummaries([]walkports.WalkSummary{{
		ID:            newerWalk,
		Target:        root,
		StartedAt:     time.Now().Add(-30 * time.Minute),
		OverallStatus: walkdomain.WalkSucceeded,
	}})

	var buf bytes.Buffer
	err := runVulnShow(context.Background(), module.String(), namedWalk, false, false,
		testfakes.NewFakeQueryVuln(), testfakes.NewFakeQueryScanRuns(), walks, &buf)
	if err == nil {
		t.Fatal("want the missing-scan refusal")
	}
	msg := err.Error()
	if !strings.Contains(msg, "run: kanonarion vuln-scan "+namedWalk) {
		t.Errorf("the primary remedy must still name the walk that was passed, got: %v", msg)
	}
	if !strings.Contains(msg, "note: a newer walk of "+root.String()+" exists") ||
		!strings.Contains(msg, newerWalk) {
		t.Errorf("want the newer walk named in a note, got: %v", msg)
	}
	requireExit(t, err, ExitNotFound)
}

// No newer walk means no note. The refusal is already correct on its own and
// must not grow a line that says nothing.
func TestVulnShow_NoNoteWhenNoNewerWalkExists(t *testing.T) {
	root := coordinatetest.MustNew("example.com/app", "v1.0.0")
	module := coordinatetest.MustNew("example.com/dep", "v1.0.0")
	const namedWalk = "01JWALKOLD000000000000001"

	walks := testfakes.NewFakeQueryWalks()
	walks.AddWalk(walkdomain.WalkRecord{ID: namedWalk, Target: root, StartedAt: time.Now()})
	// The only succeeded walk is older than the one named.
	walks.SetSummaries([]walkports.WalkSummary{{
		ID:            "01JWALKOLDER0000000000001",
		Target:        root,
		StartedAt:     time.Now().Add(-72 * time.Hour),
		OverallStatus: walkdomain.WalkSucceeded,
	}})

	var buf bytes.Buffer
	err := runVulnShow(context.Background(), module.String(), namedWalk, false, false,
		testfakes.NewFakeQueryVuln(), testfakes.NewFakeQueryScanRuns(), walks, &buf)
	if err == nil {
		t.Fatal("want the missing-scan refusal")
	}
	if strings.Contains(err.Error(), "note: a newer walk") {
		t.Errorf("an older walk must not be advertised as newer, got: %v", err)
	}
}

// The note is advisory: a walk store that cannot answer must not turn a correct
// refusal into an error about the lookup that decorates it.
func TestVulnShow_NoteFailureLeavesTheRefusalIntact(t *testing.T) {
	module := coordinatetest.MustNew("example.com/dep", "v1.0.0")
	const namedWalk = "01JWALKOLD000000000000001"

	walks := testfakes.NewFakeQueryWalks()
	walks.ListErr = context.DeadlineExceeded
	walks.AddWalk(walkdomain.WalkRecord{
		ID:     namedWalk,
		Target: coordinatetest.MustNew("example.com/app", "v1.0.0"),
	})

	var buf bytes.Buffer
	err := runVulnShow(context.Background(), module.String(), namedWalk, false, false,
		testfakes.NewFakeQueryVuln(), testfakes.NewFakeQueryScanRuns(), walks, &buf)
	if err == nil {
		t.Fatal("want the missing-scan refusal")
	}
	if !strings.Contains(err.Error(), "run: kanonarion vuln-scan "+namedWalk) {
		t.Errorf("the refusal must survive a failed note lookup, got: %v", err)
	}
	requireExit(t, err, ExitNotFound)
}
