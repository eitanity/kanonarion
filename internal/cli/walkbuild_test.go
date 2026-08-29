package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/eitanity/kanonarion/internal/cli/testfakes"
	"github.com/eitanity/kanonarion/internal/coordinate"
	coordinatetest "github.com/eitanity/kanonarion/internal/coordinate/coordinatetest"
	fetchdomain "github.com/eitanity/kanonarion/internal/fetch/domain"
	walkdomain "github.com/eitanity/kanonarion/internal/walk/domain"
)

// This file pins the rule the build disclosure exists for: every command that
// serves a walk a caller named states the build that walk was resolved in, and
// states it from one place.
//
// The failure it guards is a false clean reached without anything going wrong.
// The operator names the walk themselves, so the tool does exactly what it was
// told; nothing on the answer says which Go that walk was resolved under, and
// the stdlib node in its graph follows the walk. A dated re-scan of it then
// produces a fresh statement about a standard library nobody is shipping.

// walkRecordUnder builds a stored walk resolved under the given platform and
// toolchain, rooted at projectDir. An empty goVersion is the walk that recorded
// no build environment at all.
func walkRecordUnder(t *testing.T, id, goos, goarch, goVersion, projectDir string, stdlibNode string) walkdomain.WalkRecord {
	t.Helper()
	target := coordinatetest.MustNew("example.com/app", coordinate.LocalVersion)
	nodes := []walkdomain.GraphNode{{Coordinate: target}}
	if stdlibNode != "" {
		// The node the disclosure must NOT read. Under --stdlib-from-gomod it
		// carries the go.mod directive, which is a declared minimum rather than
		// the toolchain that ran.
		nodes = append(nodes, walkdomain.GraphNode{
			Coordinate:       coordinatetest.MustNew("stdlib", stdlibNode),
			ResolutionSource: walkdomain.ResolutionStdlib,
		})
	}
	started := time.Date(2026, 2, 20, 9, 0, 0, 0, time.UTC)
	outcome := walkdomain.WalkOutcome{
		Target: target,
		Graph: walkdomain.Graph{
			Target:          target,
			Nodes:           nodes,
			PipelineVersion: "1.0.0",
			ResolvedAt:      started,
			BuildEnv:        walkdomain.BuildEnv{GOOS: goos, GOARCH: goarch, GoVersion: goVersion},
		},
		StartedAt:     started,
		CompletedAt:   started.Add(time.Second),
		OverallStatus: walkdomain.WalkSucceeded,
	}
	rec := walkdomain.NewWalkRecord(id, "fixture", "1.0.0",
		walkdomain.WalkScopeCode, walkdomain.WalkDepthFull, outcome, walkdomain.DefaultDepthPolicy(), "")
	rec.ProjectDir = projectDir
	var hasher walkdomain.WalkRecordHasher
	rec, err := hasher.SetContentHash(rec)
	if err != nil {
		t.Fatalf("sealing the fixture walk: %v", err)
	}
	return rec
}

// TestWalkBuild_ReadsTheBuildEnvAndNeverTheStdlibNode is the acceptance the
// whole disclosure rests on. The walk holds two toolchain versions and only one
// of them is what compiled the project; a surface reading the other disagrees
// with the toolchain judgment vuln-scan and audit already render, on the same
// walk, in the same run.
func TestWalkBuild_ReadsTheBuildEnvAndNeverTheStdlibNode(t *testing.T) {
	rec := walkRecordUnder(t, "01WALKBUILD0000000000000A", "linux", "amd64", "go1.26.5", "", "v1.24.1")

	var buf bytes.Buffer
	if err := writeWalkBuild(&buf, rec, ""); err != nil {
		t.Fatalf("writeWalkBuild: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, "go1.26.5") {
		t.Errorf("the disclosure does not name the build environment's toolchain; got:\n%s", out)
	}
	if strings.Contains(out, "1.24.1") {
		t.Errorf("the disclosure read the stdlib node version, which is the go.mod directive and not what ran; got:\n%s", out)
	}
	if got := walkBuildOf(rec); got.GoVersion != "go1.26.5" || got.GOOS != "linux" || got.GOARCH != "amd64" {
		t.Errorf("walkBuildOf() = %+v, want the record's own build environment", got)
	}
}

// TestWalkBuild_UnrecordedNeverBorrowsTheReadersToolchain pins the rule an
// earlier fix established for the frame and this one must not regress: a walk
// that recorded nothing says so. Answering with the reader's own toolchain would
// attribute a standard library to a build that never named one — and a walk
// rooted at a published coordinate never will, because re-walking it does not
// produce one either.
func TestWalkBuild_UnrecordedNeverBorrowsTheReadersToolchain(t *testing.T) {
	rec := walkRecordUnder(t, "01WALKBUILD0000000000000B", "", "", "", "", "")
	// A published coordinate is not platform-scoped, which is a different
	// statement from a project walk that lost its platform.
	rec.Graph.Target = coordinatetest.MustNew("github.com/spf13/cobra", "v1.8.1")

	var buf bytes.Buffer
	if err := writeWalkBuild(&buf, rec, "go1.99.9"); err != nil {
		t.Fatalf("writeWalkBuild: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, "not recorded") {
		t.Errorf("an unrecorded toolchain must say so; got:\n%s", out)
	}
	if strings.Contains(out, "go1.99.9") {
		t.Errorf("the disclosure answered with the reader's own toolchain; got:\n%s", out)
	}
	if !strings.Contains(out, "not-platform-scoped") {
		t.Errorf("a module-rooted walk must not read as a project walk missing its platform; got:\n%s", out)
	}
}

// TestWalkBuild_DivergenceAndMatchAreDifferentAnswers exercises the three states
// the disclosure has to tell apart on one axis.
func TestWalkBuild_DivergenceAndMatchAreDifferentAnswers(t *testing.T) {
	rec := walkRecordUnder(t, "01WALKBUILD0000000000000C", "linux", "amd64", "go1.26.6", "/somewhere", "")

	for _, tc := range []struct {
		name    string
		reader  string
		wantSub []string
		notSub  []string
	}{
		{
			name:    "match states no divergence",
			reader:  "go1.26.6",
			wantSub: []string{"linux/amd64 under go1.26.6"},
			notSub:  []string{"today"},
		},
		{
			name:    "divergence names both versions",
			reader:  "go1.26.5",
			wantSub: []string{"go1.26.6", "go1.26.5"},
		},
		{
			name:   "an unreachable project says so rather than reading as a match",
			reader: "",
			// Silence here would read exactly as the match above, which is the
			// one thing an unanswered comparison must never do.
			wantSub: []string{"not present here", "could not be compared"},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var buf bytes.Buffer
			if err := writeWalkBuild(&buf, rec, tc.reader); err != nil {
				t.Fatalf("writeWalkBuild: %v", err)
			}
			out := buf.String()
			for _, want := range tc.wantSub {
				if !strings.Contains(out, want) {
					t.Errorf("missing %q in:\n%s", want, out)
				}
			}
			for _, not := range tc.notSub {
				if strings.Contains(out, not) {
					t.Errorf("unexpected %q in:\n%s", not, out)
				}
			}
		})
	}
}

// TestReaderWalkToolchain_KeysOnTheWalksProjectNotTheReadersDirectory is the
// property that stops the disclosure crying wolf. GOTOOLCHAIN honours each
// project's own go.mod, so a comparison keyed on where the reader happens to be
// standing tells an operator in a different project that their walk diverged
// when nothing about it changed. The probe therefore asks about the walk's own
// project directory, or asks nothing.
//
// The two halves are tested separately and BOTH are needed. The guards above the
// probe are satisfied by every case where there is nothing to ask, so a suite
// made only of those never runs the probe at all and never sees which directory
// it was handed — a probe rewired to this process's own working directory passes
// all of them.
func TestReaderWalkToolchain_KeysOnTheWalksProjectNotTheReadersDirectory(t *testing.T) {
	ctx := context.Background()

	t.Run("the probe is handed the walk's own project directory", func(t *testing.T) {
		// The stand-in for a toolchain that resolves per directory is a script on
		// PATH that answers by the directory it was run in — which is exactly the
		// input under test, and needs no second Go toolchain installed to
		// exercise it. Nothing here reads ambient state: both answers are
		// invented, and neither can be produced by accident.
		root := t.TempDir()
		binDir := filepath.Join(root, "bin")
		walkProject := filepath.Join(root, "the-walks-project")
		for _, d := range []string{binDir, walkProject} {
			if err := os.MkdirAll(d, 0o750); err != nil {
				t.Fatalf("mkdir %s: %v", d, err)
			}
		}

		const fromTheWalk = "go1.44.4-resolved-in-the-walks-project"
		const fromTheReader = "go1.55.5-resolved-in-the-readers-own-directory"
		script := "#!/bin/sh\ncase \"$PWD\" in\n*/the-walks-project) echo " + fromTheWalk +
			";;\n*) echo " + fromTheReader + ";;\nesac\necho linux\necho amd64\n"
		if err := os.WriteFile(filepath.Join(binDir, "go"), []byte(script), 0o700); err != nil { // #nosec G306 -- a test fixture that must be executable
			t.Fatalf("writing the toolchain stand-in: %v", err)
		}
		t.Setenv("PATH", binDir)

		rec := walkRecordUnder(t, "01WALKBUILD00000000000015", "linux", "amd64", "go1.26.6", walkProject, "")

		got := readerWalkToolchain(ctx, rec)
		if got == fromTheReader {
			t.Fatalf("readerWalkToolchain() = %q: the probe was run in this process's own working directory, "+
				"so a reader standing in a different project would be told their walk had diverged", got)
		}
		if got != fromTheWalk {
			t.Fatalf("readerWalkToolchain() = %q, want %q — the toolchain the walk's own project resolves now", got, fromTheWalk)
		}

		// The consequence, end to end: the divergence statement names the walk's
		// recorded toolchain and what that project resolves today, and nothing
		// about where the reader is standing.
		var buf bytes.Buffer
		if err := writeWalkBuild(&buf, rec, got); err != nil {
			t.Fatalf("writeWalkBuild: %v", err)
		}
		out := buf.String()
		if !strings.Contains(out, "go1.26.6") || !strings.Contains(out, fromTheWalk) {
			t.Errorf("the divergence statement does not name both versions; got:\n%s", out)
		}
		if strings.Contains(out, fromTheReader) {
			t.Errorf("the divergence statement named the reader's own directory's toolchain; got:\n%s", out)
		}
	})

	t.Run("nothing to ask means nothing is asked", func(t *testing.T) {
		noDir := walkRecordUnder(t, "01WALKBUILD0000000000000D", "linux", "amd64", "go1.26.6", "", "")
		if got := readerWalkToolchain(ctx, noDir); got != "" {
			t.Errorf("readerWalkToolchain() = %q for a walk naming no project directory, want \"\": "+
				"a walk with nowhere to ask must not be answered from the reader's own directory", got)
		}

		gone := walkRecordUnder(t, "01WALKBUILD0000000000000E", "linux", "amd64", "go1.26.6",
			filepath.Join(t.TempDir(), "deleted-since-the-walk"), "")
		if got := readerWalkToolchain(ctx, gone); got != "" {
			t.Errorf("readerWalkToolchain() = %q for a project directory that is gone, want \"\"", got)
		}

		// A walk that recorded no toolchain is not probed at all: there is
		// nothing to compare it with, and the probe is a subprocess.
		unrecorded := walkRecordUnder(t, "01WALKBUILD0000000000000F", "", "", "", t.TempDir(), "")
		if got := readerWalkToolchain(ctx, unrecorded); got != "" {
			t.Errorf("readerWalkToolchain() = %q for a walk that recorded no toolchain, want \"\"", got)
		}
	})
}

// TestWalkShow_StatesTheBuildOnTextAndLeavesTheJSONAlone pins both halves of
// this command's change: the text gains the fact, and the JSON — which already
// publishes it at .graph.build_env — is untouched, because stdout there is the
// record's own sealed bytes.
func TestWalkShow_StatesTheBuildOnTextAndLeavesTheJSONAlone(t *testing.T) {
	rec := walkRecordUnder(t, "01WALKBUILD00000000000010", "linux", "amd64", "go1.26.6", "", "")
	uc := testfakes.NewFakeQueryWalks()
	uc.AddWalk(rec)

	var text bytes.Buffer
	if err := runWalkShow(context.Background(), rec.ID, uc, &text, io.Discard); err != nil {
		t.Fatalf("runWalkShow: %v", err)
	}
	if !strings.Contains(text.String(), "linux/amd64 under go1.26.6") {
		t.Errorf("walk-show text does not state the build it was resolved in; got:\n%s", text.String())
	}

	jsonOut = true
	t.Cleanup(func() { jsonOut = false })
	var doc bytes.Buffer
	if err := runWalkShow(context.Background(), rec.ID, uc, &doc, io.Discard); err != nil {
		t.Fatalf("runWalkShow --json: %v", err)
	}
	if strings.Contains(doc.String(), "build:\n") {
		t.Errorf("the text block reached the JSON surface; got:\n%s", doc.String())
	}
	if !strings.Contains(doc.String(), `"build_env":{"goarch":"amd64","goos":"linux","go_version":"go1.26.6"}`) {
		t.Errorf("walk-show --json lost the build env it already carried; got:\n%s", doc.String())
	}
}

// TestRescanPreflight_SaysItIsReEvaluatingARecordedBuild covers the sharpest
// case in the class. A re-scan is what an operator reaches for when they want a
// DATED statement, and the date is the only thing it refreshes: the build stays
// the one the walk recorded. Re-resolving the toolchain would change the subject
// rather than refresh the answer, so what the run owes is to say which build the
// fresh advisories were evaluated against.
func TestRescanPreflight_SaysItIsReEvaluatingARecordedBuild(t *testing.T) {
	rec := walkRecordUnder(t, "01WALKBUILD00000000000011", "linux", "amd64", "go1.26.6", "", "")
	uc := testfakes.NewFakeQueryWalks()
	uc.AddWalk(rec)

	var buf bytes.Buffer
	if err := writeRescanBuildPreflight(context.Background(), &buf, uc, rec.ID); err != nil {
		t.Fatalf("writeRescanBuildPreflight: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, "linux/amd64 under go1.26.6") {
		t.Errorf("the pre-flight does not name the recorded build; got:\n%s", out)
	}
	if !strings.Contains(out, "does not re-resolve the toolchain") {
		t.Errorf("the pre-flight does not say the build is the recorded one; got:\n%s", out)
	}

	// A walk the store cannot produce costs the command nothing: the re-scan is
	// about to report that failure itself, in its own words.
	var empty bytes.Buffer
	if err := writeRescanBuildPreflight(context.Background(), &empty, uc, "01NOSUCHWALK000000000000"); err != nil {
		t.Fatalf("writeRescanBuildPreflight on a missing walk: %v", err)
	}
	if empty.Len() != 0 {
		t.Errorf("a missing walk produced a pre-flight statement: %q", empty.String())
	}
}

// TestBuildOnTheJSONSurfaces_CarriesTheWalksEnvUnderOneSpelling pins the machine
// half. An agent cannot read prose, so the fact the text states is owed to the
// JSON as a field — under one key, with one spelling, on every surface that
// serves a named walk.
//
// The key is "build" and never "toolchain": that key is taken on the
// vulnerability record surface, where it names the toolchain that produced the
// RECORD. One key must not carry two meanings.
func TestBuildOnTheJSONSurfaces_CarriesTheWalksEnvUnderOneSpelling(t *testing.T) {
	rec := walkRecordUnder(t, "01WALKBUILD00000000000012", "linux", "amd64", "go1.26.6", "", "")
	unrecorded := walkRecordUnder(t, "01WALKBUILD00000000000013", "", "", "", "", "")

	for _, tc := range []struct {
		name string
		rec  walkdomain.WalkRecord
		want walkBuildJSON
	}{
		{"a walk that recorded its build", rec, walkBuildJSON{GOOS: "linux", GOARCH: "amd64", GoVersion: "go1.26.6"}},
		{"a walk that recorded none", unrecorded, walkBuildJSON{}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := walkBuildOf(tc.rec); got != tc.want {
				t.Errorf("walkBuildOf() = %+v, want %+v", got, tc.want)
			}
			// Emitted whatever it holds. An absent key would say this producer
			// does not derive the fact at all, which is a different statement
			// from a walk that recorded nothing.
			doc, err := json.Marshal(struct {
				Build walkBuildJSON `json:"build"`
			}{walkBuildOf(tc.rec)})
			if err != nil {
				t.Fatalf("marshalling: %v", err)
			}
			for _, key := range []string{`"goos"`, `"goarch"`, `"go_version"`} {
				if !strings.Contains(string(doc), key) {
					t.Errorf("the build object omits %s: %s", key, doc)
				}
			}
			if strings.Contains(string(doc), `"toolchain"`) {
				t.Errorf("the build object reused the toolchain key, which already means something else: %s", doc)
			}
		})
	}
}

// TestVerificationCoverageJSON_BuildHoldsBothHalves: the coverage document
// already had a build object carrying the vendoring answer, and the platform and
// toolchain join it rather than arriving as a sibling. Both halves answer one
// question — what build is this answer about — and a reader who has to assemble
// them from two keys reads one and not the other.
func TestVerificationCoverageJSON_BuildHoldsBothHalves(t *testing.T) {
	doc := verificationCoverageJSON("01WALKBUILD00000000000014", fetchdomain.VerificationCoverage{}, nil,
		buildVendoring{Known: true, Vendored: true, ModulesTxt: "/p/vendor/modules.txt"},
		walkBuildJSON{GOOS: "linux", GOARCH: "amd64", GoVersion: "go1.26.6"})

	if doc.Build.GoVersion != "go1.26.6" || doc.Build.GOOS != "linux" {
		t.Errorf("the coverage document's build lost the walk's environment: %+v", doc.Build)
	}
	if !doc.Build.Vendored || doc.Build.ModulesTxt == "" {
		t.Errorf("the coverage document's build lost the vendoring answer it already carried: %+v", doc.Build)
	}
	encoded, err := json.Marshal(doc)
	if err != nil {
		t.Fatalf("marshalling: %v", err)
	}
	for _, key := range []string{`"vendoring_known"`, `"vendored"`, `"goos"`, `"goarch"`, `"go_version"`} {
		if !strings.Contains(string(encoded), key) {
			t.Errorf("the coverage build object omits %s", key)
		}
	}
}
