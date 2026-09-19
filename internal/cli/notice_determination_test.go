package cli

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/eitanity/kanonarion/internal/cli/testfakes"
	"github.com/eitanity/kanonarion/internal/coordinate/coordinatetest"
	licoverrides "github.com/eitanity/kanonarion/internal/license/adapters/overrides/yaml"
	licapp "github.com/eitanity/kanonarion/internal/license/application"
	licdomain "github.com/eitanity/kanonarion/internal/license/domain"
)

// synthOverride is an obviously invented determination; see the note in the
// licence application tests.
func synthOverride(spdx string) licdomain.LicenseOverride {
	return licdomain.LicenseOverride{
		SPDX:       spdx,
		DeclaredBy: "test-operator@example.invalid",
		DeclaredOn: "2026-09-19",
		Basis:      "synthetic fixture; no upstream source was read",
	}
}

// The configured determinations reach the generator. Without this the config
// key would parse, validate and show correctly while changing nothing — which
// is the defect: license-compat honoured the entry, notice refused as before.
func TestNoticeWith_PassesConfiguredOverrides(t *testing.T) {
	coord := coordinatetest.MustNew("example.com/dep", "v1.0.0")
	fake := &testfakes.FakeGenerateNotice{}
	ctr := &Container{
		QueryWalks:     walksWithNodes("W1", coord),
		GenerateNotice: fake,
		LicenseOverrides: licoverrides.New(map[string]licdomain.LicenseOverride{
			"example.com/dep": synthOverride("Apache-2.0"),
		}),
	}
	var stdout, stderr bytes.Buffer
	if err := noticeWith(context.Background(), ctr, "W1", "", "", "", "", &stdout, &stderr); err != nil {
		t.Fatalf("noticeWith: %v", err)
	}
	got, ok := fake.LastRequest.Overrides.Resolve(coord)
	if !ok {
		t.Fatal("the configured determination did not reach the generator")
	}
	if got.SPDX != "Apache-2.0" || got.DeclaredBy == "" || got.Basis == "" {
		t.Errorf("determination reached the generator incomplete: %+v", got)
	}
}

// With no determinations configured the generator receives a set that never
// matches — the control that keeps behaviour identical for every project that
// has recorded nothing.
func TestNoticeWith_NoOverridesConfiguredPassesEmptySet(t *testing.T) {
	coord := coordinatetest.MustNew("example.com/dep", "v1.0.0")
	fake := &testfakes.FakeGenerateNotice{}
	ctr := &Container{QueryWalks: walksWithNodes("W1", coord), GenerateNotice: fake}
	var stdout, stderr bytes.Buffer
	if err := noticeWith(context.Background(), ctr, "W1", "", "", "", "", &stdout, &stderr); err != nil {
		t.Fatalf("noticeWith: %v", err)
	}
	if _, ok := fake.LastRequest.Overrides.Resolve(coord); ok {
		t.Error("an unconfigured override set matched")
	}
}

// An entry whose identity a person decided is rendered as that and not as a
// detection: the identifier, who decided it, when, on what basis, and what the
// detector itself found. A document that printed it indistinguishably from a
// measured identity would assert, under the tool's name, something about the
// module's files that nobody measured.
func TestNoticeWith_DeterminationIsMarkedOperatorRecorded(t *testing.T) {
	coord := coordinatetest.MustNew("example.com/ungranted", "v1.0.0")
	ov := synthOverride("Apache-2.0")
	ov.Key = "example.com/ungranted"
	ctr := &Container{
		QueryWalks: walksWithNodes("W1", coord),
		GenerateNotice: &testfakes.FakeGenerateNotice{Result: licapp.NoticeResult{
			Entries: []licdomain.NoticeEntry{{
				Coordinate: coord,
				SPDX:       "Apache-2.0",
				Determination: &licdomain.NoticeDetermination{
					Override:        ov,
					DetectorFinding: "no licence identified in any file it read",
				},
			}},
		}},
	}
	var stdout, stderr bytes.Buffer
	if err := noticeWith(context.Background(), ctr, "W1", "", "", "", "", &stdout, &stderr); err != nil {
		t.Fatalf("noticeWith: %v", err)
	}
	doc := stdout.String()
	for _, want := range []string{
		"License: Apache-2.0",
		"Licence determination (operator-recorded; not a detection):",
		"Apache-2.0, recorded as license_overrides.example.com/ungranted",
		"declared by test-operator@example.invalid on 2026-09-19",
		"basis: synthetic fixture; no upstream source was read",
		"the licence detector identified: no licence identified in any file it read",
	} {
		if !strings.Contains(doc, want) {
			t.Errorf("document is missing %q:\n%s", want, doc)
		}
	}
}

// A determination recorded as a bare identifier names nobody, and the document
// says so rather than leaving a reader to assume the identifier was measured.
func TestNoticeWith_UnattributedDeterminationSaysSo(t *testing.T) {
	coord := coordinatetest.MustNew("example.com/ungranted", "v1.0.0")
	ctr := &Container{
		QueryWalks: walksWithNodes("W1", coord),
		GenerateNotice: &testfakes.FakeGenerateNotice{Result: licapp.NoticeResult{
			Entries: []licdomain.NoticeEntry{{
				Coordinate: coord,
				SPDX:       "MIT",
				Determination: &licdomain.NoticeDetermination{
					Override:        licdomain.LicenseOverride{SPDX: "MIT", Key: "example.com/ungranted"},
					DetectorFinding: "no licence identified in any file it read",
				},
			}},
		}},
	}
	var stdout, stderr bytes.Buffer
	if err := noticeWith(context.Background(), ctr, "W1", "", "", "", "", &stdout, &stderr); err != nil {
		t.Fatalf("noticeWith: %v", err)
	}
	doc := stdout.String()
	if !strings.Contains(doc, "no declarer, date or basis was recorded with this determination") {
		t.Errorf("the document does not say the determination names nobody:\n%s", doc)
	}
	if strings.Contains(doc, "declared by ") {
		t.Errorf("the document names a declarer none was recorded for:\n%s", doc)
	}
}

// A module with no determination is untouched: no block, and the entry reads
// exactly as it did.
func TestNoticeWith_NoDeterminationRendersNoBlock(t *testing.T) {
	coord := coordinatetest.MustNew("example.com/dep", "v1.0.0")
	ctr := &Container{
		QueryWalks: walksWithNodes("W1", coord),
		GenerateNotice: &testfakes.FakeGenerateNotice{Result: licapp.NoticeResult{
			Entries: []licdomain.NoticeEntry{{Coordinate: coord, SPDX: "MIT"}},
		}},
	}
	var stdout, stderr bytes.Buffer
	if err := noticeWith(context.Background(), ctr, "W1", "", "", "", "", &stdout, &stderr); err != nil {
		t.Fatalf("noticeWith: %v", err)
	}
	if strings.Contains(stdout.String(), "Licence determination") {
		t.Errorf("a determination block appeared for a module that has none:\n%s", stdout.String())
	}
}

// An undetermined-licence refusal names the way out. The refusal is correct and
// stays; what was missing is the step that turns it into a document.
func TestNoticeWith_UndeterminedLicenceRefusalNamesTheRemedy(t *testing.T) {
	coord := coordinatetest.MustNew("example.com/ungranted", "v1.0.0")
	ctr := &Container{
		QueryWalks: walksWithNodes("W1", coord),
		GenerateNotice: &testfakes.FakeGenerateNotice{Result: licapp.NoticeResult{
			ReviewItems: []licdomain.ReviewItem{{
				Coordinate:          coord,
				Reason:              "no license found",
				UndeterminedLicence: true,
			}},
		}},
	}
	var stdout, stderr bytes.Buffer
	if err := noticeWith(context.Background(), ctr, "W1", "", "", "", "", &stdout, &stderr); err == nil {
		t.Fatal("expected the review gate to fire")
	}
	msg := stderr.String()
	for _, want := range []string{
		"example.com/ungranted@v1.0.0: no license found",
		"license_overrides:",
		"example.com/ungranted:",
		"spdx:",
		"declared_by:",
		"basis:",
	} {
		if !strings.Contains(msg, want) {
			t.Errorf("refusal is missing %q:\n%s", want, msg)
		}
	}
	if strings.Contains(msg, "copyright_declarations") {
		t.Errorf("the copyright remedy was offered for a licence refusal:\n%s", msg)
	}
	if stdout.Len() != 0 {
		t.Errorf("no document must be written when review is required, got: %q", stdout.String())
	}
}

// A refusal a determination cannot clear does not offer one. Extraction has not
// run for this module, so recording an identity would be recording a guess.
func TestNoticeWith_MissingRecordRefusalOmitsTheLicenceRemedy(t *testing.T) {
	coord := coordinatetest.MustNew("example.com/unextracted", "v1.0.0")
	ctr := &Container{
		QueryWalks: walksWithNodes("W1", coord),
		GenerateNotice: &testfakes.FakeGenerateNotice{Result: licapp.NoticeResult{
			ReviewItems: []licdomain.ReviewItem{{
				Coordinate: coord,
				Reason:     "no license record: run 'kanonarion license' first",
			}},
		}},
	}
	var stdout, stderr bytes.Buffer
	if err := noticeWith(context.Background(), ctr, "W1", "", "", "", "", &stdout, &stderr); err == nil {
		t.Fatal("expected the review gate to fire")
	}
	if strings.Contains(stderr.String(), "license_overrides:") {
		t.Errorf("the determination remedy was offered where extraction has not run:\n%s", stderr.String())
	}
}

// `config set` writes scalars, and the write replaces the whole node. Setting a
// module whose entry records who determined the licence would delete that
// provenance and report success. It is refused, naming the file as the place to
// edit it.
func TestRunConfigSet_RefusesToOverwriteAnAttributedDetermination(t *testing.T) {
	root := t.TempDir()
	const cfg = `version: "2"
license_overrides:
  example.com/ungranted:
    spdx: "Apache-2.0"
    declared_by: "test-operator@example.invalid"
    declared_on: "2026-09-19"
    basis: "synthetic fixture; no upstream source was read"
`
	if err := os.WriteFile(filepath.Join(root, "config.yaml"), []byte(cfg), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	var buf bytes.Buffer
	err := runConfigSet(root, "license_overrides.example.com/ungranted", "MIT", false, &buf)
	if err == nil {
		t.Fatal("the attributed determination was overwritten with a bare identifier")
	}
	if !strings.Contains(err.Error(), "provenance") {
		t.Errorf("refusal does not say what would be lost: %v", err)
	}
	after, rerr := os.ReadFile(filepath.Join(root, "config.yaml")) // #nosec G304 -- test-controlled t.TempDir() path
	if rerr != nil {
		t.Fatalf("reading config back: %v", rerr)
	}
	// The entry is intact. (The file itself may have grown: `config set`
	// tops a config file up with its commented template before it does
	// anything else, refusal or not.)
	for _, want := range []string{"spdx: \"Apache-2.0\"", "declared_by: \"test-operator@example.invalid\"",
		"declared_on: \"2026-09-19\"", "basis: \"synthetic fixture; no upstream source was read\""} {
		if !strings.Contains(string(after), want) {
			t.Errorf("the determination lost %q despite the refusal:\n%s", want, after)
		}
	}
}

// A module recorded as a bare identifier is still settable: the guard is about
// provenance that would be lost, not about the key.
func TestRunConfigSet_BareDeterminationStaysSettable(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "config.yaml"),
		[]byte("version: \"2\"\nlicense_overrides:\n  example.com/mod: MIT\n"), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	var buf bytes.Buffer
	if err := runConfigSet(root, "license_overrides.example.com/mod", "Apache-2.0", false, &buf); err != nil {
		t.Fatalf("runConfigSet: %v", err)
	}
	after, rerr := os.ReadFile(filepath.Join(root, "config.yaml")) // #nosec G304 -- test-controlled t.TempDir() path
	if rerr != nil {
		t.Fatalf("reading config back: %v", rerr)
	}
	if !strings.Contains(string(after), "Apache-2.0") {
		t.Errorf("the set did not take:\n%s", after)
	}
}
