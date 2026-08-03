package cli

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/eitanity/kanonarion/internal/cli/testfakes"
	sbomdomain "github.com/eitanity/kanonarion/internal/sbom/domain"
)

// With no --output, the SBOM bytes are written straight to stdout.
func TestSBOMGenerateWith_Stdout(t *testing.T) {
	ctr := &Container{GenerateSBOM: &testfakes.FakeGenerateSBOM{
		Result: sbomdomain.SBOMRecord{ID: "S1", Content: []byte("<bom/>")},
	}}
	var stdout bytes.Buffer
	err := sbomGenerateWith(context.Background(), ctr, "W1", sbomFlags{format: "cyclonedx-json", operator: "tester"}, time.Time{}, &stdout, io.Discard)
	if err != nil {
		t.Fatalf("sbomGenerateWith: %v", err)
	}
	if stdout.String() != "<bom/>" {
		t.Errorf("expected raw SBOM content on stdout, got: %q", stdout.String())
	}
}

// The --main-version and --main-license flags must reach the SBOMRequest so the
// generator can stamp them onto the subject component.
func TestSBOMGenerateWith_MainComponentFlagsPropagate(t *testing.T) {
	fake := &testfakes.FakeGenerateSBOM{
		Result: sbomdomain.SBOMRecord{ID: "S1", Content: []byte("<bom/>")},
	}
	ctr := &Container{GenerateSBOM: fake}
	var stdout bytes.Buffer
	err := sbomGenerateWith(context.Background(), ctr, "W1", sbomFlags{format: "cyclonedx-json", mainVersion: "v9.9.9", mainLicense: "Apache-2.0", operator: "tester"}, time.Time{}, &stdout, io.Discard)
	if err != nil {
		t.Fatalf("sbomGenerateWith: %v", err)
	}
	if fake.LastRequest.MainComponentVersion != "v9.9.9" {
		t.Errorf("MainComponentVersion = %q, want v9.9.9", fake.LastRequest.MainComponentVersion)
	}
	if fake.LastRequest.MainComponentLicense != "Apache-2.0" {
		t.Errorf("MainComponentLicense = %q, want Apache-2.0", fake.LastRequest.MainComponentLicense)
	}
}

// With --output and complete licence data, the file is written and the
// command succeeds with the confirmation on stdout — the happy path that
// must not be swept up by the incomplete-licence loud-fail.
func TestSBOMGenerateWith_FileOutputComplete(t *testing.T) {
	dst := filepath.Join(t.TempDir(), "bom.json")
	ctr := &Container{GenerateSBOM: &testfakes.FakeGenerateSBOM{
		Result: sbomdomain.SBOMRecord{
			ID:                 "S1",
			Content:            []byte("<bom/>"),
			ContentHash:        "sha256:abc",
			LicensesIncomplete: false,
		},
	}}
	var stdout bytes.Buffer
	err := sbomGenerateWith(context.Background(), ctr, "W1", sbomFlags{format: "cyclonedx-json", output: dst, operator: "tester"}, time.Time{}, &stdout, io.Discard)
	if err != nil {
		t.Fatalf("sbomGenerateWith: %v", err)
	}
	got, rerr := os.ReadFile(dst) // #nosec G304 -- dst is a test-controlled t.TempDir() path
	if rerr != nil {
		t.Fatalf("reading written SBOM: %v", rerr)
	}
	if string(got) != "<bom/>" {
		t.Errorf("file content = %q, want <bom/>", string(got))
	}
	if !strings.Contains(stdout.String(), "SBOM written to") {
		t.Errorf("expected a 'written to' confirmation, got: %q", stdout.String())
	}
}

// With --output, the SBOM file is still written but incomplete licence data
// fails the command loudly (non-zero exit), and the confirmation stays on
// stdout while the failure never contaminates it.
func TestSBOMGenerateWith_FileOutputIncompleteLicencesFailsLoud(t *testing.T) {
	dst := filepath.Join(t.TempDir(), "bom.json")
	ctr := &Container{GenerateSBOM: &testfakes.FakeGenerateSBOM{
		Result: sbomdomain.SBOMRecord{
			ID:                 "S1",
			Content:            []byte("<bom/>"),
			ContentHash:        "sha256:abc",
			LicensesIncomplete: true,
		},
	}}
	var stdout bytes.Buffer
	err := sbomGenerateWith(context.Background(), ctr, "W1", sbomFlags{format: "cyclonedx-json", output: dst, operator: "tester"}, time.Time{}, &stdout, io.Discard)
	assertIncompleteLicenceExit(t, err)

	got, rerr := os.ReadFile(dst) // #nosec G304 -- dst is a test-controlled t.TempDir() path
	if rerr != nil {
		t.Fatalf("reading written SBOM: %v", rerr)
	}
	if string(got) != "<bom/>" {
		t.Errorf("file content = %q, want <bom/>", string(got))
	}
	out := stdout.String()
	if !strings.Contains(out, "SBOM written to") {
		t.Errorf("expected a 'written to' confirmation, got: %q", out)
	}
	// The failure signal must never land on stdout — that carries the SBOM
	// confirmation and, on the bare path, the SBOM bytes.
	if strings.Contains(out, "undetermined licence") {
		t.Errorf("undetermined-licence signal must not be on stdout, got: %q", out)
	}
}

// On the bare stdout path (no --output) incomplete licence data must also fail
// loudly rather than silently emit a degraded SBOM — the previously-dropped
// case. The SBOM bytes still reach stdout uncorrupted.
func TestSBOMGenerateWith_StdoutIncompleteLicencesFailsLoud(t *testing.T) {
	ctr := &Container{GenerateSBOM: &testfakes.FakeGenerateSBOM{
		Result: sbomdomain.SBOMRecord{
			ID:                 "S1",
			Content:            []byte("<bom/>"),
			LicensesIncomplete: true,
		},
	}}
	var stdout bytes.Buffer
	err := sbomGenerateWith(context.Background(), ctr, "W1", sbomFlags{format: "cyclonedx-json", operator: "tester"}, time.Time{}, &stdout, io.Discard)
	assertIncompleteLicenceExit(t, err)

	if stdout.String() != "<bom/>" {
		t.Errorf("stdout must carry only the SBOM bytes, got: %q", stdout.String())
	}
}

// A generation failure surfaces wrapped, never masked as success.
func TestSBOMGenerateWith_GenerateError(t *testing.T) {
	ctr := &Container{GenerateSBOM: &testfakes.FakeGenerateSBOM{Err: errors.New("boom")}}
	var stdout bytes.Buffer
	err := sbomGenerateWith(context.Background(), ctr, "W1", sbomFlags{format: "cyclonedx-json", operator: "tester"}, time.Time{}, &stdout, io.Discard)
	if err == nil || !strings.Contains(err.Error(), "generating sbom") {
		t.Fatalf("want wrapped generation error, got: %v", err)
	}
}

// An unwritable --output path surfaces the file-write error.
func TestSBOMGenerateWith_FileWriteError(t *testing.T) {
	// A path under a non-existent directory makes os.WriteFile fail.
	dst := filepath.Join(t.TempDir(), "no-such-dir", "bom.json")
	ctr := &Container{GenerateSBOM: &testfakes.FakeGenerateSBOM{
		Result: sbomdomain.SBOMRecord{ID: "S1", Content: []byte("<bom/>")},
	}}
	var stdout bytes.Buffer
	err := sbomGenerateWith(context.Background(), ctr, "W1", sbomFlags{format: "cyclonedx-json", output: dst, operator: "tester"}, time.Time{}, &stdout, io.Discard)
	if err == nil || !strings.Contains(err.Error(), "writing SBOM to") {
		t.Fatalf("want file-write error, got: %v", err)
	}
}

// failWriter fails every write, exercising the stdout write-error path.
type failWriter struct{}

func (failWriter) Write([]byte) (int, error) { return 0, errors.New("write failed") }

// A failing stdout writer surfaces the write error rather than being swallowed.
func TestSBOMGenerateWith_StdoutWriteError(t *testing.T) {
	ctr := &Container{GenerateSBOM: &testfakes.FakeGenerateSBOM{
		Result: sbomdomain.SBOMRecord{ID: "S1", Content: []byte("<bom/>")},
	}}
	err := sbomGenerateWith(context.Background(), ctr, "W1", sbomFlags{format: "cyclonedx-json", operator: "tester"}, time.Time{}, failWriter{}, io.Discard)
	if err == nil || !strings.Contains(err.Error(), "writing sbom to stdout") {
		t.Fatalf("want stdout write error, got: %v", err)
	}
}

// A document whose components carry no licences block is named in the failure
// message, component by component, so the operator learns which they are without
// opening the artefact. The names come from the document, so the message says the
// same thing for a cached document as for a freshly generated one.
func TestSBOMGenerateWith_UndeterminedLicencesAreNamed(t *testing.T) {
	doc := `{"metadata":{"component":{"name":"github.com/example/app","version":"local"}},` +
		`"components":[` +
		`{"name":"github.com/example/licensed","version":"v1.0.0","licenses":[{"license":{"id":"MIT"}}]},` +
		`{"name":"github.com/example/unclassified","version":"v0.0.1"}]}`
	ctr := &Container{GenerateSBOM: &testfakes.FakeGenerateSBOM{
		Result: sbomdomain.SBOMRecord{
			ID:                 "S1",
			Content:            []byte(doc),
			LicensesIncomplete: true,
		},
	}}
	var stdout bytes.Buffer
	err := sbomGenerateWith(context.Background(), ctr, "W1", sbomFlags{format: "cyclonedx-json", operator: "tester"}, time.Time{}, &stdout, io.Discard)
	assertIncompleteLicenceExit(t, err)
	msg := err.Error()
	for _, want := range []string{
		"2 component(s)",
		"github.com/example/app@local (the document's subject)",
		"github.com/example/unclassified@v0.0.1",
	} {
		if !strings.Contains(msg, want) {
			t.Errorf("failure message missing %q:\n%s", want, msg)
		}
	}
	if strings.Contains(msg, "github.com/example/licensed") {
		t.Errorf("a licensed component must not be named as undetermined:\n%s", msg)
	}
}

// A document this process cannot re-read still fails, and says why it cannot name
// the components rather than reporting a clean run or none.
func TestSBOMGenerateWith_UnreadableDocumentStillFailsAndSaysSo(t *testing.T) {
	ctr := &Container{GenerateSBOM: &testfakes.FakeGenerateSBOM{
		Result: sbomdomain.SBOMRecord{ID: "S1", Content: []byte("<bom/>"), LicensesIncomplete: true},
	}}
	var stdout bytes.Buffer
	err := sbomGenerateWith(context.Background(), ctr, "W1", sbomFlags{format: "cyclonedx-json", operator: "tester"}, time.Time{}, &stdout, io.Discard)
	assertIncompleteLicenceExit(t, err)
	if !strings.Contains(err.Error(), "could not be re-read") {
		t.Errorf("want the message to state it could not name them, got: %v", err)
	}
}

// --generated-at is the caller's document-creation clock; it must reach the
// request, and an unparseable value must be refused rather than silently
// dropped back to the derived timestamp.
func TestSBOMGeneratedAtFlag_ParsesAndPropagates(t *testing.T) {
	want := time.Date(2026, 1, 31, 9, 0, 0, 0, time.UTC)
	got, err := parseGeneratedAt("2026-01-31T09:00:00Z")
	if err != nil {
		t.Fatalf("parseGeneratedAt: %v", err)
	}
	if !got.Equal(want) {
		t.Errorf("parseGeneratedAt = %s, want %s", got, want)
	}
	if zero, zerr := parseGeneratedAt(""); zerr != nil || !zero.IsZero() {
		t.Errorf("empty --generated-at = (%s, %v), want (zero, nil)", zero, zerr)
	}
	if _, berr := parseGeneratedAt("yesterday"); berr == nil {
		t.Error("want a refusal for an unparseable --generated-at, got none")
	}

	fake := &testfakes.FakeGenerateSBOM{Result: sbomdomain.SBOMRecord{ID: "S1", Content: []byte("<bom/>")}}
	ctr := &Container{GenerateSBOM: fake}
	var stdout bytes.Buffer
	if err := sbomGenerateWith(context.Background(), ctr, "W1", sbomFlags{format: "cyclonedx-json", operator: "tester"}, want, &stdout, io.Discard); err != nil {
		t.Fatalf("sbomGenerateWith: %v", err)
	}
	if !fake.LastRequest.GeneratedAt.Equal(want) {
		t.Errorf("SBOMRequest.GeneratedAt = %s, want %s", fake.LastRequest.GeneratedAt, want)
	}
}

// assertIncompleteLicenceExit asserts err is a non-zero exit categorised as
// ExitPartial — the contract for an incomplete-licence SBOM.
func assertIncompleteLicenceExit(t *testing.T, err error) {
	t.Helper()
	if err == nil {
		t.Fatal("expected a non-zero exit for incomplete licence data, got nil")
	}
	var ee *exitError
	if !errors.As(err, &ee) {
		t.Fatalf("want *exitError, got %T: %v", err, err)
	}
	if ee.code != ExitPartial {
		t.Errorf("exit code = %d, want ExitPartial (%d)", ee.code, ExitPartial)
	}
}
