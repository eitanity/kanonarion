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

	"github.com/eitanity/kanonarion/internal/cli/testfakes"
	sbomdomain "github.com/eitanity/kanonarion/internal/sbom/domain"
)

// With no --output, the SBOM bytes are written straight to stdout.
func TestSBOMGenerateWith_Stdout(t *testing.T) {
	ctr := &Container{GenerateSBOM: &testfakes.FakeGenerateSBOM{
		Result: sbomdomain.SBOMRecord{ID: "S1", Content: []byte("<bom/>")},
	}}
	var stdout bytes.Buffer
	err := sbomGenerateWith(context.Background(), ctr, "W1", "", nil, "cyclonedx-json", "", false, false, "tester", &stdout, io.Discard)
	if err != nil {
		t.Fatalf("sbomGenerateWith: %v", err)
	}
	if stdout.String() != "<bom/>" {
		t.Errorf("expected raw SBOM content on stdout, got: %q", stdout.String())
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
	err := sbomGenerateWith(context.Background(), ctr, "W1", "", nil, "cyclonedx-json", dst, false, false, "tester", &stdout, io.Discard)
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
	err := sbomGenerateWith(context.Background(), ctr, "W1", "", nil, "cyclonedx-json", dst, false, false, "tester", &stdout, io.Discard)
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
	if strings.Contains(out, "incomplete licence data") {
		t.Errorf("incomplete-licence signal must not be on stdout, got: %q", out)
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
	err := sbomGenerateWith(context.Background(), ctr, "W1", "", nil, "cyclonedx-json", "", false, false, "tester", &stdout, io.Discard)
	assertIncompleteLicenceExit(t, err)

	if stdout.String() != "<bom/>" {
		t.Errorf("stdout must carry only the SBOM bytes, got: %q", stdout.String())
	}
}

// A generation failure surfaces wrapped, never masked as success.
func TestSBOMGenerateWith_GenerateError(t *testing.T) {
	ctr := &Container{GenerateSBOM: &testfakes.FakeGenerateSBOM{Err: errors.New("boom")}}
	var stdout bytes.Buffer
	err := sbomGenerateWith(context.Background(), ctr, "W1", "", nil, "cyclonedx-json", "", false, false, "tester", &stdout, io.Discard)
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
	err := sbomGenerateWith(context.Background(), ctr, "W1", "", nil, "cyclonedx-json", dst, false, false, "tester", &stdout, io.Discard)
	if err == nil || !strings.Contains(err.Error(), "writing sbom to") {
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
	err := sbomGenerateWith(context.Background(), ctr, "W1", "", nil, "cyclonedx-json", "", false, false, "tester", failWriter{}, io.Discard)
	if err == nil || !strings.Contains(err.Error(), "writing sbom to stdout") {
		t.Fatalf("want stdout write error, got: %v", err)
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
