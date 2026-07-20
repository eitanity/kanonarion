package cli

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/eitanity/kanonarion/internal/coordinate"

	"github.com/eitanity/kanonarion/internal/cli/testfakes"
	exapp "github.com/eitanity/kanonarion/internal/example/application"
	exdomain "github.com/eitanity/kanonarion/internal/example/domain"
	exports "github.com/eitanity/kanonarion/internal/example/ports"
)

func TestExamplesListCmd_EmptyStore(t *testing.T) {
	dir := t.TempDir()
	var stdout, stderr bytes.Buffer
	err := Run([]string{"examples-list", "--store-root", dir}, &stdout, &stderr)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(stdout.String(), "no example records found") {
		t.Errorf("expected empty message, got: %q", stdout.String())
	}
}

func TestExamplesFindCmd_EmptyStore(t *testing.T) {
	dir := t.TempDir()
	var stdout, stderr bytes.Buffer
	err := Run([]string{"examples-find", "--store-root", dir, "symbol"}, &stdout, &stderr)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if stdout.Len() == 0 {
		t.Error("expected non-empty output")
	}
}

func makeExampleCoord(t *testing.T) coordinate.ModuleCoordinate {
	t.Helper()
	c, err := coordinate.NewModuleCoordinate("example.com/app", "v1.0.0")
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func makeExampleRecord(t *testing.T) exdomain.ExampleRecord {
	t.Helper()
	coord := makeExampleCoord(t)
	return exdomain.ExampleRecord{
		Coordinate:      coord,
		PipelineVersion: exapp.PipelineVersion,
		OverallStatus:   exdomain.ExampleStatusFound,
		Examples: []exdomain.ExampleEntry{
			{Name: "ExampleMain", Package: "app", AssociatedSymbol: "Main", Body: "{ // ... }"},
		},
	}
}

func TestRunExamplesList_WithRecords(t *testing.T) {
	uc := testfakes.NewFakeQueryExamples()
	uc.SetList([]exports.ExampleSummary{
		{ModulePath: "example.com/app", ModuleVersion: "v1.0.0", ExampleCount: 1, OverallStatus: exdomain.ExampleStatusFound},
	})
	var buf bytes.Buffer
	err := runExamplesList(context.Background(), 50, uc, &buf)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(buf.String(), "example.com/app@v1.0.0") {
		t.Errorf("expected module in output, got: %q", buf.String())
	}
}

func TestRunExamplesList_Empty(t *testing.T) {
	uc := testfakes.NewFakeQueryExamples()
	var buf bytes.Buffer
	if err := runExamplesList(context.Background(), 50, uc, &buf); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(buf.String(), "no example records found") {
		t.Errorf("expected empty message, got: %q", buf.String())
	}
}

func TestRunExamplesListForModule_WithRecord(t *testing.T) {
	uc := testfakes.NewFakeQueryExamples()
	rec := makeExampleRecord(t)
	coord := makeExampleCoord(t)
	uc.AddRecord(coord, exapp.PipelineVersion, rec)
	var buf bytes.Buffer
	err := runExamplesListForModule(context.Background(), "example.com/app@v1.0.0", uc, &buf)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, "ExampleMain") {
		t.Errorf("expected example name in output, got: %q", out)
	}
	if !strings.Contains(out, "Main") {
		t.Errorf("expected symbol in output, got: %q", out)
	}
}

func TestRunExamplesListForModule_NotFound(t *testing.T) {
	uc := testfakes.NewFakeQueryExamples()
	var buf bytes.Buffer
	err := runExamplesListForModule(context.Background(), "non-existent@v1.0.0", uc, &buf)
	if err == nil {
		t.Fatal("expected error for missing record")
	}
	if !strings.Contains(err.Error(), "no example record") {
		t.Errorf("expected 'no example record' in error, got: %v", err)
	}
}

func TestRunExamplesShow_Found(t *testing.T) {
	uc := testfakes.NewFakeQueryExamples()
	rec := makeExampleRecord(t)
	coord := makeExampleCoord(t)
	uc.AddRecord(coord, exapp.PipelineVersion, rec)
	var buf bytes.Buffer
	err := runExamplesShow(context.Background(), "example.com/app@v1.0.0", "ExampleMain", false, uc, &buf)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, "ExampleMain") {
		t.Errorf("expected example name in output, got: %q", out)
	}
	if !strings.Contains(out, "Main") {
		t.Errorf("expected symbol in output, got: %q", out)
	}
}

func TestRunExamplesShow_NotFoundModule(t *testing.T) {
	uc := testfakes.NewFakeQueryExamples()
	var buf bytes.Buffer
	err := runExamplesShow(context.Background(), "non-existent@v1.0.0", "ExampleMain", false, uc, &buf)
	if err == nil {
		t.Fatal("expected error")
	}
	if !strings.Contains(err.Error(), "no example record") {
		t.Errorf("expected 'no example record' in error, got: %v", err)
	}
}

func TestRunExamplesShow_ExampleNotFound(t *testing.T) {
	uc := testfakes.NewFakeQueryExamples()
	rec := makeExampleRecord(t)
	coord := makeExampleCoord(t)
	uc.AddRecord(coord, exapp.PipelineVersion, rec)
	var buf bytes.Buffer
	err := runExamplesShow(context.Background(), "example.com/app@v1.0.0", "ExampleNotExist", false, uc, &buf)
	if err == nil {
		t.Fatal("expected error for missing example")
	}
	if !strings.Contains(err.Error(), "not found") {
		t.Errorf("expected 'not found' in error, got: %v", err)
	}
}

func TestRunExamplesShow_JSON(t *testing.T) {
	uc := testfakes.NewFakeQueryExamples()
	rec := makeExampleRecord(t)
	coord := makeExampleCoord(t)
	uc.AddRecord(coord, exapp.PipelineVersion, rec)
	var buf bytes.Buffer
	err := runExamplesShow(context.Background(), "example.com/app@v1.0.0", "ExampleMain", true, uc, &buf)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(buf.String(), `"Name"`) {
		t.Errorf("expected JSON output, got: %q", buf.String())
	}
}

func TestRunExamplesFind_WithResults(t *testing.T) {
	uc := testfakes.NewFakeQueryExamples()
	uc.SetRefs([]exports.ExampleRef{
		{ModulePath: "example.com/app", ModuleVersion: "v1.0.0", ExampleName: "ExampleMain", AssociatedSymbol: "Main"},
	})
	var buf bytes.Buffer
	err := runExamplesFind(context.Background(), "Main", false, uc, &buf)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(buf.String(), "ExampleMain") {
		t.Errorf("expected example name in output, got: %q", buf.String())
	}
}

func TestRunExamplesFind_NoResults(t *testing.T) {
	uc := testfakes.NewFakeQueryExamples()
	var buf bytes.Buffer
	err := runExamplesFind(context.Background(), "NoSuchSymbol", false, uc, &buf)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(buf.String(), `no examples found for symbol "NoSuchSymbol"`) {
		t.Errorf("expected empty message, got: %q", buf.String())
	}
}

func TestRunExamplesFind_JSON_Empty(t *testing.T) {
	uc := testfakes.NewFakeQueryExamples()
	var buf bytes.Buffer
	err := runExamplesFind(context.Background(), "NoSuchSymbol", true, uc, &buf)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(buf.String(), "[]") {
		t.Errorf("expected empty JSON array, got: %q", buf.String())
	}
}

func TestRunExamplesFind_JSON_WithRefs(t *testing.T) {
	uc := testfakes.NewFakeQueryExamples()
	uc.SetRefs([]exports.ExampleRef{
		{ModulePath: "example.com/app", ModuleVersion: "v1.0.0", ExampleName: "ExampleMain", AssociatedSymbol: "Main"},
	})
	var buf bytes.Buffer
	err := runExamplesFind(context.Background(), "Main", true, uc, &buf)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	out := buf.String()
	// curated snake_case keys.
	if !strings.Contains(out, `"example_name"`) || !strings.Contains(out, `"associated_symbol"`) {
		t.Errorf("expected snake_case JSON keys, got: %q", out)
	}
	if strings.Contains(out, `"ExampleName"`) || strings.Contains(out, `"AssociatedSymbol"`) {
		t.Errorf("raw PascalCase key leaked: %q", out)
	}
}

func TestRunExamplesShow_WithDoc(t *testing.T) {
	uc := testfakes.NewFakeQueryExamples()
	coord := makeExampleCoord(t)
	rec := exdomain.ExampleRecord{
		Coordinate:      coord,
		PipelineVersion: exapp.PipelineVersion,
		OverallStatus:   exdomain.ExampleStatusFound,
		Examples: []exdomain.ExampleEntry{
			{Name: "ExampleFunc", Package: "mypkg", AssociatedSymbol: "Func", Doc: "Example shows how to use Func.", Body: "{ }"},
		},
	}
	uc.AddRecord(coord, exapp.PipelineVersion, rec)

	var buf bytes.Buffer
	err := runExamplesShow(context.Background(), "example.com/app@v1.0.0", "ExampleFunc", false, uc, &buf)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(buf.String(), "Example shows how to use Func.") {
		t.Errorf("expected doc in output, got: %q", buf.String())
	}
}

func TestRunExamplesShow_GetError(t *testing.T) {
	uc := testfakes.NewFakeQueryExamples()
	uc.Err = errors.New("store unavailable")
	var buf bytes.Buffer
	err := runExamplesShow(context.Background(), "example.com/app@v1.0.0", "ExampleMain", false, uc, &buf)
	if err == nil {
		t.Fatal("expected error from store")
	}
	if !strings.Contains(err.Error(), "getting example record") {
		t.Errorf("expected 'getting example record' in error, got: %v", err)
	}
}

func TestPrintExampleRecord_WithCacheAndValidates(t *testing.T) {
	coord := makeExampleCoord(t)
	rec := exdomain.ExampleRecord{
		Coordinate:      coord,
		PipelineVersion: exapp.PipelineVersion,
		OverallStatus:   exdomain.ExampleStatusFound,
		FailureDetail:   "some extraction warning",
		Examples: []exdomain.ExampleEntry{
			{Name: "ExampleFoo", Package: "pkg", AssociatedSymbol: "Foo", Validates: true},
		},
		ParseFailures: []exdomain.ParseFailure{{File: "bad_test.go", Error: "syntax error"}},
	}

	var buf bytes.Buffer
	if err := printExampleRecord(rec, true, false, &buf); err != nil {
		t.Fatalf("printExampleRecord: %v", err)
	}
	out := buf.String()
	for _, want := range []string{"(cached)", "some extraction warning", "[validated]", "[parse failure]", "bad_test.go"} {
		if !strings.Contains(out, want) {
			t.Errorf("expected %q in output, got:\n%s", want, out)
		}
	}
}
