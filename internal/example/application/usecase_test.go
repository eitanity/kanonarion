package application_test

import (
	"archive/zip"
	"bytes"
	"context"
	"errors"
	"io"
	"log/slog"
	"testing"
	"time"

	"github.com/eitanity/kanonarion/internal/example/adapters/parser/goast"
	"github.com/eitanity/kanonarion/internal/example/application"
	domain2 "github.com/eitanity/kanonarion/internal/example/domain"
	"github.com/eitanity/kanonarion/internal/example/ports"
	"github.com/eitanity/kanonarion/internal/fetch/domain"
	fetchports "github.com/eitanity/kanonarion/internal/fetch/ports"
)

func TestExecute_ModuleNotFetched(t *testing.T) {
	uc := buildUseCase(t, nil, nil, nil)
	coord := mustCoord(t, "example.com/pkg", "v1.0.0")

	_, err := uc.Execute(context.Background(), application.ExtractRequest{Coordinate: coord})
	if !errors.Is(err, ports.ErrModuleNotFetched) {
		t.Fatalf("expected ErrModuleNotFetched, got %v", err)
	}
}

func TestExecute_CacheHit(t *testing.T) {
	coord := mustCoord(t, "example.com/pkg", "v1.0.0")
	factStore := &fakeFactStore{}
	exampleStore := &fakeExampleStore{}

	putFact(t, factStore, coord, "blob:fakecontent")

	existing := domain2.ExampleRecord{
		SchemaVersion:   domain2.ExampleSchemaVersion,
		Coordinate:      coord,
		OverallStatus:   domain2.ExampleStatusFound,
		ExtractedAt:     time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC),
		PipelineVersion: application.PipelineVersion,
	}
	var h domain2.ExampleRecordHasher
	var err error
	existing, err = h.SetContentHash(existing)
	if err != nil {
		t.Fatalf("SetContentHash: %v", err)
	}
	if err := exampleStore.PutExampleRecord(context.Background(), existing); err != nil {
		t.Fatalf("PutExampleRecord: %v", err)
	}

	uc := buildUseCase(t, factStore, nil, exampleStore)
	result, err := uc.Execute(context.Background(), application.ExtractRequest{Coordinate: coord})
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if !result.FromCache {
		t.Error("expected FromCache = true")
	}
}

func TestExecute_ForceBypassesCache(t *testing.T) {
	coord := mustCoord(t, "example.com/pkg", "v1.0.0")
	blobStore := &fakeBlobStore{}
	factStore := &fakeFactStore{}
	exampleStore := &fakeExampleStore{}

	zipData := buildModuleZip(t, coord, map[string]string{
		"foo_test.go": "package foo_test\n",
	})
	handle, err := blobStore.Put(context.Background(), bytes.NewReader(zipData))
	if err != nil {
		t.Fatalf("Put: %v", err)
	}
	putFactWithBlob(t, factStore, coord, string(handle))

	existing := domain2.ExampleRecord{
		SchemaVersion:   domain2.ExampleSchemaVersion,
		Coordinate:      coord,
		OverallStatus:   domain2.ExampleStatusNone,
		ExtractedAt:     time.Now().UTC(),
		PipelineVersion: application.PipelineVersion,
	}
	var hh domain2.ExampleRecordHasher
	existing, err = hh.SetContentHash(existing)
	if err != nil {
		t.Fatalf("SetContentHash: %v", err)
	}
	if err := exampleStore.PutExampleRecord(context.Background(), existing); err != nil {
		t.Fatalf("PutExampleRecord: %v", err)
	}

	uc := buildUseCase(t, factStore, blobStore, exampleStore)
	result, err := uc.Execute(context.Background(), application.ExtractRequest{Coordinate: coord, Force: true})
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if result.FromCache {
		t.Error("expected FromCache = false when Force=true")
	}
}

func TestExecute_NoExamples(t *testing.T) {
	coord := mustCoord(t, "example.com/noex", "v1.0.0")
	blobStore := &fakeBlobStore{}
	factStore := &fakeFactStore{}
	exampleStore := &fakeExampleStore{}

	zipData := buildModuleZip(t, coord, map[string]string{
		"foo_test.go": "package foo_test\n\nimport \"testing\"\n\nfunc TestFoo(t *testing.T) {}\n",
	})
	handle, err := blobStore.Put(context.Background(), bytes.NewReader(zipData))
	if err != nil {
		t.Fatalf("Put: %v", err)
	}
	putFactWithBlob(t, factStore, coord, string(handle))

	uc := buildUseCase(t, factStore, blobStore, exampleStore)
	result, err := uc.Execute(context.Background(), application.ExtractRequest{Coordinate: coord})
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if result.Record.OverallStatus != domain2.ExampleStatusNone {
		t.Errorf("OverallStatus: got %v, want None", result.Record.OverallStatus)
	}
	if len(result.Record.Examples) != 0 {
		t.Errorf("expected 0 examples, got %d", len(result.Record.Examples))
	}
}

func TestExecute_WithExamples(t *testing.T) {
	coord := mustCoord(t, "example.com/pkg", "v2.0.0")
	blobStore := &fakeBlobStore{}
	factStore := &fakeFactStore{}
	exampleStore := &fakeExampleStore{}

	testSrc := `package pkg_test

import "fmt"

// ExampleFoo demonstrates Foo.
func ExampleFoo() {
	fmt.Println("hello")
	// Output:
	// hello
}

func ExampleBar_method() {
	fmt.Println("bar")
}
`
	zipData := buildModuleZip(t, coord, map[string]string{
		"foo_test.go": testSrc,
	})
	handle, err := blobStore.Put(context.Background(), bytes.NewReader(zipData))
	if err != nil {
		t.Fatalf("Put: %v", err)
	}
	putFactWithBlob(t, factStore, coord, string(handle))

	uc := buildUseCase(t, factStore, blobStore, exampleStore)
	result, err := uc.Execute(context.Background(), application.ExtractRequest{Coordinate: coord})
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if result.Record.OverallStatus != domain2.ExampleStatusFound {
		t.Errorf("OverallStatus: got %v, want Found", result.Record.OverallStatus)
	}
	if len(result.Record.Examples) != 2 {
		t.Fatalf("expected 2 examples, got %d", len(result.Record.Examples))
	}
	if result.Record.ContentHash == "" {
		t.Error("ContentHash must not be empty")
	}

	// Sort order is (Package, AssociatedSymbol, Name):
	// "Bar" < "Foo", so ExampleBar_method is Examples[0] and ExampleFoo is Examples[1].
	// Note: ExampleBar_method has lowercase "method" → sub-example, not method name.

	// Verify ExampleBar_method (index 0 after sort).
	bar := result.Record.Examples[0]
	if bar.Name != "ExampleBar_method" {
		t.Errorf("Examples[0].Name: got %q, want ExampleBar_method", bar.Name)
	}
	if bar.AssociatedSymbol != "Bar" {
		t.Errorf("Examples[0].AssociatedSymbol: got %q, want Bar", bar.AssociatedSymbol)
	}
	if bar.SubExample != "method" {
		t.Errorf("Examples[0].SubExample: got %q, want method", bar.SubExample)
	}
	if bar.Validates {
		t.Error("ExampleBar_method should have Validates=false (no Output comment)")
	}

	// Verify ExampleFoo (index 1 after sort).
	foo := result.Record.Examples[1]
	if foo.Name != "ExampleFoo" {
		t.Errorf("Examples[1].Name: got %q, want ExampleFoo", foo.Name)
	}
	if foo.AssociatedSymbol != "Foo" {
		t.Errorf("Examples[1].AssociatedSymbol: got %q, want Foo", foo.AssociatedSymbol)
	}
	if !foo.Validates {
		t.Error("ExampleFoo should have Validates=true (has // Output: comment)")
	}
	if foo.Output != "hello" {
		t.Errorf("ExampleFoo.Output: got %q, want %q", foo.Output, "hello")
	}
}

func TestExecute_SubExample(t *testing.T) {
	coord := mustCoord(t, "example.com/sub", "v1.0.0")
	blobStore := &fakeBlobStore{}
	factStore := &fakeFactStore{}
	exampleStore := &fakeExampleStore{}

	testSrc := `package sub_test

import "fmt"

func ExampleClient_Do_advanced() {
	fmt.Println("advanced")
}
`
	zipData := buildModuleZip(t, coord, map[string]string{
		"client_test.go": testSrc,
	})
	handle, err := blobStore.Put(context.Background(), bytes.NewReader(zipData))
	if err != nil {
		t.Fatalf("Put: %v", err)
	}
	putFactWithBlob(t, factStore, coord, string(handle))

	uc := buildUseCase(t, factStore, blobStore, exampleStore)
	result, err := uc.Execute(context.Background(), application.ExtractRequest{Coordinate: coord})
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if len(result.Record.Examples) != 1 {
		t.Fatalf("expected 1 example, got %d", len(result.Record.Examples))
	}
	e := result.Record.Examples[0]
	if e.AssociatedSymbol != "Client.Do" {
		t.Errorf("AssociatedSymbol: got %q, want Client.Do", e.AssociatedSymbol)
	}
	if e.SubExample != "advanced" {
		t.Errorf("SubExample: got %q, want advanced", e.SubExample)
	}
}

func TestExecute_ParseFailure(t *testing.T) {
	coord := mustCoord(t, "example.com/bad", "v1.0.0")
	blobStore := &fakeBlobStore{}
	factStore := &fakeFactStore{}
	exampleStore := &fakeExampleStore{}

	zipData := buildModuleZip(t, coord, map[string]string{
		"bad_test.go":  "package bad_test\nfunc Example( {", // syntax error
		"good_test.go": "package good_test\nimport \"fmt\"\nfunc ExampleGood() {\nfmt.Println(\"ok\")\n}\n",
	})
	handle, err := blobStore.Put(context.Background(), bytes.NewReader(zipData))
	if err != nil {
		t.Fatalf("Put: %v", err)
	}
	putFactWithBlob(t, factStore, coord, string(handle))

	uc := buildUseCase(t, factStore, blobStore, exampleStore)
	result, err := uc.Execute(context.Background(), application.ExtractRequest{Coordinate: coord})
	if err != nil {
		t.Fatalf("Execute should not return error for parse failures: %v", err)
	}
	if result.Record.OverallStatus != domain2.ExampleStatusFound {
		t.Errorf("OverallStatus: got %v, want Found", result.Record.OverallStatus)
	}
	if len(result.Record.ParseFailures) != 1 {
		t.Errorf("expected 1 parse failure, got %d", len(result.Record.ParseFailures))
	}
}

func TestExecute_CorruptZip(t *testing.T) {
	coord := mustCoord(t, "example.com/corrupt", "v1.0.0")
	blobStore := &fakeBlobStore{}
	factStore := &fakeFactStore{}
	exampleStore := &fakeExampleStore{}

	handle, err := blobStore.Put(context.Background(), bytes.NewReader([]byte("not a zip")))
	if err != nil {
		t.Fatalf("Put: %v", err)
	}
	putFactWithBlob(t, factStore, coord, string(handle))

	uc := buildUseCase(t, factStore, blobStore, exampleStore)
	result, err := uc.Execute(context.Background(), application.ExtractRequest{Coordinate: coord})
	if err != nil {
		t.Fatalf("Execute should not error on corrupt zip; got %v", err)
	}
	if result.Record.OverallStatus != domain2.ExampleStatusExtractionFailed {
		t.Errorf("OverallStatus: got %v, want ExtractionFailed", result.Record.OverallStatus)
	}
	if result.Record.FailureDetail == "" {
		t.Error("FailureDetail must not be empty for ExtractionFailed record")
	}
}

func TestExecute_Idempotent(t *testing.T) {
	coord := mustCoord(t, "example.com/idem", "v1.0.0")
	blobStore := &fakeBlobStore{}
	factStore := &fakeFactStore{}
	exampleStore := &fakeExampleStore{}

	testSrc := "package idem_test\nimport \"fmt\"\nfunc ExampleFoo() {\nfmt.Println(\"hi\")\n// Output:\n// hi\n}\n"
	zipData := buildModuleZip(t, coord, map[string]string{"foo_test.go": testSrc})
	handle, err := blobStore.Put(context.Background(), bytes.NewReader(zipData))
	if err != nil {
		t.Fatalf("Put: %v", err)
	}
	putFactWithBlob(t, factStore, coord, string(handle))

	uc := buildUseCase(t, factStore, blobStore, exampleStore)

	r1, err := uc.Execute(context.Background(), application.ExtractRequest{Coordinate: coord})
	if err != nil {
		t.Fatalf("first Execute: %v", err)
	}
	r2, err := uc.Execute(context.Background(), application.ExtractRequest{Coordinate: coord})
	if err != nil {
		t.Fatalf("second Execute: %v", err)
	}
	if !r2.FromCache {
		t.Error("second Execute should be a cache hit")
	}
	if r1.Record.ContentHash != r2.Record.ContentHash {
		t.Errorf("content hashes differ: %q vs %q", r1.Record.ContentHash, r2.Record.ContentHash)
	}
}

func TestExecute_DocComment(t *testing.T) {
	coord := mustCoord(t, "example.com/doc", "v1.0.0")
	blobStore := &fakeBlobStore{}
	factStore := &fakeFactStore{}
	exampleStore := &fakeExampleStore{}

	testSrc := `package doc_test

import "fmt"

// ExampleFoo shows how to use Foo.
// Multiple lines are supported.
func ExampleFoo() {
	fmt.Println("ok")
}
`
	zipData := buildModuleZip(t, coord, map[string]string{"foo_test.go": testSrc})
	handle, err := blobStore.Put(context.Background(), bytes.NewReader(zipData))
	if err != nil {
		t.Fatalf("Put: %v", err)
	}
	putFactWithBlob(t, factStore, coord, string(handle))

	uc := buildUseCase(t, factStore, blobStore, exampleStore)
	result, err := uc.Execute(context.Background(), application.ExtractRequest{Coordinate: coord})
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if len(result.Record.Examples) != 1 {
		t.Fatalf("expected 1 example, got %d", len(result.Record.Examples))
	}
	if result.Record.Examples[0].Doc == "" {
		t.Error("expected non-empty Doc for ExampleFoo with doc comment")
	}
}

func TestExecute_InlineOutput(t *testing.T) {
	coord := mustCoord(t, "example.com/inline", "v1.0.0")
	blobStore := &fakeBlobStore{}
	factStore := &fakeFactStore{}
	exampleStore := &fakeExampleStore{}

	// Inline output: "// Output: result" on the same line as the marker.
	testSrc := "package inline_test\n\nimport \"fmt\"\n\nfunc ExampleFoo() {\n\tfmt.Println(\"result\")\n\t// Output: result\n}\n"
	zipData := buildModuleZip(t, coord, map[string]string{"foo_test.go": testSrc})
	handle, err := blobStore.Put(context.Background(), bytes.NewReader(zipData))
	if err != nil {
		t.Fatalf("Put: %v", err)
	}
	putFactWithBlob(t, factStore, coord, string(handle))

	uc := buildUseCase(t, factStore, blobStore, exampleStore)
	result, err := uc.Execute(context.Background(), application.ExtractRequest{Coordinate: coord})
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if len(result.Record.Examples) != 1 {
		t.Fatalf("expected 1 example, got %d", len(result.Record.Examples))
	}
	e := result.Record.Examples[0]
	if !e.Validates {
		t.Error("expected Validates=true for inline // Output: comment")
	}
	if e.Output != "result" {
		t.Errorf("Output: got %q, want %q", e.Output, "result")
	}
}

func TestExecute_UnorderedOutput(t *testing.T) {
	coord := mustCoord(t, "example.com/unordered", "v1.0.0")
	blobStore := &fakeBlobStore{}
	factStore := &fakeFactStore{}
	exampleStore := &fakeExampleStore{}

	testSrc := "package unordered_test\n\nimport \"fmt\"\n\nfunc ExampleFoo() {\n\tfmt.Println(\"b\")\n\tfmt.Println(\"a\")\n\t// Unordered output:\n\t// a\n\t// b\n}\n"
	zipData := buildModuleZip(t, coord, map[string]string{"foo_test.go": testSrc})
	handle, err := blobStore.Put(context.Background(), bytes.NewReader(zipData))
	if err != nil {
		t.Fatalf("Put: %v", err)
	}
	putFactWithBlob(t, factStore, coord, string(handle))

	uc := buildUseCase(t, factStore, blobStore, exampleStore)
	result, err := uc.Execute(context.Background(), application.ExtractRequest{Coordinate: coord})
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if len(result.Record.Examples) != 1 {
		t.Fatalf("expected 1 example, got %d", len(result.Record.Examples))
	}
	if !result.Record.Examples[0].Validates {
		t.Error("expected Validates=true for // Unordered output: comment")
	}
}

func TestExecute_UsedImports(t *testing.T) {
	coord := mustCoord(t, "example.com/imports", "v1.0.0")
	blobStore := &fakeBlobStore{}
	factStore := &fakeFactStore{}
	exampleStore := &fakeExampleStore{}

	// Only "fmt" is used in the example body; "io" is imported but not referenced.
	testSrc := "package imports_test\n\nimport (\n\t\"fmt\"\n\t\"io\"\n)\n\nfunc ExampleFoo() {\n\tfmt.Println(\"ok\")\n}\n\nvar _ io.Reader\n"
	zipData := buildModuleZip(t, coord, map[string]string{"foo_test.go": testSrc})
	handle, err := blobStore.Put(context.Background(), bytes.NewReader(zipData))
	if err != nil {
		t.Fatalf("Put: %v", err)
	}
	putFactWithBlob(t, factStore, coord, string(handle))

	uc := buildUseCase(t, factStore, blobStore, exampleStore)
	result, err := uc.Execute(context.Background(), application.ExtractRequest{Coordinate: coord})
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if len(result.Record.Examples) != 1 {
		t.Fatalf("expected 1 example, got %d", len(result.Record.Examples))
	}
	e := result.Record.Examples[0]
	if len(e.Imports) != 1 || e.Imports[0] != "fmt" {
		t.Errorf("Imports: got %v, want [fmt]", e.Imports)
	}
}

func TestExecute_AliasedImport(t *testing.T) {
	coord := mustCoord(t, "example.com/alias", "v1.0.0")
	blobStore := &fakeBlobStore{}
	factStore := &fakeFactStore{}
	exampleStore := &fakeExampleStore{}

	// Use an aliased import: "myfmt" → "fmt".
	testSrc := "package alias_test\n\nimport myfmt \"fmt\"\n\nfunc ExampleFoo() {\n\tmyfmt.Println(\"ok\")\n}\n"
	zipData := buildModuleZip(t, coord, map[string]string{"foo_test.go": testSrc})
	handle, err := blobStore.Put(context.Background(), bytes.NewReader(zipData))
	if err != nil {
		t.Fatalf("Put: %v", err)
	}
	putFactWithBlob(t, factStore, coord, string(handle))

	uc := buildUseCase(t, factStore, blobStore, exampleStore)
	result, err := uc.Execute(context.Background(), application.ExtractRequest{Coordinate: coord})
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if len(result.Record.Examples) != 1 {
		t.Fatalf("expected 1 example, got %d", len(result.Record.Examples))
	}
	e := result.Record.Examples[0]
	if len(e.Imports) != 1 || e.Imports[0] != "fmt" {
		t.Errorf("Imports: got %v, want [fmt] for aliased import", e.Imports)
	}
}

func TestExecute_BlankImport(t *testing.T) {
	coord := mustCoord(t, "example.com/blank", "v1.0.0")
	blobStore := &fakeBlobStore{}
	factStore := &fakeFactStore{}
	exampleStore := &fakeExampleStore{}

	// Blank import should be excluded from example imports.
	testSrc := "package blank_test\n\nimport (\n\t\"fmt\"\n\t_ \"io\"\n)\n\nfunc ExampleFoo() {\n\tfmt.Println(\"ok\")\n}\n"
	zipData := buildModuleZip(t, coord, map[string]string{"foo_test.go": testSrc})
	handle, err := blobStore.Put(context.Background(), bytes.NewReader(zipData))
	if err != nil {
		t.Fatalf("Put: %v", err)
	}
	putFactWithBlob(t, factStore, coord, string(handle))

	uc := buildUseCase(t, factStore, blobStore, exampleStore)
	result, err := uc.Execute(context.Background(), application.ExtractRequest{Coordinate: coord})
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if len(result.Record.Examples) != 1 {
		t.Fatalf("expected 1 example, got %d", len(result.Record.Examples))
	}
	e := result.Record.Examples[0]
	// Blank import "io" must not appear in the example's import list.
	for _, imp := range e.Imports {
		if imp == "io" {
			t.Errorf("blank import io should not appear in example imports")
		}
	}
}

func TestExecute_ContextCancelled(t *testing.T) {
	coord := mustCoord(t, "example.com/cancel", "v1.0.0")
	blobStore := &fakeBlobStore{}
	factStore := &fakeFactStore{}
	exampleStore := &fakeExampleStore{}

	zipData := buildModuleZip(t, coord, map[string]string{"foo.go": "package foo\n"})
	handle, err := blobStore.Put(context.Background(), bytes.NewReader(zipData))
	if err != nil {
		t.Fatalf("Put: %v", err)
	}
	putFactWithBlob(t, factStore, coord, string(handle))

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // pre-cancel so extractFromZip sees a cancelled context

	uc := buildUseCase(t, factStore, blobStore, exampleStore)
	result, err := uc.Execute(ctx, application.ExtractRequest{Coordinate: coord})
	// Infrastructure errors are returned as Go errors; extraction failures are in the record.
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if result.Record.OverallStatus != domain2.ExampleStatusExtractionFailed {
		t.Errorf("expected ExtractionFailed for cancelled context, got %v", result.Record.OverallStatus)
	}
}

func TestExecute_ZipDirectoryEntry(t *testing.T) {
	coord := mustCoord(t, "example.com/dir", "v1.0.0")
	blobStore := &fakeBlobStore{}
	factStore := &fakeFactStore{}
	exampleStore := &fakeExampleStore{}

	// Build a zip with a directory entry and a test file.
	var buf bytes.Buffer
	w := zip.NewWriter(&buf)
	prefix := coord.Path + "@" + coord.Version + "/"
	// Create a directory entry.
	if _, err := w.Create(prefix + "subdir/"); err != nil {
		t.Fatalf("create dir entry: %v", err)
	}
	// Create a file entry.
	f, err := w.Create(prefix + "foo_test.go")
	if err != nil {
		t.Fatalf("create file entry: %v", err)
	}
	if _, err := f.Write([]byte("package dir_test\nimport \"fmt\"\nfunc ExampleFoo() {\nfmt.Println(\"ok\")\n}\n")); err != nil {
		t.Fatalf("write file: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("zip close: %v", err)
	}

	handle, err := blobStore.Put(context.Background(), bytes.NewReader(buf.Bytes()))
	if err != nil {
		t.Fatalf("Put: %v", err)
	}
	putFactWithBlob(t, factStore, coord, string(handle))

	uc := buildUseCase(t, factStore, blobStore, exampleStore)
	result, err := uc.Execute(context.Background(), application.ExtractRequest{Coordinate: coord})
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if len(result.Record.Examples) != 1 {
		t.Errorf("expected 1 example (directory entry skipped), got %d", len(result.Record.Examples))
	}
}

func TestExecute_NoSpaceInComment(t *testing.T) {
	coord := mustCoord(t, "example.com/nospace", "v1.0.0")
	blobStore := &fakeBlobStore{}
	factStore := &fakeFactStore{}
	exampleStore := &fakeExampleStore{}

	// Use "//comment" (no space) in both the doc comment and the output block.
	// This exercises the else branches in extractDoc and extractOutput.
	testSrc := "package nospace_test\n\nimport \"fmt\"\n\n//ExampleFoo shows Foo.\nfunc ExampleFoo() {\n\tfmt.Println(\"ok\")\n\t// Output:\n\t//ok\n}\n"
	zipData := buildModuleZip(t, coord, map[string]string{"foo_test.go": testSrc})
	handle, err := blobStore.Put(context.Background(), bytes.NewReader(zipData))
	if err != nil {
		t.Fatalf("Put: %v", err)
	}
	putFactWithBlob(t, factStore, coord, string(handle))

	uc := buildUseCase(t, factStore, blobStore, exampleStore)
	result, err := uc.Execute(context.Background(), application.ExtractRequest{Coordinate: coord})
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if len(result.Record.Examples) != 1 {
		t.Fatalf("expected 1 example, got %d", len(result.Record.Examples))
	}
	e := result.Record.Examples[0]
	if e.Doc == "" {
		t.Error("expected non-empty Doc from //comment doc")
	}
	if !e.Validates {
		t.Error("expected Validates=true")
	}
	if e.Output != "ok" {
		t.Errorf("Output: got %q, want %q", e.Output, "ok")
	}
}

func TestExecute_Persists(t *testing.T) {
	coord := mustCoord(t, "example.com/persist", "v1.0.0")
	blobStore := &fakeBlobStore{}
	factStore := &fakeFactStore{}
	exampleStore := &fakeExampleStore{}

	zipData := buildModuleZip(t, coord, map[string]string{
		"foo_test.go": "package foo_test\nimport \"fmt\"\nfunc ExampleFoo() {\nfmt.Println(\"ok\")\n}\n",
	})
	handle, err := blobStore.Put(context.Background(), bytes.NewReader(zipData))
	if err != nil {
		t.Fatalf("Put: %v", err)
	}
	putFactWithBlob(t, factStore, coord, string(handle))

	uc := buildUseCase(t, factStore, blobStore, exampleStore)
	_, err = uc.Execute(context.Background(), application.ExtractRequest{Coordinate: coord})
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}

	persisted, found, err := exampleStore.GetExampleRecord(context.Background(), coord, application.PipelineVersion)
	if err != nil {
		t.Fatalf("GetExampleRecord: %v", err)
	}
	if !found {
		t.Fatal("record was not persisted")
	}
	if len(persisted.Examples) != 1 {
		t.Errorf("expected 1 example in persisted record, got %d", len(persisted.Examples))
	}
}

// -- helpers --

func mustCoord(t *testing.T, path, version string) domain.ModuleCoordinate {
	t.Helper()
	c, err := domain.NewModuleCoordinate(path, version)
	if err != nil {
		t.Fatalf("NewModuleCoordinate(%q, %q): %v", path, version, err)
	}
	return c
}

func buildUseCase(t *testing.T, facts *fakeFactStore, blobs *fakeBlobStore, examples *fakeExampleStore) *application.ExtractExampleUseCase {
	t.Helper()
	if facts == nil {
		facts = &fakeFactStore{}
	}
	if blobs == nil {
		blobs = &fakeBlobStore{}
	}
	if examples == nil {
		examples = &fakeExampleStore{}
	}
	return application.NewExtractExampleUseCase(application.Config{
		Facts:                facts,
		Blobs:                blobs,
		Examples:             examples,
		Parser:               goast.New(),
		Clock:                fakeClock{t: time.Date(2025, 6, 1, 0, 0, 0, 0, time.UTC)},
		Stopwatch:            fakeStopwatch{},
		FetchPipelineVersion: application.PipelineVersion,
		Logger:               slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
}

func putFact(t *testing.T, s *fakeFactStore, coord domain.ModuleCoordinate, blobHandle string) {
	t.Helper()
	putFactWithBlob(t, s, coord, blobHandle)
}

func putFactWithBlob(t *testing.T, s *fakeFactStore, coord domain.ModuleCoordinate, blobHandle string) {
	t.Helper()
	r := domain.FactRecord{
		SchemaVersion:      "2",
		ModulePath:         coord.Path,
		ModuleVersion:      coord.Version,
		PipelineVersion:    application.PipelineVersion,
		ContentLocation:    blobHandle,
		ContentHash:        "sha256:placeholder",
		VerificationStatus: "Verified",
	}
	if err := s.PutFetchRecord(context.Background(), r); err != nil {
		t.Fatalf("PutFetchRecord: %v", err)
	}
}

func buildModuleZip(t *testing.T, coord domain.ModuleCoordinate, files map[string]string) []byte {
	t.Helper()
	var buf bytes.Buffer
	w := zip.NewWriter(&buf)
	prefix := coord.Path + "@" + coord.Version + "/"
	for name, content := range files {
		f, err := w.Create(prefix + name)
		if err != nil {
			t.Fatalf("zip create %q: %v", name, err)
		}
		if _, err := f.Write([]byte(content)); err != nil {
			t.Fatalf("zip write %q: %v", name, err)
		}
	}
	if err := w.Close(); err != nil {
		t.Fatalf("zip close: %v", err)
	}
	return buf.Bytes()
}

// Ensure fakeFactStore satisfies fetchports.FactStore.
var _ fetchports.FactStore = (*fakeFactStore)(nil)
