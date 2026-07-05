package goast

import (
	"archive/zip"
	"bytes"
	"testing"
)

func buildZip(t *testing.T, prefix string, files map[string]string) []byte {
	t.Helper()
	var buf bytes.Buffer
	w := zip.NewWriter(&buf)
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

func TestParse_ExtractsExample(t *testing.T) {
	const src = `package foo_test

import "fmt"

// ExampleAdd shows addition.
func ExampleAdd() {
	fmt.Println(1 + 2)
	// Output: 3
}
`
	prefix := "example.com/foo@v1.0.0/"
	zipData := buildZip(t, prefix, map[string]string{
		"add_test.go": src,
		"add.go":      "package foo\n",
	})

	entries, failures, err := Parser{}.Parse(zipData, prefix)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if len(failures) != 0 {
		t.Fatalf("unexpected failures: %v", failures)
	}
	if len(entries) != 1 {
		t.Fatalf("want 1 entry, got %d", len(entries))
	}
	e := entries[0]
	if e.Name != "ExampleAdd" {
		t.Errorf("Name = %q, want ExampleAdd", e.Name)
	}
	if e.AssociatedSymbol != "Add" {
		t.Errorf("AssociatedSymbol = %q, want Add", e.AssociatedSymbol)
	}
	if !e.Validates || e.Output != "3" {
		t.Errorf("Output = %q validates=%v, want \"3\" true", e.Output, e.Validates)
	}
	if e.Position.File != "add_test.go" {
		t.Errorf("Position.File = %q, want add_test.go", e.Position.File)
	}
}

// TestParse_UniquePackageKeys covers two sources of duplicate example names:
//
//  1. Sibling sub-packages share a Go package name (GCP SDK pattern: apiv1/ and
//     apiv1beta1/ both declare "package aiplatform"). Without the fix both entries
//     would collide in example_index on (package_path, associated_symbol, example_name).
//
//  2. Internal and external test packages in the same directory ("package foo" and
//     "package foo_test") can both legally define the same Example function. Without
//     the fix the bare directory path would be identical for both, causing a UNIQUE
//     constraint violation on the second INSERT.
func TestParse_UniquePackageKeys(t *testing.T) {
	const sharedName = `
import "fmt"

func ExampleClient_Do() { fmt.Println("ok") }
`
	prefix := "example.com/m@v1.0.0/"
	zipData := buildZip(t, prefix, map[string]string{
		// Case 1: different dirs, same package name.
		"apiv1/ex_test.go":      "package aiplatform\n" + sharedName,
		"apiv1beta1/ex_test.go": "package aiplatform\n" + sharedName,
		// Case 2: same dir, internal vs external test package.
		"sub/internal_test.go": "package sub\n" + sharedName,
		"sub/external_test.go": "package sub_test\n" + sharedName,
	})

	entries, failures, err := Parser{}.Parse(zipData, prefix)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if len(failures) != 0 {
		t.Fatalf("unexpected parse failures: %v", failures)
	}
	if len(entries) != 4 {
		t.Fatalf("want 4 entries, got %d: %v", len(entries), entries)
	}

	pkgs := map[string]bool{}
	for _, e := range entries {
		pkgs[e.Package] = true
		if e.Package == "aiplatform" {
			t.Errorf("entry %q: Package is bare name %q, want dir:name key", e.Name, e.Package)
		}
	}
	if len(pkgs) != 4 {
		t.Errorf("want 4 distinct Package keys (all four entries unique), got %d: %v", len(pkgs), pkgs)
	}
}

func TestParse_BadZip(t *testing.T) {
	if _, _, err := (Parser{}).Parse([]byte("not a zip"), "x/"); err == nil {
		t.Fatal("expected error for invalid zip")
	}
}

func TestParse_RecordsParseFailure(t *testing.T) {
	prefix := "example.com/foo@v1.0.0/"
	zipData := buildZip(t, prefix, map[string]string{
		"broken_test.go": "package foo_test\nfunc (\n",
	})
	entries, failures, err := Parser{}.Parse(zipData, prefix)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if len(entries) != 0 {
		t.Fatalf("want 0 entries, got %d", len(entries))
	}
	if len(failures) != 1 || failures[0].File != "broken_test.go" {
		t.Fatalf("want 1 failure for broken_test.go, got %v", failures)
	}
}
