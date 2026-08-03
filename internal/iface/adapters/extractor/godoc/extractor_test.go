package godoc_test

import (
	"context"
	"fmt"
	"io/fs"
	"strings"
	"testing"
	"testing/fstest"
	"time"

	"github.com/eitanity/kanonarion/internal/coordinate"

	"github.com/eitanity/kanonarion/internal/iface/adapters/extractor/godoc"
	domain2 "github.com/eitanity/kanonarion/internal/iface/domain"
)

type fixedClock struct{ t time.Time }

func (c fixedClock) Now() time.Time { return c.t }

func makeExtractor() *godoc.Extractor {
	return godoc.New("0.1.0", fixedClock{t: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)})
}

func coord(t testing.TB) coordinate.ModuleCoordinate {
	t.Helper()
	c, err := coordinate.NewModuleCoordinate("example.com/m", "v1.0.0")
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestExtractor_SingleExportedType(t *testing.T) {
	fsys := fstest.MapFS{
		"client.go": &fstest.MapFile{
			Data: []byte(`package mypkg

// Client calls the remote service.
type Client struct {
	// Timeout is the request timeout.
	Timeout int
}

// Do sends a request.
func (c *Client) Do() error { return nil }
`),
		},
	}

	ext := makeExtractor()
	r, err := ext.Extract(context.Background(), fsys, coord(t))
	if err != nil {
		t.Fatalf("Extract: %v", err)
	}

	if r.OverallStatus != domain2.InterfaceStatusExtracted {
		t.Errorf("OverallStatus = %s, want Extracted", r.OverallStatus)
	}
	if len(r.Packages) != 1 {
		t.Fatalf("len(Packages) = %d, want 1", len(r.Packages))
	}
	pkg := r.Packages[0]
	if len(pkg.Types) != 1 {
		t.Fatalf("len(Types) = %d, want 1", len(pkg.Types))
	}
	typ := pkg.Types[0]
	if typ.Name != "Client" {
		t.Errorf("Type.Name = %q, want Client", typ.Name)
	}
	if typ.Kind != domain2.TypeKindStruct {
		t.Errorf("Type.Kind = %s, want struct", typ.Kind)
	}
	if typ.Doc == "" {
		t.Error("Type.Doc is empty")
	}
	if strings.HasPrefix(typ.Signature, "//") {
		t.Errorf("Type.Signature starts with comment line: %q", typ.Signature)
	}
	if len(typ.Methods) != 1 {
		t.Fatalf("len(Methods) = %d, want 1", len(typ.Methods))
	}
	if typ.Methods[0].Name != "Do" {
		t.Errorf("Method.Name = %q, want Do", typ.Methods[0].Name)
	}
	if !typ.Methods[0].PtrReceiver {
		t.Error("Method.PtrReceiver = false, want true")
	}
	if strings.HasPrefix(typ.Methods[0].Signature, "//") {
		t.Errorf("Method.Signature starts with comment line: %q", typ.Methods[0].Signature)
	}
}

func TestExtractor_ExportedFunc(t *testing.T) {
	fsys := fstest.MapFS{
		"funcs.go": &fstest.MapFile{
			Data: []byte(`package mypkg

// New constructs a Client.
func New(addr string) *Client { return nil }

type Client struct{}
`),
		},
	}

	r, err := makeExtractor().Extract(context.Background(), fsys, coord(t))
	if err != nil {
		t.Fatal(err)
	}
	if len(r.Packages[0].Funcs) != 1 {
		t.Fatalf("len(Funcs) = %d, want 1", len(r.Packages[0].Funcs))
	}
	f := r.Packages[0].Funcs[0]
	if f.Name != "New" {
		t.Errorf("Func.Name = %q, want New", f.Name)
	}
	if f.Signature == "" {
		t.Error("Func.Signature is empty")
	}
	if strings.HasPrefix(f.Signature, "//") {
		t.Errorf("Func.Signature starts with comment line: %q", f.Signature)
	}
}

func TestExtractor_ConstsAndVars(t *testing.T) {
	fsys := fstest.MapFS{
		"values.go": &fstest.MapFile{
			Data: []byte(`package mypkg

const MaxRetries = 3

var DefaultAddr = "localhost:8080"
`),
		},
	}

	r, err := makeExtractor().Extract(context.Background(), fsys, coord(t))
	if err != nil {
		t.Fatal(err)
	}
	pkg := r.Packages[0]
	if len(pkg.Consts) != 1 || pkg.Consts[0].Name != "MaxRetries" {
		t.Errorf("Consts: %+v", pkg.Consts)
	}
	if len(pkg.Vars) != 1 || pkg.Vars[0].Name != "DefaultAddr" {
		t.Errorf("Vars: %+v", pkg.Vars)
	}
}

func TestExtractor_GenericsTypeParam(t *testing.T) {
	fsys := fstest.MapFS{
		"generic.go": &fstest.MapFile{
			Data: []byte(`package mypkg

// Stack is a generic stack.
type Stack[T any] struct {
	items []T
}
`),
		},
	}

	r, err := makeExtractor().Extract(context.Background(), fsys, coord(t))
	if err != nil {
		t.Fatal(err)
	}
	if len(r.Packages) == 0 || len(r.Packages[0].Types) == 0 {
		t.Fatal("no types extracted")
	}
	typ := r.Packages[0].Types[0]
	if typ.Kind != domain2.TypeKindGeneric {
		t.Errorf("Kind = %s, want generic", typ.Kind)
	}
	if len(typ.TypeParams) != 1 || typ.TypeParams[0].Name != "T" {
		t.Errorf("TypeParams: %+v", typ.TypeParams)
	}
}

func TestExtractor_InterfaceEmbedding(t *testing.T) {
	fsys := fstest.MapFS{
		"iface.go": &fstest.MapFile{
			Data: []byte(`package mypkg

import "io"

// ReadWriter combines Reader and Writer.
type ReadWriter interface {
	io.Reader
	io.Writer
}
`),
		},
	}

	r, err := makeExtractor().Extract(context.Background(), fsys, coord(t))
	if err != nil {
		t.Fatal(err)
	}
	if len(r.Packages[0].Types) == 0 {
		t.Fatal("no types extracted")
	}
	typ := r.Packages[0].Types[0]
	if typ.Kind != domain2.TypeKindInterface {
		t.Errorf("Kind = %s, want interface", typ.Kind)
	}
	if len(typ.EmbeddedTypes) != 2 {
		t.Errorf("EmbeddedTypes: %v", typ.EmbeddedTypes)
	}
}

func TestExtractor_ParseFailure(t *testing.T) {
	fsys := fstest.MapFS{
		"good.go": &fstest.MapFile{
			Data: []byte(`package mypkg

// Foo is exported.
type Foo struct{}
`),
		},
		"bad.go": &fstest.MapFile{
			Data: []byte(`package mypkg

this is not valid go syntax !!!
`),
		},
	}

	r, err := makeExtractor().Extract(context.Background(), fsys, coord(t))
	if err != nil {
		t.Fatal(err)
	}
	if r.OverallStatus != domain2.InterfaceStatusPartial {
		t.Errorf("OverallStatus = %s, want Partial", r.OverallStatus)
	}
	if len(r.Packages) == 0 || len(r.Packages[0].ParseFailures) == 0 {
		t.Error("expected ParseFailures, got none")
	}
}

func TestExtractor_TestFilesExcluded(t *testing.T) {
	fsys := fstest.MapFS{
		"client.go": &fstest.MapFile{
			Data: []byte(`package mypkg

type Client struct{}
`),
		},
		"client_test.go": &fstest.MapFile{
			Data: []byte(`package mypkg_test

// ExampleClient should not appear in interface.
func ExampleClient() {}
`),
		},
	}

	r, err := makeExtractor().Extract(context.Background(), fsys, coord(t))
	if err != nil {
		t.Fatal(err)
	}
	// No funcs from the test file should appear.
	if len(r.Packages[0].Funcs) != 0 {
		t.Errorf("expected 0 funcs (test file excluded), got %d", len(r.Packages[0].Funcs))
	}
}

func TestExtractor_VendorDirSkipped(t *testing.T) {
	fsys := fstest.MapFS{
		"client.go": &fstest.MapFile{
			Data: []byte(`package mypkg

type Client struct{}
`),
		},
		"vendor/github.com/foo/bar/bar.go": &fstest.MapFile{
			Data: []byte(`package bar

type Bar struct{}
`),
		},
	}

	r, err := makeExtractor().Extract(context.Background(), fsys, coord(t))
	if err != nil {
		t.Fatal(err)
	}
	for _, pkg := range r.Packages {
		if strings.HasPrefix(pkg.ImportPath, "vendor") {
			t.Errorf("vendor package should be excluded: %s", pkg.ImportPath)
		}
	}
}

func TestExtractor_ImportPath(t *testing.T) {
	fsys := fstest.MapFS{
		"doc.go": &fstest.MapFile{
			Data: []byte(`package m

type Root struct{}
`),
		},
		"sub/sub.go": &fstest.MapFile{
			Data: []byte(`package sub

type Sub struct{}
`),
		},
	}

	r, err := makeExtractor().Extract(context.Background(), fsys, coord(t))
	if err != nil {
		t.Fatal(err)
	}
	if len(r.Packages) != 2 {
		t.Fatalf("expected 2 packages, got %d", len(r.Packages))
	}
	paths := map[string]bool{}
	for _, pkg := range r.Packages {
		paths[pkg.ImportPath] = true
	}
	if !paths["example.com/m"] {
		t.Errorf("root package ImportPath should be %q, got paths: %v", "example.com/m", paths)
	}
	if !paths["example.com/m/sub"] {
		t.Errorf("sub-package ImportPath should be %q, got paths: %v", "example.com/m/sub", paths)
	}
}

func TestExtractor_GeneratedFilesFlagged(t *testing.T) {
	fsys := fstest.MapFS{
		"gen.go": &fstest.MapFile{
			Data: []byte(`// Code generated by protoc. DO NOT EDIT.

package mypkg

type GenType struct{}
`),
		},
	}

	r, err := makeExtractor().Extract(context.Background(), fsys, coord(t))
	if err != nil {
		t.Fatal(err)
	}
	if len(r.Packages) == 0 || len(r.Packages[0].Types) == 0 {
		t.Fatal("no types")
	}
	if !r.Packages[0].Types[0].IsGenerated {
		t.Error("IsGenerated = false, want true for generated file")
	}
}

func TestExtractor_MultiPackageDirs(t *testing.T) {
	fsys := fstest.MapFS{
		"client.go": &fstest.MapFile{
			Data: []byte(`package client

type Client struct{}
`),
		},
		"server/server.go": &fstest.MapFile{
			Data: []byte(`package server

type Server struct{}
`),
		},
	}

	r, err := makeExtractor().Extract(context.Background(), fsys, coord(t))
	if err != nil {
		t.Fatal(err)
	}
	if len(r.Packages) != 2 {
		t.Errorf("len(Packages) = %d, want 2", len(r.Packages))
	}
}

func TestExtractor_Sorted(t *testing.T) {
	fsys := fstest.MapFS{
		"z.go": &fstest.MapFile{
			Data: []byte(`package mypkg

type Zebra struct{}
type Antelope struct{}

func ZFunc() {}
func AFunc() {}
`),
		},
	}

	r, err := makeExtractor().Extract(context.Background(), fsys, coord(t))
	if err != nil {
		t.Fatal(err)
	}
	pkg := r.Packages[0]
	if pkg.Types[0].Name != "Antelope" {
		t.Errorf("types not sorted: first = %q", pkg.Types[0].Name)
	}
	if pkg.Funcs[0].Name != "AFunc" {
		t.Errorf("funcs not sorted: first = %q", pkg.Funcs[0].Name)
	}
}

func TestExtractor_Deterministic(t *testing.T) {
	fsys := fstest.MapFS{
		"a.go": &fstest.MapFile{
			Data: []byte(`package mypkg

type A struct{ X int }
func (a *A) M() {}
func Top() *A { return nil }
const C = 1
var V = "hello"
`),
		},
	}
	ext := makeExtractor()
	c := coord(t)

	r1, err1 := ext.Extract(context.Background(), fsys, c)
	r2, err2 := ext.Extract(context.Background(), fsys, c)
	if err1 != nil || err2 != nil {
		t.Fatalf("Extract: %v / %v", err1, err2)
	}

	var h interface {
		SetContentHash(domain2.InterfaceRecord) (domain2.InterfaceRecord, error)
		Marshal(domain2.InterfaceRecord) ([]byte, error)
	} = domain2.InterfaceRecordHasher{}

	r1, _ = h.SetContentHash(r1)
	r2, _ = h.SetContentHash(r2)
	b1, _ := h.Marshal(r1)
	b2, _ := h.Marshal(r2)
	if string(b1) != string(b2) {
		t.Error("two identical extractions produced different output")
	}
}

func TestExtractor_InternalPackageFlagged(t *testing.T) {
	fsys := fstest.MapFS{
		"internal/util/util.go": &fstest.MapFile{
			Data: []byte(`package util

type Helper struct{}
`),
		},
	}

	r, err := makeExtractor().Extract(context.Background(), fsys, coord(t))
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, pkg := range r.Packages {
		if pkg.IsInternal {
			found = true
		}
	}
	if !found {
		t.Error("internal package not flagged IsInternal")
	}
}

func TestExtractor_ContextCancelled(t *testing.T) {
	// Build a big fs to ensure cancellation fires before all dirs are processed.
	fsys := make(fstest.MapFS)
	for i := range 50 {
		name := "pkg" + string(rune('a'+i%26)) + "/file.go"
		fsys[name] = &fstest.MapFile{
			Data: []byte(`package p

type T struct{}
`),
		}
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // cancel immediately

	r, err := makeExtractor().Extract(ctx, fs.FS(fsys), coord(t))
	if err != nil {
		t.Fatalf("Extract should not return error on cancel: %v", err)
	}
	if r.OverallStatus != domain2.InterfaceStatusCancelled {
		t.Errorf("OverallStatus = %s, want Cancelled", r.OverallStatus)
	}
}

func TestExtractor_AliasType(t *testing.T) {
	fsys := fstest.MapFS{
		"alias.go": &fstest.MapFile{
			Data: []byte(`package mypkg

import "io"

// ReadCloser is an alias.
type ReadCloser = io.ReadCloser
`),
		},
	}

	r, err := makeExtractor().Extract(context.Background(), fsys, coord(t))
	if err != nil {
		t.Fatal(err)
	}
	if len(r.Packages) == 0 || len(r.Packages[0].Types) == 0 {
		t.Fatal("no types")
	}
	if r.Packages[0].Types[0].Kind != domain2.TypeKindAlias {
		t.Errorf("Kind = %s, want alias", r.Packages[0].Types[0].Kind)
	}
}

func TestExtractor_ComplexTypes(t *testing.T) {
	fsys := fstest.MapFS{
		"complex.go": &fstest.MapFile{
			Data: []byte(`package mypkg

type Complex struct {
	Map map[string][]int
	Chan chan<- bool
	Func func(a, b int) (error, bool)
	Array [3]string
	Slice []interface{}
	Ptr *int
}
`),
		},
	}

	r, err := makeExtractor().Extract(context.Background(), fsys, coord(t))
	if err != nil {
		t.Fatal(err)
	}
	if len(r.Packages[0].Types) == 0 {
		t.Fatal("no types")
	}
	typ := r.Packages[0].Types[0]
	foundMap := false
	foundChan := false
	for _, f := range typ.Fields {
		if f.Name == "Map" && f.Type == "map[string][]int" {
			foundMap = true
		}
		if f.Name == "Chan" && f.Type == "chan<- bool" {
			foundChan = true
		}
	}
	if !foundMap {
		t.Error("Map field not found or incorrect type")
	}
	if !foundChan {
		t.Error("Chan field not found or incorrect type")
	}
}

func TestExtractor_Generics(t *testing.T) {
	fsys := fstest.MapFS{
		"gen.go": &fstest.MapFile{
			Data: []byte(`package mypkg

type Container[T any] struct {
	Value T
}

func (c Container[T]) Get() T { return c.Value }
`),
		},
	}

	r, err := makeExtractor().Extract(context.Background(), fsys, coord(t))
	if err != nil {
		t.Fatal(err)
	}
	if len(r.Packages[0].Types) == 0 {
		t.Fatal("no types")
	}
	typ := r.Packages[0].Types[0]
	if typ.Name != "Container" {
		t.Errorf("got %s, want Container", typ.Name)
	}
}

// TestExtractor_PartialRecordsItsReason pins that a Partial record states why it
// is partial. The status word alone was unactionable and unfalsifiable: nothing
// named which package failed or why, and re-deriving the record was the only way
// to find out.
func TestExtractor_PartialRecordsItsReason(t *testing.T) {
	fsys := fstest.MapFS{
		"good.go":    &fstest.MapFile{Data: []byte("package mypkg\n\ntype Foo struct{}\n")},
		"bad/bad.go": &fstest.MapFile{Data: []byte("package bad\n\nthis is not valid go !!!\n")},
		"worse/w.go": &fstest.MapFile{Data: []byte("package worse\n\nalso not valid !!!\n")},
	}

	r, err := makeExtractor().Extract(context.Background(), fsys, coord(t))
	if err != nil {
		t.Fatal(err)
	}
	if r.OverallStatus != domain2.InterfaceStatusPartial {
		t.Fatalf("OverallStatus = %s, want Partial", r.OverallStatus)
	}
	if r.FailureDetail == "" {
		t.Fatal("Partial record recorded no FailureDetail")
	}
	// The detail must name a failing package and its parse error, not merely
	// count them.
	if !strings.Contains(r.FailureDetail, "example.com/m/bad") {
		t.Errorf("FailureDetail names no failing package: %q", r.FailureDetail)
	}
	if !strings.Contains(r.FailureDetail, "bad/bad.go") {
		t.Errorf("FailureDetail carries no parse error: %q", r.FailureDetail)
	}
	if !strings.Contains(r.FailureDetail, "2 package(s)") {
		t.Errorf("FailureDetail does not count the failing packages: %q", r.FailureDetail)
	}
	if !strings.Contains(r.FailureDetail, "+1 more") {
		t.Errorf("FailureDetail does not account for the unnamed failures: %q", r.FailureDetail)
	}
	if strings.Contains(r.FailureDetail, "\n") {
		t.Errorf("FailureDetail spans several lines: %q", r.FailureDetail)
	}
}

// TestExtractor_PartialDetailIsDeterministic pins that the reason does not vary
// between two extractions of the same tree. The package directories are
// collected through a map, so a detail taken in iteration order would make two
// identical extractions two records with different content hashes.
func TestExtractor_PartialDetailIsDeterministic(t *testing.T) {
	fsys := fstest.MapFS{
		"a/a.go": &fstest.MapFile{Data: []byte("package a\n\ninvalid !!!\n")},
		"b/b.go": &fstest.MapFile{Data: []byte("package b\n\ninvalid !!!\n")},
		"c/c.go": &fstest.MapFile{Data: []byte("package c\n\ninvalid !!!\n")},
	}
	first := ""
	for i := range 8 {
		r, err := makeExtractor().Extract(context.Background(), fsys, coord(t))
		if err != nil {
			t.Fatal(err)
		}
		if i == 0 {
			first = r.FailureDetail
			continue
		}
		if r.FailureDetail != first {
			t.Fatalf("FailureDetail varies between extractions:\n %q\n %q", first, r.FailureDetail)
		}
	}
}

// TestExtractor_ExtractedRecordsNoReason is the control: a complete extraction
// records no detail, because it has none. "No detail recorded" is the true value
// for it, and a record that stated one would be making a claim it cannot support
// — as well as changing the content hash of every complete record in the store.
func TestExtractor_ExtractedRecordsNoReason(t *testing.T) {
	fsys := fstest.MapFS{
		"client.go": &fstest.MapFile{Data: []byte("package mypkg\n\ntype Client struct{}\n")},
	}
	r, err := makeExtractor().Extract(context.Background(), fsys, coord(t))
	if err != nil {
		t.Fatal(err)
	}
	if r.OverallStatus != domain2.InterfaceStatusExtracted {
		t.Fatalf("OverallStatus = %s, want Extracted", r.OverallStatus)
	}
	if r.FailureDetail != "" {
		t.Errorf("complete extraction recorded a detail it does not have: %q", r.FailureDetail)
	}
}

// countingFS is a fault seam for the directory-read failure path. The extractor
// reads each package directory twice — once collecting the directories, once
// parsing one — and this fails the second read of one directory, which is the
// transient I/O error the silent skip used to swallow whole.
type countingFS struct {
	fstest.MapFS
	target string
	seen   map[string]int
}

func (c *countingFS) ReadDir(name string) ([]fs.DirEntry, error) {
	c.seen[name]++
	if name == c.target && c.seen[name] > 1 {
		return nil, fs.ErrPermission
	}
	entries, err := c.MapFS.ReadDir(name)
	if err != nil {
		return nil, fmt.Errorf("reading %s: %w", name, err)
	}
	return entries, nil
}

// TestExtractor_UnreadableDirRecordsItsReason pins that a directory the
// extractor could not turn into a package is recorded rather than skipped
// silently. The skip discarded the only statement about that directory a reader
// could act on, and left the record claiming the directory did not exist.
func TestExtractor_UnreadableDirRecordsItsReason(t *testing.T) {
	fsys := &countingFS{
		MapFS: fstest.MapFS{
			"good.go":     &fstest.MapFile{Data: []byte("package mypkg\n\ntype Foo struct{}\n")},
			"locked/l.go": &fstest.MapFile{Data: []byte("package locked\n\ntype Bar struct{}\n")},
		},
		target: "locked",
		seen:   map[string]int{},
	}

	r, err := makeExtractor().Extract(context.Background(), fsys, coord(t))
	if err != nil {
		t.Fatal(err)
	}
	if r.OverallStatus != domain2.InterfaceStatusPartial {
		t.Fatalf("OverallStatus = %s, want Partial", r.OverallStatus)
	}
	if !strings.Contains(r.FailureDetail, "example.com/m/locked") {
		t.Errorf("FailureDetail does not name the unreadable directory: %q", r.FailureDetail)
	}
	var found *domain2.PackageInterface
	for i := range r.Packages {
		if r.Packages[i].ImportPath == "example.com/m/locked" {
			found = &r.Packages[i]
		}
	}
	if found == nil {
		t.Fatalf("the unreadable directory is absent from the record entirely: %v", r.Packages)
	}
	if len(found.ParseFailures) != 1 || found.ParseFailures[0].File != "locked" {
		t.Fatalf("directory failure not recorded on the package: %+v", found.ParseFailures)
	}
	if !strings.Contains(found.ParseFailures[0].Error, "permission") {
		t.Errorf("recorded failure does not carry the cause: %q", found.ParseFailures[0].Error)
	}
}

// TestExtractor_CancelledRecordsItsReason pins that an interrupted extraction
// states what it got through, so the record reads as a measurement that stopped
// rather than as a module with almost no API.
func TestExtractor_CancelledRecordsItsReason(t *testing.T) {
	fsys := fstest.MapFS{
		"a/a.go": &fstest.MapFile{Data: []byte("package a\n\ntype A struct{}\n")},
		"b/b.go": &fstest.MapFile{Data: []byte("package b\n\ntype B struct{}\n")},
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	r, err := makeExtractor().Extract(ctx, fsys, coord(t))
	if err != nil {
		t.Fatal(err)
	}
	if r.OverallStatus != domain2.InterfaceStatusCancelled {
		t.Fatalf("OverallStatus = %s, want Cancelled", r.OverallStatus)
	}
	if !strings.Contains(r.FailureDetail, "cancelled") || !strings.Contains(r.FailureDetail, "context canceled") {
		t.Errorf("cancelled record does not state its cause: %q", r.FailureDetail)
	}
}
