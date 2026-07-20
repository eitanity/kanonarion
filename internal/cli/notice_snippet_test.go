package cli

import (
	"bytes"
	"context"
	"path/filepath"
	"strings"
	"testing"

	"github.com/eitanity/kanonarion/internal/cli/testfakes"
	fetchdomain "github.com/eitanity/kanonarion/internal/fetch/domain"
	licapp "github.com/eitanity/kanonarion/internal/license/application"
	licdomain "github.com/eitanity/kanonarion/internal/license/domain"
)

// repoRoot returns this repository's module root, two levels up from
// internal/cli. The snippet scan reads real first-party source, so these tests
// exercise the shipped tree rather than a fixture.
func repoRoot(t *testing.T) string {
	t.Helper()
	root, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	return root
}

// The gap this closes: internal/capability/domain/sinks.go transcribes Capslock
// classification data, which is not a go.mod dependency and so never appears in
// the module set. It must still reach THIRD-PARTY-LICENSES.
func TestNoticeWith_IncludesCopiedSourceAttribution(t *testing.T) {
	coord := fetchdomain.ModuleCoordinate{Path: "example.com/dep", Version: "v1.0.0"}
	ctr := &Container{
		QueryWalks: walksWithNodes("W1", coord),
		GenerateNotice: &testfakes.FakeGenerateNotice{Result: licapp.NoticeResult{
			Entries: []licdomain.NoticeEntry{{Coordinate: coord, SPDX: "MIT"}},
		}},
	}

	var stdout, stderr bytes.Buffer
	if err := noticeWith(context.Background(), ctr, "W1", "", "", repoRoot(t), &stdout, &stderr); err != nil {
		t.Fatalf("expected success, got: %v", err)
	}

	doc := stdout.String()
	for _, want := range []string{
		"Copied source:",
		"github.com/google/capslock@v0.3.2",
		"internal/capability/domain/sinks.go",
		"BSD-3-Clause",
		"Copyright 2023 Google LLC",
		"Redistribution and use in source and binary forms",
	} {
		if !strings.Contains(doc, want) {
			t.Errorf("attribution document missing %q", want)
		}
	}
	// The module entry must still be there — copied source is additive.
	if !strings.Contains(doc, "Module:  example.com/dep@v1.0.0") {
		t.Error("module attribution should be unaffected by the snippet scan")
	}
}

// Copied-source entries interleave with module entries by coordinate sort, so
// the document is byte-stable regardless of scan order.
func TestNoticeWith_CopiedSourceSortsWithModules(t *testing.T) {
	before := fetchdomain.ModuleCoordinate{Path: "a.example.com/dep", Version: "v1.0.0"}
	after := fetchdomain.ModuleCoordinate{Path: "z.example.com/dep", Version: "v1.0.0"}
	ctr := &Container{
		QueryWalks: walksWithNodes("W1", before, after),
		GenerateNotice: &testfakes.FakeGenerateNotice{Result: licapp.NoticeResult{
			Entries: []licdomain.NoticeEntry{{Coordinate: before, SPDX: "MIT"}, {Coordinate: after, SPDX: "MIT"}},
		}},
	}

	var stdout, stderr bytes.Buffer
	if err := noticeWith(context.Background(), ctr, "W1", "", "", repoRoot(t), &stdout, &stderr); err != nil {
		t.Fatalf("expected success, got: %v", err)
	}

	doc := stdout.String()
	first := strings.Index(doc, "a.example.com/dep")
	capslock := strings.Index(doc, "github.com/google/capslock")
	last := strings.Index(doc, "z.example.com/dep")
	if first < 0 || capslock < 0 || last < 0 {
		t.Fatalf("expected all three entries, got:\n%s", doc)
	}
	if !(first < capslock && capslock < last) {
		t.Errorf("copied source should sort by coordinate between the modules (a=%d capslock=%d z=%d)", first, capslock, last)
	}
}

// With no store-backed modules at all, a project that redistributes copied
// source still gets a document rather than "no modules found".
func TestNoticeWith_CopiedSourceOnlyStillEmitsDocument(t *testing.T) {
	ctr := &Container{
		QueryWalks:     walksWithNodes("W2"),
		GenerateNotice: &testfakes.FakeGenerateNotice{},
	}

	var stdout, stderr bytes.Buffer
	if err := noticeWith(context.Background(), ctr, "W2", "", "", repoRoot(t), &stdout, &stderr); err != nil {
		t.Fatalf("expected success, got: %v", err)
	}
	if !strings.Contains(stdout.String(), "github.com/google/capslock@v0.3.2") {
		t.Errorf("expected the copied-source attribution, got: %q", stdout.String())
	}
}

// An empty snippet root disables the scan — a --walk-id run outside a checkout
// has no first-party tree to read.
func TestNoticeWith_NoSnippetRootSkipsScan(t *testing.T) {
	ctr := &Container{
		QueryWalks:     walksWithNodes("W2"),
		GenerateNotice: &testfakes.FakeGenerateNotice{},
	}

	var stdout, stderr bytes.Buffer
	if err := noticeWith(context.Background(), ctr, "W2", "", "", "", &stdout, &stderr); err != nil {
		t.Fatalf("expected success, got: %v", err)
	}
	if !strings.Contains(stderr.String(), "no modules found") {
		t.Errorf("expected 'no modules found', got: %q", stderr.String())
	}
}
