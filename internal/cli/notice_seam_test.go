package cli

import (
	"bytes"
	"context"
	"strings"
	"testing"

	"github.com/eitanity/kanonarion/internal/cli/testfakes"
	fetchdomain "github.com/eitanity/kanonarion/internal/fetch/domain"
	licapp "github.com/eitanity/kanonarion/internal/license/application"
	licdomain "github.com/eitanity/kanonarion/internal/license/domain"
	walkdomain "github.com/eitanity/kanonarion/internal/walk/domain"
)

// walksWithNodes returns a FakeQueryWalks holding one walk (id) whose graph has
// a node for each coord — the shape resolveNoticeCoords reads in walkID mode.
func walksWithNodes(id string, coords ...fetchdomain.ModuleCoordinate) *testfakes.FakeQueryWalks {
	nodes := make([]walkdomain.GraphNode, 0, len(coords))
	for _, c := range coords {
		nodes = append(nodes, walkdomain.GraphNode{Coordinate: c})
	}
	fqw := testfakes.NewFakeQueryWalks()
	fqw.AddWalk(walkdomain.WalkRecord{ID: id, Graph: walkdomain.Graph{Nodes: nodes}})
	return fqw
}

// The review gate: when any module requires human review, noticeWith must NOT
// emit the document — it fails loudly with a non-nil error and writes nothing
// to stdout. Publishing an incomplete NOTICE would be the failure mode.
func TestNoticeWith_ReviewItemsFailLoud(t *testing.T) {
	coord := fetchdomain.ModuleCoordinate{Path: "example.com/dep", Version: "v1.0.0"}
	ctr := &Container{
		QueryWalks: walksWithNodes("W1", coord),
		GenerateNotice: &testfakes.FakeGenerateNotice{Result: licapp.NoticeResult{
			ReviewItems: []licdomain.ReviewItem{{Coordinate: coord, Reason: "no license detected"}},
		}},
	}
	var stdout, stderr bytes.Buffer
	err := noticeWith(context.Background(), ctr, "W1", "", "", &stdout, &stderr)
	if err == nil || !strings.Contains(err.Error(), "require review") {
		t.Fatalf("expected a review-required error, got: %v", err)
	}
	if stdout.Len() != 0 {
		t.Errorf("no document must be written when review is required, got: %q", stdout.String())
	}
	if !strings.Contains(stderr.String(), "no license detected") {
		t.Errorf("review reason should be reported to stderr, got: %q", stderr.String())
	}
}

// An empty module set reports "no modules found" and exits 0 without invoking
// the generator.
func TestNoticeWith_NoModules(t *testing.T) {
	ctr := &Container{
		QueryWalks:     walksWithNodes("W2"), // walk with zero nodes
		GenerateNotice: &testfakes.FakeGenerateNotice{},
	}
	var stdout, stderr bytes.Buffer
	if err := noticeWith(context.Background(), ctr, "W2", "", "", &stdout, &stderr); err != nil {
		t.Fatalf("empty module set should exit 0, got: %v", err)
	}
	if !strings.Contains(stderr.String(), "no modules found") {
		t.Errorf("expected 'no modules found' notice, got: %q", stderr.String())
	}
}

// With no review items, the document is written to stdout.
func TestNoticeWith_WritesDocument(t *testing.T) {
	coord := fetchdomain.ModuleCoordinate{Path: "example.com/dep", Version: "v1.0.0"}
	ctr := &Container{
		QueryWalks: walksWithNodes("W1", coord),
		GenerateNotice: &testfakes.FakeGenerateNotice{Result: licapp.NoticeResult{
			Entries: []licdomain.NoticeEntry{{Coordinate: coord, SPDX: "MIT"}},
		}},
	}
	var stdout, stderr bytes.Buffer
	if err := noticeWith(context.Background(), ctr, "W1", "", "", &stdout, &stderr); err != nil {
		t.Fatalf("expected success, got: %v", err)
	}
	if !strings.Contains(stdout.String(), "THIRD-PARTY-LICENSES") {
		t.Errorf("expected the attribution document on stdout, got: %q", stdout.String())
	}
}
