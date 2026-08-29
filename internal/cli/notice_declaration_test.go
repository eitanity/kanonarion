package cli

import (
	"bytes"
	"context"
	"strings"
	"testing"

	"github.com/eitanity/kanonarion/internal/cli/testfakes"
	configdomain "github.com/eitanity/kanonarion/internal/config/domain"
	"github.com/eitanity/kanonarion/internal/coordinate/coordinatetest"
	licapp "github.com/eitanity/kanonarion/internal/license/application"
	licdomain "github.com/eitanity/kanonarion/internal/license/domain"
)

// synthDecl is an obviously invented declaration; see the note in the licence
// application tests.
func synthDecl(line string) licdomain.CopyrightDeclaration {
	return licdomain.CopyrightDeclaration{
		Copyright:  line,
		DeclaredBy: "test-operator@example.invalid",
		DeclaredOn: "2026-08-25",
		Basis:      "synthetic fixture; no upstream source was read",
	}
}

// A declaration standing in for a copyright the archive does not carry is
// rendered as the attribution AND marked as human-supplied with its basis. A
// document that printed it indistinguishably from an extracted line would put
// an unverifiable assertion into an audit file under the tool's name.
func TestNoticeWith_DeclarationIsMarkedHumanSupplied(t *testing.T) {
	coord := coordinatetest.MustNew("example.com/nocopyright", "v1.0.0")
	decl := synthDecl("Copyright SYNTHETIC-FIXTURE-HOLDER")
	ctr := &Container{
		QueryWalks: walksWithNodes("W1", coord),
		GenerateNotice: &testfakes.FakeGenerateNotice{Result: licapp.NoticeResult{
			Entries: []licdomain.NoticeEntry{{
				Coordinate:  coord,
				SPDX:        "Apache-2.0",
				Declaration: &decl,
			}},
		}},
	}
	var stdout, stderr bytes.Buffer
	if err := noticeWith(context.Background(), ctr, "W1", "", "", "", "", &stdout, &stderr); err != nil {
		t.Fatalf("noticeWith: %v", err)
	}
	doc := stdout.String()
	for _, want := range []string{
		"Copyright notices (human-supplied; none found in the module):",
		"Copyright SYNTHETIC-FIXTURE-HOLDER",
		"declared by test-operator@example.invalid on 2026-08-25",
		"basis: synthetic fixture; no upstream source was read",
	} {
		if !strings.Contains(doc, want) {
			t.Errorf("document is missing %q:\n%s", want, doc)
		}
	}
}

// The falsifying case at the document level: an extracted notice is what the
// document attributes, and the declaration appears only as corroboration under
// a heading that says so.
func TestNoticeWith_DeclarationBesideExtractedIsCorroboration(t *testing.T) {
	coord := coordinatetest.MustNew("example.com/hascopyright", "v1.0.0")
	decl := synthDecl("Copyright 1999 DECLARED-BY-A-HUMAN")
	ctr := &Container{
		QueryWalks: walksWithNodes("W1", coord),
		GenerateNotice: &testfakes.FakeGenerateNotice{Result: licapp.NoticeResult{
			Entries: []licdomain.NoticeEntry{{
				Coordinate:  coord,
				SPDX:        "MIT",
				Copyrights:  []string{"Copyright 2020 EXTRACTED-FROM-ARCHIVE"},
				Declaration: &decl,
			}},
		}},
	}
	var stdout, stderr bytes.Buffer
	if err := noticeWith(context.Background(), ctr, "W1", "", "", "", "", &stdout, &stderr); err != nil {
		t.Fatalf("noticeWith: %v", err)
	}
	doc := stdout.String()
	if !strings.Contains(doc, "Copyright notices:\n  Copyright 2020 EXTRACTED-FROM-ARCHIVE") {
		t.Errorf("the extracted line is not the attributed one:\n%s", doc)
	}
	if !strings.Contains(doc, "corroboration; the extracted notice above is authoritative") {
		t.Errorf("the declaration is not labelled as corroboration:\n%s", doc)
	}
	if strings.Contains(doc, "human-supplied; none found in the module") {
		t.Errorf("the declaration is presented as the attribution beside an extracted notice:\n%s", doc)
	}
}

// A missing-copyright refusal names the way out. The refusal was already
// correct and already named the modules; without the remedy the operator had a
// correct refusal and no next step, which is the defect.
func TestNoticeWith_MissingCopyrightRefusalNamesTheRemedy(t *testing.T) {
	coord := coordinatetest.MustNew("example.com/dep", "v1.0.0")
	ctr := &Container{
		QueryWalks: walksWithNodes("W1", coord),
		GenerateNotice: &testfakes.FakeGenerateNotice{Result: licapp.NoticeResult{
			ReviewItems: []licdomain.ReviewItem{{
				Coordinate:       coord,
				Reason:           "copyright not found (status: none_found)",
				MissingCopyright: true,
			}},
		}},
	}
	var stdout, stderr bytes.Buffer
	err := noticeWith(context.Background(), ctr, "W1", "", "", "", "", &stdout, &stderr)
	if err == nil {
		t.Fatal("expected the review gate to fire")
	}
	msg := stderr.String()
	for _, want := range []string{
		"example.com/dep@v1.0.0: copyright not found (status: none_found)",
		"copyright_declarations:",
		"example.com/dep:",
		"declared_by:",
		"basis:",
		"An extracted notice",
	} {
		if !strings.Contains(msg, want) {
			t.Errorf("refusal is missing %q:\n%s", want, msg)
		}
	}
	if stdout.Len() != 0 {
		t.Errorf("no document must be written when review is required, got: %q", stdout.String())
	}
}

// A refusal on any other ground does NOT offer the copyright remedy: recording
// a copyright settles nothing for an ambiguous licence, and pointing an
// operator at it would send them to do work that changes no outcome.
func TestNoticeWith_OtherRefusalOmitsTheCopyrightRemedy(t *testing.T) {
	coord := coordinatetest.MustNew("example.com/ambig", "v1.0.0")
	ctr := &Container{
		QueryWalks: walksWithNodes("W1", coord),
		GenerateNotice: &testfakes.FakeGenerateNotice{Result: licapp.NoticeResult{
			ReviewItems: []licdomain.ReviewItem{{
				Coordinate: coord,
				Reason:     "ambiguous license: primary=MIT (60%), alts=[Apache-2.0 (55%)]",
			}},
		}},
	}
	var stdout, stderr bytes.Buffer
	if err := noticeWith(context.Background(), ctr, "W1", "", "", "", "", &stdout, &stderr); err == nil {
		t.Fatal("expected the review gate to fire")
	}
	if strings.Contains(stderr.String(), "copyright_declarations") {
		t.Errorf("the copyright remedy was offered for a licence-ambiguity refusal:\n%s", stderr.String())
	}
}

// The configured declarations reach the generator. Without this the config key
// would parse, validate and show correctly while changing nothing.
func TestNoticeWith_PassesConfiguredDeclarations(t *testing.T) {
	coord := coordinatetest.MustNew("example.com/dep", "v1.0.0")
	fake := &testfakes.FakeGenerateNotice{}
	ctr := &Container{
		QueryWalks:     walksWithNodes("W1", coord),
		GenerateNotice: fake,
		Config: configdomain.Config{CopyrightDeclarations: map[string]configdomain.CopyrightDeclaration{
			"example.com/dep": {
				Copyright:  "Copyright SYNTHETIC-FIXTURE-HOLDER",
				DeclaredBy: "test-operator@example.invalid",
				DeclaredOn: "2026-08-25",
				Basis:      "synthetic fixture; no upstream source was read",
			},
		}},
	}
	var stdout, stderr bytes.Buffer
	if err := noticeWith(context.Background(), ctr, "W1", "", "", "", "", &stdout, &stderr); err != nil {
		t.Fatalf("noticeWith: %v", err)
	}
	got, ok := fake.LastRequest.Declarations.Resolve(coord)
	if !ok {
		t.Fatal("the configured declaration did not reach the generator")
	}
	if got.Copyright != "Copyright SYNTHETIC-FIXTURE-HOLDER" || got.Basis == "" {
		t.Errorf("declaration reached the generator incomplete: %+v", got)
	}
}

// With no declarations configured the generator receives a set that never
// matches — the control that keeps behaviour identical for every project that
// has recorded nothing.
func TestNoticeWith_NoDeclarationsConfiguredPassesEmptySet(t *testing.T) {
	coord := coordinatetest.MustNew("example.com/dep", "v1.0.0")
	fake := &testfakes.FakeGenerateNotice{}
	ctr := &Container{QueryWalks: walksWithNodes("W1", coord), GenerateNotice: fake}
	var stdout, stderr bytes.Buffer
	if err := noticeWith(context.Background(), ctr, "W1", "", "", "", "", &stdout, &stderr); err != nil {
		t.Fatalf("noticeWith: %v", err)
	}
	if _, ok := fake.LastRequest.Declarations.Resolve(coord); ok {
		t.Error("an unconfigured declaration set matched")
	}
}
