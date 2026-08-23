package domain_test

import (
	"strings"
	"testing"

	"github.com/eitanity/kanonarion/internal/callgraph/domain"
	"github.com/eitanity/kanonarion/internal/coordinate"
	"github.com/eitanity/kanonarion/internal/coordinate/coordinatetest"
)

// checksumDetail is the go command's own sentence, as the analyser records it.
const checksumDetail = "the loader reported: a.go:3:8: missing go.sum entry for module providing " +
	"package golang.org/x/mod/semver (imported by example.com/inc); to add: go get example.com/inc"

// TestIncompleteGraphRemedy_ChecksumGapIsNotACompileError guards the remedy a
// reader is handed. A checksum the tree does not carry files under the same
// cause as a package that does not compile, and the remedy for that one sends
// them to edit source that is fine.
func TestIncompleteGraphRemedy_ChecksumGapIsNotACompileError(t *testing.T) {
	coord := coordinatetest.MustNew("example.com/inc", coordinate.LocalVersion)

	got := domain.IncompleteGraphRemedy(coord, domain.FailureCauseModule, checksumDetail, "/work/tree")

	if strings.Contains(got, "Fix the package so it compiles") {
		t.Errorf("a missing checksum entry was reported as a compile error:\n%s", got)
	}
	if !strings.Contains(got, "go.sum") {
		t.Errorf("the remedy does not name the checksum gap:\n%s", got)
	}
	if !strings.Contains(got, domain.MissingChecksumRemedy) {
		t.Errorf("the remedy names nothing that closes the gap:\n%s", got)
	}
	if !strings.Contains(got, "kanonarion local /work/tree") {
		t.Errorf("the remedy does not name the run in the tree it was pointed at:\n%s", got)
	}
}

// TestIsMissingChecksumEntry_NeedsBothHalves keeps a module that merely quotes
// the phrase — in a diagnostic of its own, or in a test fixture — from being
// reported as a checksum gap it does not have.
func TestIsMissingChecksumEntry_NeedsBothHalves(t *testing.T) {
	if !domain.IsMissingChecksumEntry(checksumDetail) {
		t.Error("the go command's own sentence was not recognised")
	}
	for _, near := range []string{
		`panic: missing go.sum entry`,
		`x.go:1:1: undefined: somethingElse; to add more, see docs`,
		"",
	} {
		if domain.IsMissingChecksumEntry(near) {
			t.Errorf("a detail that is not the go command's sentence matched: %q", near)
		}
	}
}
