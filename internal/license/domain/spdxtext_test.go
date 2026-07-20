package domain

import (
	"errors"
	"strings"
	"testing"
)

// The embedded table is a build asset: an empty one would silently turn every
// copied-source attribution into an unknown-identifier failure.
func TestSPDXLicenseText_TableIsPopulated(t *testing.T) {
	ids := KnownSPDXTextIDs()
	if len(ids) == 0 {
		t.Fatal("embedded SPDX licence text table is empty")
	}
	for _, id := range ids {
		text, err := SPDXLicenseText(id)
		if err != nil {
			t.Errorf("SPDXLicenseText(%q) errored: %v", id, err)
			continue
		}
		if strings.TrimSpace(text) == "" {
			t.Errorf("SPDXLicenseText(%q) returned empty text", id)
		}
	}
}

func TestSPDXLicenseText_BSD3Clause(t *testing.T) {
	text, err := SPDXLicenseText("BSD-3-Clause")
	if err != nil {
		t.Fatalf("BSD-3-Clause must be covered: %v", err)
	}
	for _, want := range []string{
		"Redistribution and use in source and binary forms",
		"Neither the name of the copyright holder",
		"THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS",
	} {
		if !strings.Contains(text, want) {
			t.Errorf("BSD-3-Clause text missing %q", want)
		}
	}
}

func TestSPDXLicenseText_UnknownID(t *testing.T) {
	_, err := SPDXLicenseText("NotALicence-9.9")
	if !errors.Is(err, ErrUnknownSPDXText) {
		t.Fatalf("want ErrUnknownSPDXText, got: %v", err)
	}
}

// SPDX identifiers are case-sensitive; a near-miss must not resolve to a
// neighbouring licence.
func TestSPDXLicenseText_LookupIsCaseSensitive(t *testing.T) {
	if _, err := SPDXLicenseText("bsd-3-clause"); !errors.Is(err, ErrUnknownSPDXText) {
		t.Fatalf("lowercase identifier should not resolve, got: %v", err)
	}
}
