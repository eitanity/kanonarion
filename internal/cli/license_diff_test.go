package cli

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/eitanity/kanonarion/internal/coordinate/coordinatetest"
	licdomain "github.com/eitanity/kanonarion/internal/license/domain"
)

func makeDiffRecord(path, ver, spdx string, files ...licdomain.LicenseFileEntry) licdomain.LicenseRecord {
	return licdomain.LicenseRecord{
		Coordinate:    coordinatetest.MustNew(path, ver),
		PrimarySPDX:   spdx,
		OverallStatus: licdomain.LicenseStatusDetected,
		LicenseFiles:  files,
	}
}

// escalation from permissive to strong copyleft is flagged in text output.
func TestPrintLicenseDiff_Escalation(t *testing.T) {
	a := makeDiffRecord("example.com/app", "v1.0.0", "MIT",
		licdomain.LicenseFileEntry{Path: "LICENSE", SPDX: "MIT",
			CopyrightStatements: []licdomain.CopyrightStatement{{Verbatim: "Copyright 2020 Alice"}}},
	)
	b := makeDiffRecord("example.com/app", "v2.0.0", "GPL-3.0-only",
		licdomain.LicenseFileEntry{Path: "LICENSE", SPDX: "GPL-3.0-only",
			CopyrightStatements: []licdomain.CopyrightStatement{{Verbatim: "Copyright 2023 Bob"}}},
	)
	diff := licdomain.DiffRecords(a, b)

	var buf bytes.Buffer
	if err := printLicenseDiff(diff, &buf); err != nil {
		t.Fatalf("printLicenseDiff: %v", err)
	}
	got := buf.String()

	for _, want := range []string{
		"ESCALATION",
		"MIT",
		"GPL-3.0-only",
		"strong",
		"Copyright 2023 Bob",
		"Copyright 2020 Alice",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("output missing %q\nfull output:\n%s", want, got)
		}
	}
}

// no changes prints a stable "no changes" message.
func TestPrintLicenseDiff_NoChanges(t *testing.T) {
	r := makeDiffRecord("example.com/app", "v1.0.0", "MIT")
	diff := licdomain.DiffRecords(r, r)

	var buf bytes.Buffer
	if err := printLicenseDiff(diff, &buf); err != nil {
		t.Fatalf("printLicenseDiff: %v", err)
	}
	got := buf.String()
	// The no-change line names the population it was measured over: two records
	// that agree and two records with nothing in them to disagree about would
	// otherwise print the same sentence.
	for _, want := range []string{"No license changes", "both sides declare MIT", "license file", "copyright statement"} {
		if !strings.Contains(got, want) {
			t.Errorf("expected %q in the no-change output, got: %q", want, got)
		}
	}
	if strings.Contains(got, "ESCALATION") {
		t.Errorf("unexpected ESCALATION in no-change output")
	}
}

// toLicenseDiffJSON projects the diff to the expected JSON shape.
func TestToLicenseDiffJSON_Shape(t *testing.T) {
	a := makeDiffRecord("example.com/app", "v1.0.0", "MIT",
		licdomain.LicenseFileEntry{Path: "LICENSE", SPDX: "MIT",
			CopyrightStatements: []licdomain.CopyrightStatement{{Verbatim: "Copyright 2020 Alice"}}},
	)
	b := makeDiffRecord("example.com/app", "v2.0.0", "GPL-3.0-only",
		licdomain.LicenseFileEntry{Path: "LICENSE", SPDX: "GPL-3.0-only",
			CopyrightStatements: []licdomain.CopyrightStatement{{Verbatim: "Copyright 2023 Bob"}}},
	)
	diff := licdomain.DiffRecords(a, b)

	out := toLicenseDiffJSON(diff)

	if out.ModuleA != "example.com/app@v1.0.0" {
		t.Errorf("module_a = %q, want example.com/app@v1.0.0", out.ModuleA)
	}
	if out.ModuleB != "example.com/app@v2.0.0" {
		t.Errorf("module_b = %q, want example.com/app@v2.0.0", out.ModuleB)
	}
	if out.SPDXChanged == nil || out.SPDXChanged.From != "MIT" || out.SPDXChanged.To != "GPL-3.0-only" {
		t.Errorf("spdx_changed = %+v, want {MIT → GPL-3.0-only}", out.SPDXChanged)
	}
	if out.Escalation == nil || out.Escalation.To != "strong" {
		t.Errorf("escalation.to = %v, want strong", out.Escalation)
	}

	raw, err := json.Marshal(out)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	s := string(raw)
	for _, key := range []string{
		`"module_a"`, `"module_b"`, `"from"`, `"to"`, `"escalation"`,
		`"files_added"`, `"files_removed"`, `"copyright_added"`, `"copyright_removed"`,
	} {
		if !strings.Contains(s, key) {
			t.Errorf("JSON missing key %s\nfull payload: %s", key, s)
		}
	}
}

// empty diff emits empty arrays (not nil) so JSON consumers can always range over slices.
func TestToLicenseDiffJSON_EmptyArrays(t *testing.T) {
	r := makeDiffRecord("example.com/app", "v1.0.0", "MIT")
	diff := licdomain.DiffRecords(r, r)

	out := toLicenseDiffJSON(diff)
	raw, err := json.Marshal(out)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	s := string(raw)
	for _, want := range []string{`"files_added":[]`, `"files_removed":[]`, `"copyright_added":[]`, `"copyright_removed":[]`} {
		if !strings.Contains(s, want) {
			t.Errorf("empty diff JSON missing %q\nfull payload: %s", want, s)
		}
	}
}

// TestToLicenseDiffJSON_DistinguishesUnchangedFromAbsent is the discriminating
// case.
//
// Two records that both declare Apache-2.0 and two records that are both
// unlicensed produce the same four empty delta lists, so a document carrying
// only deltas could not tell an unchanged licence from an absent one — and a
// consumer reading the machine form of "no license changes" was told nothing
// about what either side declares. A relicensing alone would not have shown it:
// that case already differed, in spdx_changed.
func TestToLicenseDiffJSON_DistinguishesUnchangedFromAbsent(t *testing.T) {
	licensed := makeDiffRecord("example.com/app", "v1.0.0", "Apache-2.0",
		licdomain.LicenseFileEntry{Path: "LICENSE", SPDX: "Apache-2.0",
			CopyrightStatements: []licdomain.CopyrightStatement{{Verbatim: "Copyright 2020 Alice"}}},
	)
	unlicensed := licdomain.LicenseRecord{
		Coordinate:    coordinatetest.MustNew("example.com/app", "v1.0.0"),
		OverallStatus: licdomain.LicenseStatusNone,
	}
	relicensed := makeDiffRecord("example.com/app", "v2.0.0", "GPL-3.0-only",
		licdomain.LicenseFileEntry{Path: "LICENSE", SPDX: "GPL-3.0-only",
			CopyrightStatements: []licdomain.CopyrightStatement{{Verbatim: "Copyright 2023 Bob"}}},
	)

	render := func(a, b licdomain.LicenseRecord) string {
		raw, err := json.Marshal(toLicenseDiffJSON(licdomain.DiffRecords(a, b)))
		if err != nil {
			t.Fatalf("Marshal: %v", err)
		}
		return string(raw)
	}
	docs := map[string]string{
		"both Apache-2.0": render(licensed, licensed),
		"both unlicensed": render(unlicensed, unlicensed),
		"a relicensing":   render(licensed, relicensed),
	}
	for name, doc := range docs {
		for other, otherDoc := range docs {
			if name < other && doc == otherDoc {
				t.Errorf("%q and %q are the same document:\n%s", name, other, doc)
			}
		}
	}

	// And the facts themselves, so the documents differ for the stated reason
	// rather than incidentally.
	var apache, absent licenseDiffJSON
	if err := json.Unmarshal([]byte(docs["both Apache-2.0"]), &apache); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal([]byte(docs["both unlicensed"]), &absent); err != nil {
		t.Fatal(err)
	}
	if apache.DeclaredA.PrimarySPDX != "Apache-2.0" || apache.DeclaredB.PrimarySPDX != "Apache-2.0" {
		t.Errorf("declared SPDX = %q/%q, want Apache-2.0 on both sides",
			apache.DeclaredA.PrimarySPDX, apache.DeclaredB.PrimarySPDX)
	}
	if apache.DeclaredA.OverallStatus != licdomain.LicenseStatusDetected.String() {
		t.Errorf("declared status = %q, want %q", apache.DeclaredA.OverallStatus,
			licdomain.LicenseStatusDetected.String())
	}
	// The two counts the text's no-change line names.
	if apache.DeclaredA.LicenseFiles != 1 || apache.DeclaredA.CopyrightStatements != 1 {
		t.Errorf("declared populations = %d file(s), %d statement(s), want 1 and 1",
			apache.DeclaredA.LicenseFiles, apache.DeclaredA.CopyrightStatements)
	}
	if absent.DeclaredA.PrimarySPDX != "" || absent.DeclaredA.OverallStatus != licdomain.LicenseStatusNone.String() {
		t.Errorf("an unlicensed side declares %q at status %q, want the empty expression at %q",
			absent.DeclaredA.PrimarySPDX, absent.DeclaredA.OverallStatus, licdomain.LicenseStatusNone.String())
	}
	if absent.DeclaredA.LicenseFiles != 0 || absent.DeclaredA.CopyrightStatements != 0 {
		t.Errorf("an unlicensed side reports %d file(s) and %d statement(s), want none of either",
			absent.DeclaredA.LicenseFiles, absent.DeclaredA.CopyrightStatements)
	}
}
