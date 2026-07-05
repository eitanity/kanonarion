package cli

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	fetchdomain "github.com/eitanity/kanonarion/internal/fetch/domain"
	licdomain "github.com/eitanity/kanonarion/internal/license/domain"
)

func makeDiffRecord(path, ver, spdx string, files ...licdomain.LicenseFileEntry) licdomain.LicenseRecord {
	return licdomain.LicenseRecord{
		Coordinate:    fetchdomain.ModuleCoordinate{Path: path, Version: ver},
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
	if !strings.Contains(got, "No license changes") {
		t.Errorf("expected 'No license changes' in output, got: %q", got)
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
