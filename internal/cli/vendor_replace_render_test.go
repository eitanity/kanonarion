package cli

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	vendomain "github.com/eitanity/kanonarion/internal/vendortree/domain"
)

// replacedRecord is a clean reconciliation of a project holding one ordinary
// module and one replaced by a fork whose checksum go.sum carries.
func replacedRecord() vendomain.Record {
	return vendomain.Record{
		Ecosystem:         vendomain.EcosystemGo,
		ProjectModulePath: "example.com/proj",
		VendorDir:         "vendor",
		OverallStatus:     "clean",
		SchemaVersion:     vendomain.VendorSchemaVersion,
		PipelineVersion:   vendomain.PipelineVersion,
		Modules: []vendomain.VendoredModule{
			{
				Path: "example.com/plain", Version: "v1.0.0", Present: true,
				PackageCount: 1, ExpectedHash: "h1:plain=", FilesCompared: 8,
			},
			{
				Path: "example.com/dep", Version: "v1.2.0", Present: true,
				PackageCount: 1, ExpectedHash: "h1:fork=", FilesCompared: 12,
				ReplacementPath: "example.com/fork", ReplacementVersion: "v1.4.0",
			},
		},
	}
}

// TestVendorRender_StatesBothCoordinatesForAReplacedModule. `go mod vendor`
// writes a fork's source under the original module's directory, so a report
// naming only the directory tells the reader that upstream was verified. It was
// not; a fork was. The row and the text both have to say so.
func TestVendorRender_StatesBothCoordinatesForAReplacedModule(t *testing.T) {
	section := toVendorSection(replacedRecord())

	var buf bytes.Buffer
	if err := printVendorTable(&buf, section); err != nil {
		t.Fatalf("printVendorTable: %v", err)
	}
	out := buf.String()
	for _, want := range []string{"example.com/dep v1.2.0", "example.com/fork v1.4.0", "checked against the replacement"} {
		if !strings.Contains(out, want) {
			t.Errorf("the report does not state %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "example.com/plain v1.0.0 =>") {
		t.Errorf("an unreplaced module is listed as replaced:\n%s", out)
	}

	encoded, err := json.Marshal(section)
	if err != nil {
		t.Fatalf("marshalling section: %v", err)
	}
	var got struct {
		FilesCompared int `json:"files_compared"`
		Modules       []struct {
			Path               string `json:"path"`
			ReplacementPath    string `json:"replacement_path"`
			ReplacementVersion string `json:"replacement_version"`
			FilesCompared      int    `json:"files_compared"`
		} `json:"modules"`
	}
	if err := json.Unmarshal(encoded, &got); err != nil {
		t.Fatalf("decoding section: %v", err)
	}
	if got.FilesCompared != 20 {
		t.Errorf("total files compared = %d, want 20 — the total is the size of the measurement the status rests on", got.FilesCompared)
	}
	for _, m := range got.Modules {
		if m.Path != "example.com/dep" {
			continue
		}
		if m.ReplacementPath != "example.com/fork" || m.ReplacementVersion != "v1.4.0" {
			t.Errorf("row carries replacement (%q, %q), want the fork's coordinate", m.ReplacementPath, m.ReplacementVersion)
		}
		if m.FilesCompared != 12 {
			t.Errorf("row's files compared = %d, want 12", m.FilesCompared)
		}
	}
}

// TestVendorRender_FilesystemReplaceSaysNothingCanCheckIt is the honest-gap arm.
// A filesystem replacement publishes no module, so the report must say that no
// checksum can exist rather than implying one was looked for and missed.
func TestVendorRender_FilesystemReplaceSaysNothingCanCheckIt(t *testing.T) {
	rec := replacedRecord()
	rec.Modules[1].ReplacementPath = "../fork"
	rec.Modules[1].ReplacementVersion = ""
	rec.Modules[1].ExpectedHash = ""
	rec.Modules[1].FilesCompared = 0

	var buf bytes.Buffer
	if err := printVendorTable(&buf, toVendorSection(rec)); err != nil {
		t.Fatalf("printVendorTable: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, "../fork") || !strings.Contains(out, "no go.sum checksum exists") {
		t.Errorf("the report must name the filesystem replacement and say no checksum can exist for it:\n%s", out)
	}
	if strings.Contains(out, "checked against the replacement") {
		t.Errorf("a filesystem replacement is reported as checked:\n%s", out)
	}
}

// TestVendorRender_MeasurementSizeIsAlwaysStated. A clean status over nothing
// compared is the case the line exists to expose, so the count is printed at
// zero rather than suppressed.
func TestVendorRender_MeasurementSizeIsAlwaysStated(t *testing.T) {
	rec := replacedRecord()
	for i := range rec.Modules {
		rec.Modules[i].FilesCompared = 0
	}

	var buf bytes.Buffer
	if err := printVendorTable(&buf, toVendorSection(rec)); err != nil {
		t.Fatalf("printVendorTable: %v", err)
	}
	if !strings.Contains(buf.String(), "compared: 0 file(s) across 0 of 2 module(s)") {
		t.Errorf("a run that compared nothing must say so:\n%s", buf.String())
	}
}
