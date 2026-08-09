package cli

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/eitanity/kanonarion/internal/coordinate"

	licdomain "github.com/eitanity/kanonarion/internal/license/domain"
)

// The pre-modules caveat is evidence, not decoration: it says the named
// modules' own dependencies are ABSENT from the closure the verdict covers,
// rather than measured to be none, which narrows the licence claim. A machine
// consumer needs it more than a human does — so it belongs IN the document, and
// appending it to stdout after the closing brace both breaks every parser and
// loses the fact for every consumer that recovers by reading stdout as JSON.

// compatWithPreModulesClosure builds a closure holding two pre-modules modules
// (both licensed permissively, so neither is a conflict on its own account),
// one module that raises a genuine review item, and one unmodelled identifier,
// so the document carries conflicts, coverage holes and the caveat at once.
func compatWithPreModulesClosure(t *testing.T) (*Container, coordinate.ModuleCoordinate, string) {
	t.Helper()
	ctr, root := compatFromRecords(t, map[string]licdomain.LicenseRecord{
		"github.com/docker/docker@v28.5.2+incompatible": simpleLicenceRecord("Apache-2.0"),
		"github.com/willf/bloom@v2.0.3+incompatible":    simpleLicenceRecord("BSD-2-Clause"),
		"example.com/unmodelled@v1.0.0":                 simpleLicenceRecord("CC-BY-SA-4.0"),
	})
	return ctr, root, "Apache-2.0"
}

// simpleLicenceRecord is a module whose own root licence is a single
// identifier, the ordinary case.
func simpleLicenceRecord(spdx string) licdomain.LicenseRecord {
	return withEffectiveSet(licdomain.LicenseRecord{
		PrimarySPDX:   spdx,
		Expression:    spdx,
		OverallStatus: licdomain.LicenseStatusDetected,
		LicenseFiles:  []licdomain.LicenseFileEntry{{Path: "LICENSE", SPDX: spdx, Confidence: 1}},
	})
}

// Before the fix stdout was the JSON object followed by the caveat as prose, so
// json.Decode saw trailing data and every consumer failed.
func TestLicenseCompat_JSONStdoutIsOneDocument_WithPreModulesCaveat(t *testing.T) {
	ctr, root, target := compatWithPreModulesClosure(t)
	out, err := runCompat(t, ctr, root, target, true)
	if err == nil {
		t.Fatal("an unmodelled identifier is still a review item; want a non-clean result")
	}
	doc := assertSingleJSONDocument(t, "license-compat --json", []byte(out))
	if _, ok := doc["coverage_holes"]; !ok {
		t.Error("the closure must also carry coverage holes, so the caveat is pinned alongside them")
	}
}

// The caveat must reach the document as a field carrying the coordinates, so a
// consumer can act on the narrowed scope rather than re-deriving it.
func TestLicenseCompat_JSONCarriesPreModulesCaveatField(t *testing.T) {
	ctr, root, target := compatWithPreModulesClosure(t)
	out, _ := runCompat(t, ctr, root, target, true)

	var doc struct {
		PreModulesCaveat *struct {
			Coordinates []string `json:"coordinates"`
			Limitation  string   `json:"limitation"`
			Remedy      string   `json:"remedy"`
		} `json:"pre_modules_caveat"`
	}
	if err := json.Unmarshal([]byte(firstJSONDocument(out)), &doc); err != nil {
		t.Fatalf("decoding document: %v\n%s", err, out)
	}
	if doc.PreModulesCaveat == nil {
		t.Fatal("pre_modules_caveat missing: a closure bounded by pre-modules modules must say so in the document")
	}
	want := []string{
		"github.com/docker/docker@v28.5.2+incompatible",
		"github.com/willf/bloom@v2.0.3+incompatible",
	}
	if strings.Join(doc.PreModulesCaveat.Coordinates, ",") != strings.Join(want, ",") {
		t.Errorf("coordinates = %v, want %v", doc.PreModulesCaveat.Coordinates, want)
	}
	if doc.PreModulesCaveat.Limitation == "" || doc.PreModulesCaveat.Remedy == "" {
		t.Error("the caveat must carry the limitation and the remedy, not only the coordinates")
	}
}

// Absence is pinned too: a closure with no pre-modules module marshals exactly
// as it did before, so the field's presence is a signal.
func TestLicenseCompat_JSONOmitsCaveatWithoutPreModules(t *testing.T) {
	ctr, root := compatFromRecords(t, map[string]licdomain.LicenseRecord{
		"example.com/unmodelled@v1.0.0": simpleLicenceRecord("CC-BY-SA-4.0"),
	})
	out, _ := runCompat(t, ctr, root, "Apache-2.0", true)
	doc := assertSingleJSONDocument(t, "license-compat --json", []byte(out))
	if _, present := doc["pre_modules_caveat"]; present {
		t.Errorf("pre_modules_caveat must be absent when no module in the closure is one:\n%s", out)
	}
}

// The caveat is not being MOVED to the document — it is being rendered properly
// in both. A reader of the text output must still see it, naming the modules.
func TestLicenseCompat_TextKeepsPreModulesCaveat(t *testing.T) {
	ctr, root, target := compatWithPreModulesClosure(t)
	out, _ := runCompat(t, ctr, root, target, false)
	if !strings.Contains(out, "caveat:") {
		t.Fatalf("text output lost the pre-modules caveat:\n%s", out)
	}
	for _, coord := range []string{
		"github.com/docker/docker@v28.5.2+incompatible",
		"github.com/willf/bloom@v2.0.3+incompatible",
	} {
		if !strings.Contains(out, coord) {
			t.Errorf("text caveat does not name %s:\n%s", coord, out)
		}
	}
}

// firstJSONDocument returns the leading JSON document of out, so a test that is
// about the document's CONTENT still reads it while the trailing-bytes defect
// exists. The trailing bytes are a separate assertion, made above.
func firstJSONDocument(out string) string {
	dec := json.NewDecoder(strings.NewReader(out))
	var doc json.RawMessage
	if err := dec.Decode(&doc); err != nil {
		return out
	}
	return string(doc)
}
