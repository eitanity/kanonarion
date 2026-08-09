package cli

import (
	"encoding/json"
	"strings"
	"testing"

	licdomain "github.com/eitanity/kanonarion/internal/license/domain"
)

// A module with no licence record and a module whose record carries no
// classifiable identifier are two different states with two different operator
// actions: run the extraction, versus make a human determination and record it.
// Reporting them both as "no license detected" sent the operator to a remedy
// that provably cannot help — the extraction has already run and will produce
// the same answer forever.
//
// The real instance is github.com/termie/go-shutil, whose LICENSE file reads
// "I guess Python's? If that doesn't apply then MIT. Have fun." Refusing to
// guess MIT is correct and is not what these tests change.

// unclassifiableRecord models that module: extraction ran, a licence-named file
// was found and read, and no identifier could be determined from it.
func unclassifiableRecord() licdomain.LicenseRecord {
	return withEffectiveSet(licdomain.LicenseRecord{
		OverallStatus: licdomain.LicenseStatusUnclassified,
		LicenseFiles:  []licdomain.LicenseFileEntry{{Path: "LICENSE"}},
	})
}

const extractionHint = "Run 'kanonarion extract"

// The defect: the hint fired for a module whose record exists.
func TestLicenseCompat_UnclassifiableRecordDoesNotSuggestExtraction(t *testing.T) {
	ctr, root := compatFromRecords(t, map[string]licdomain.LicenseRecord{
		"github.com/termie/go-shutil@v0.0.0-20140729215957-bcacb06fecae": unclassifiableRecord(),
	})
	out, err := runCompat(t, ctr, root, "Apache-2.0", false)
	if err == nil {
		t.Fatal("an unclassifiable module is still a review item; want a non-clean result")
	}
	if strings.Contains(out, extractionHint) {
		t.Errorf("extraction has already run for this module and cannot change the answer; the hint must not fire:\n%s", out)
	}
	if !strings.Contains(out, "go-shutil") {
		t.Fatalf("the module must still be reported as an open item:\n%s", out)
	}
	if !strings.Contains(out, "unclassifiable") {
		t.Errorf("the row must say what the state IS — measured, not classifiable:\n%s", out)
	}
}

// The non-zero control: an absent record must STILL produce the hint. A fix
// that simply deleted the hint would pass the test above.
func TestLicenseCompat_AbsentRecordStillSuggestsExtraction(t *testing.T) {
	ctr, root := compatFromClosure(t, nil, []string{"example.com/never-extracted@v1.0.0"})
	out, err := runCompat(t, ctr, root, "Apache-2.0", false)
	if err == nil {
		t.Fatal("a module with no licence record is a review item; want a non-clean result")
	}
	if !strings.Contains(out, extractionHint) {
		t.Errorf("a module extraction never reached must still send the operator to extraction:\n%s", out)
	}
	if !strings.Contains(out, "no licence record") {
		t.Errorf("the row must say the record is absent:\n%s", out)
	}
}

// One of each: the hint fires once, for the unmeasured module only, and the
// module extraction already measured is reported as its own kind of open item.
func TestLicenseCompat_MixedClosureSeparatesTheTwoStates(t *testing.T) {
	ctr, root := compatFromClosure(t,
		map[string]licdomain.LicenseRecord{
			"github.com/termie/go-shutil@v0.0.0-20140729215957-bcacb06fecae": unclassifiableRecord(),
		},
		[]string{"example.com/never-extracted@v1.0.0"},
	)
	out, _ := runCompat(t, ctr, root, "Apache-2.0", false)
	if n := strings.Count(out, extractionHint); n != 1 {
		t.Errorf("the extraction hint must appear exactly once, got %d:\n%s", n, out)
	}
	at := strings.Index(out, extractionHint)
	if at < 0 {
		t.Fatalf("the extraction hint is missing entirely:\n%s", out)
	}
	if strings.Contains(out[at:], "go-shutil") {
		t.Errorf("the hint must not name the module extraction has already measured:\n%s", out[at:])
	}
	if !strings.Contains(out, "unclassifiable") || !strings.Contains(out, "no licence record") {
		t.Errorf("both states must be visible in the text output:\n%s", out)
	}
}

// A machine consumer must be able to tell "not yet measured" from "measured,
// unclassifiable" without parsing prose.
func TestLicenseCompat_JSONDistinguishesUnmeasuredFromUnclassifiable(t *testing.T) {
	ctr, root := compatFromClosure(t,
		map[string]licdomain.LicenseRecord{
			"github.com/termie/go-shutil@v0.0.0-20140729215957-bcacb06fecae": unclassifiableRecord(),
			"example.com/permissive@v1.0.0":                                  simpleLicenceRecord("MIT"),
		},
		[]string{"example.com/never-extracted@v1.0.0"},
	)
	out, _ := runCompat(t, ctr, root, "Apache-2.0", true)

	var doc struct {
		Conflicts []struct {
			Module      string `json:"module"`
			Measurement string `json:"license_measurement"`
		} `json:"conflicts"`
	}
	if err := json.Unmarshal([]byte(firstJSONDocument(out)), &doc); err != nil {
		t.Fatalf("decoding document: %v\n%s", err, out)
	}
	got := map[string]string{}
	for _, c := range doc.Conflicts {
		got[c.Module] = c.Measurement
	}
	want := map[string]string{
		"github.com/termie/go-shutil": "unclassifiable",
		"example.com/never-extracted": "unmeasured",
	}
	for module, state := range want {
		if got[module] != state {
			t.Errorf("license_measurement for %s = %q, want %q\n%s", module, got[module], state, out)
		}
	}
	// A module whose licence WAS classified is neither: MIT is compatible with
	// Apache-2.0, so it raises no entry at all and cannot be mislabelled.
	if _, present := got["example.com/permissive"]; present {
		t.Errorf("a compatible module must raise no conflict entry:\n%s", out)
	}
}
