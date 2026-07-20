package licensecheck_test

import (
	"context"
	"strings"
	"testing"

	detector "github.com/eitanity/kanonarion/internal/license/adapters/detector/licensecheck"
	licensedomain "github.com/eitanity/kanonarion/internal/license/domain"
)

// The embedded SPDX text table is the verbatim licence text kanonarion
// publishes when attributing third-party code copied into first-party source.
// A wrong or truncated text there is a compliance defect that no other test
// would catch, because nothing else reads these files for meaning.
//
// This test is the oracle: it runs each stored text back through the same
// detector the licence pipeline uses for module LICENSE files and requires it
// to classify as the identifier it is filed under. A text that no longer
// identifies as its own filename fails here.
//
// It lives in the detector package rather than in domain so the check runs
// against the real detector, not a fake.
func TestEmbeddedSPDXTextsClassifyAsTheirOwnIdentifier(t *testing.T) {
	ids := licensedomain.KnownSPDXTextIDs()
	if len(ids) == 0 {
		t.Fatal("embedded SPDX text table is empty; this test would vacuously pass")
	}

	d := detector.New()
	for _, id := range ids {
		t.Run(id, func(t *testing.T) {
			text, err := licensedomain.SPDXLicenseText(id)
			if err != nil {
				t.Fatalf("SPDXLicenseText(%q): %v", id, err)
			}

			match, derr := d.Detect(context.Background(), []byte(text))
			if derr != nil {
				t.Fatalf("detecting %q: %v", id, derr)
			}
			if match.SPDX != id {
				t.Errorf("stored text for %q classifies as %q — the file is wrong, truncated, or misnamed", id, match.SPDX)
			}
			if match.Confidence < 0.99 {
				t.Errorf("stored text for %q matched at only %.2f coverage; it is likely truncated", id, match.Confidence)
			}
			if len(match.AltMatches) != 0 {
				t.Errorf("stored text for %q is ambiguous (alts: %+v); it should be exactly one licence", id, match.AltMatches)
			}
		})
	}
}

// The BSD family templates the entity named in the no-endorsement clause. The
// table attributes arbitrary third-party snippets, so a body naming a specific
// organisation would be the wrong grant for anyone else's code — the text must
// keep the generic placeholder wording.
func TestEmbeddedBSDTextsAreNotOrganisationSpecific(t *testing.T) {
	for _, id := range []string{"BSD-3-Clause"} {
		text, err := licensedomain.SPDXLicenseText(id)
		if err != nil {
			t.Fatalf("SPDXLicenseText(%q): %v", id, err)
		}
		if !strings.Contains(text, "Neither the name of the copyright holder") {
			t.Errorf("%s must use the generic 'name of the copyright holder' wording, not a specific organisation", id)
		}
	}
}
