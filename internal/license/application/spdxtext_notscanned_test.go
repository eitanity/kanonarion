package application

import (
	"path"
	"testing"

	licensedomain "github.com/eitanity/kanonarion/internal/license/domain"
)

// The embedded SPDX text table ships verbatim licence texts inside this
// repository. They are attribution *source data*, not a licence grant for
// kanonarion itself, and must never be mistaken for one by kanonarion's own
// licence-file selection — that would report a phantom licence or a phantom
// embedded component for the project.
//
// Two independent guards hold: the filenames are SPDX identifiers, which match
// no licence-file stem, and the table lives well below the module root. This
// test pins both, so renaming a text to something like "LICENSE-BSD-3-Clause.txt"
// fails here rather than silently corrupting a NOTICE.
func TestEmbeddedSPDXTextsAreNotSelectedAsLicenceFiles(t *testing.T) {
	ids := licensedomain.KnownSPDXTextIDs()
	if len(ids) == 0 {
		t.Fatal("embedded SPDX text table is empty; this test would vacuously pass")
	}

	const dir = "internal/license/domain/spdxtexts"
	for _, id := range ids {
		name := "spdx-" + id + ".txt"
		if isLicenceFilename(name) {
			t.Errorf("%q matches a licence-file stem; rename it so licence selection cannot pick it up", name)
		}
		rel := path.Join(dir, name)
		if isRootLevel(rel) {
			t.Errorf("%q is root-level; the table must stay below the module root", rel)
		}
	}
}
