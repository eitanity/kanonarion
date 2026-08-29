package domain_test

import (
	"testing"

	"github.com/eitanity/kanonarion/internal/coordinate/coordinatetest"
	"github.com/eitanity/kanonarion/internal/license/domain"
)

// synthDeclaration is an obviously invented declaration. A fixture that reads
// like a genuine upstream attribution is one copy-paste away from a published
// document.
func synthDeclaration(line string) domain.CopyrightDeclaration {
	return domain.CopyrightDeclaration{
		Copyright:  line,
		DeclaredBy: "test-operator@example.invalid",
		DeclaredOn: "2026-08-25",
		Basis:      "synthetic fixture; no upstream source was read",
	}
}

// TestCopyrightDeclarationSet_VersionPinnedWins mirrors the licence-override
// precedence rule: a "path@version" entry beats a module-level one, and the key
// that matched is stamped on the answer so a caller can say which entry applied.
func TestCopyrightDeclarationSet_VersionPinnedWins(t *testing.T) {
	set := domain.NewCopyrightDeclarationSet(map[string]domain.CopyrightDeclaration{
		"example.com/mod":        synthDeclaration("Copyright MODULE-LEVEL"),
		"example.com/mod@v1.2.3": synthDeclaration("Copyright VERSION-PINNED"),
	})

	got, ok := set.Resolve(coordinatetest.MustNew("example.com/mod", "v1.2.3"))
	if !ok {
		t.Fatal("Resolve found nothing for the pinned version")
	}
	if got.Copyright != "Copyright VERSION-PINNED" {
		t.Errorf("Copyright = %q, want the version-pinned entry", got.Copyright)
	}
	if !got.VersionPinned || got.Key != "example.com/mod@v1.2.3" {
		t.Errorf("key/pinned not stamped: key=%q pinned=%v", got.Key, got.VersionPinned)
	}

	got, ok = set.Resolve(coordinatetest.MustNew("example.com/mod", "v9.9.9"))
	if !ok {
		t.Fatal("Resolve found nothing for the unpinned version")
	}
	if got.Copyright != "Copyright MODULE-LEVEL" || got.VersionPinned {
		t.Errorf("unpinned version resolved to %+v, want the module-level entry", got)
	}
}

// TestCopyrightDeclarationSet_NoMatch: an unrelated coordinate, a blank
// copyright line and the zero-value set all resolve to nothing. A
// present-but-blank entry must not clear the notice gate: it reads as an
// attribution in the document and says nothing.
func TestCopyrightDeclarationSet_NoMatch(t *testing.T) {
	set := domain.NewCopyrightDeclarationSet(map[string]domain.CopyrightDeclaration{
		"example.com/mod":   synthDeclaration("Copyright SYNTHETIC-FIXTURE-HOLDER"),
		"example.com/blank": {DeclaredBy: "a@example.invalid", DeclaredOn: "2026-08-25", Basis: "nothing"},
	})

	if _, ok := set.Resolve(coordinatetest.MustNew("example.com/other", "v1.0.0")); ok {
		t.Error("an unrelated coordinate matched")
	}
	if _, ok := set.Resolve(coordinatetest.MustNew("example.com/blank", "v1.0.0")); ok {
		t.Error("a blank copyright line resolved as a declaration")
	}
	if _, ok := (domain.CopyrightDeclarationSet{}).Resolve(coordinatetest.MustNew("example.com/mod", "v1.0.0")); ok {
		t.Error("the zero-value set matched")
	}
	if _, ok := domain.NewCopyrightDeclarationSet(nil).Resolve(coordinatetest.MustNew("example.com/mod", "v1.0.0")); ok {
		t.Error("a set built from nil matched")
	}
}

// TestCopyrightDeclarationSet_CopiesItsInput: the set is immutable, so mutating
// the caller's map afterwards must not change what it resolves.
func TestCopyrightDeclarationSet_CopiesItsInput(t *testing.T) {
	entries := map[string]domain.CopyrightDeclaration{
		"example.com/mod": synthDeclaration("Copyright ORIGINAL"),
	}
	set := domain.NewCopyrightDeclarationSet(entries)
	entries["example.com/mod"] = synthDeclaration("Copyright MUTATED-AFTERWARDS")

	got, ok := set.Resolve(coordinatetest.MustNew("example.com/mod", "v1.0.0"))
	if !ok {
		t.Fatal("Resolve found nothing")
	}
	if got.Copyright != "Copyright ORIGINAL" {
		t.Errorf("Copyright = %q; the set did not copy its input", got.Copyright)
	}
}

// TestNoticeEntry_DeclarationAttributes: the rule that decides whether a
// declaration is the attribution or corroboration is on the extracted lines
// that reached the entry, never on the record's status.
func TestNoticeEntry_DeclarationAttributes(t *testing.T) {
	decl := synthDeclaration("Copyright SYNTHETIC-FIXTURE-HOLDER")
	cases := []struct {
		name       string
		entry      domain.NoticeEntry
		attributes bool
	}{
		{"no declaration", domain.NoticeEntry{}, false},
		{"declaration, nothing extracted", domain.NoticeEntry{Declaration: &decl}, true},
		{
			"declaration beside an extracted notice",
			domain.NoticeEntry{Declaration: &decl, Copyrights: []string{"Copyright 2020 EXTRACTED"}},
			false,
		},
		{
			"extracted notice, no declaration",
			domain.NoticeEntry{Copyrights: []string{"Copyright 2020 EXTRACTED"}},
			false,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := c.entry.DeclarationAttributes(); got != c.attributes {
				t.Errorf("DeclarationAttributes() = %v, want %v", got, c.attributes)
			}
		})
	}
}
