package domain

import "testing"

func TestLoadTaxonomy_MalformedJSONIsRefused(t *testing.T) {
	if _, err := loadTaxonomy([]byte("{")); err == nil {
		t.Error("malformed taxonomy loaded")
	}
}

// The embedded file is checked at init; a bad one must stop the binary rather
// than classify against an empty taxonomy.
func TestMustLoadTaxonomy_PanicsOnABadFile(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Error("a bad taxonomy did not panic")
		}
	}()
	mustLoadTaxonomy([]byte(`{"version":""}`))
}
