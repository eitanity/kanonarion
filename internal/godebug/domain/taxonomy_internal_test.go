package domain

import "testing"

// TestEmbeddedTaxonomyWellFormed guards the committed data file: a malformed
// taxonomy.json would otherwise only blow up as an init panic at runtime.
// This keeps the "taxonomy is a maintainable data file" contract honest.
func TestEmbeddedTaxonomyWellFormed(t *testing.T) {
	lt, err := loadTaxonomy(taxonomyJSON)
	if err != nil {
		t.Fatalf("embedded taxonomy.json invalid: %v", err)
	}
	if lt.version == "" {
		t.Fatal("taxonomy version empty")
	}
	if len(lt.tiers) == 0 {
		t.Fatal("taxonomy has no settings")
	}
	// Spot-check a representative of each tier survives the round trip.
	for name, want := range map[string]Tier{
		"tlsrsakex":      TierRed,
		"http2client":    TierAmber,
		"asynctimerchan": TierGreen,
	} {
		if lt.tiers[name] != want {
			t.Errorf("taxonomy[%q] = %v, want %v", name, lt.tiers[name], want)
		}
	}
}

// TestLoadTaxonomyRejectsBadTier ensures the loader fails closed on an
// unrecognised tier token rather than silently dropping the setting.
func TestLoadTaxonomyRejectsBadTier(t *testing.T) {
	_, err := loadTaxonomy([]byte(`{"version":"x","settings":{"foo":"purple"}}`))
	if err == nil {
		t.Fatal("expected error for invalid tier token")
	}
}

// TestLoadTaxonomyRejectsEmptyVersion ensures a versionless file is rejected
// — the version is the cache-invalidation key, it may not be blank.
func TestLoadTaxonomyRejectsEmptyVersion(t *testing.T) {
	if _, err := loadTaxonomy([]byte(`{"settings":{}}`)); err == nil {
		t.Fatal("expected error for empty version")
	}
}
