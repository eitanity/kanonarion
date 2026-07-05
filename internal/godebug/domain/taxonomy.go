package domain

import (
	_ "embed"
	"encoding/json"
	"fmt"
)

// taxonomyJSON is the versioned risk taxonomy, embedded at compile time so
// the classifier carries its knowledge without runtime I/O. It is a *data
// file* (taxonomy.json), not hardcoded Go: adding a setting as the Go team
// ships one is a one-line edit plus a TaxonomyVersion bump, never a change to
// classification code (requirement).
//
//go:embed taxonomy.json
var taxonomyJSON []byte

// taxonomyFile is the on-disk shape of taxonomy.json.
type taxonomyFile struct {
	Version  string            `json:"version"`
	Comment  string            `json:"comment"`
	Settings map[string]string `json:"settings"`
}

// taxonomy is the parsed, validated taxonomy. It is built once at package
// init from the embedded bytes; a malformed embedded file is a build-time
// asset error surfaced as an init panic (it can only happen if the committed
// data file is broken, which a test guards against).
var taxonomy = mustLoadTaxonomy()

// TaxonomyVersion is the revision string of the embedded taxonomy. It is
// recorded on every Record and folded into the pipeline fingerprint so a
// taxonomy update alone forces re-classification.
func TaxonomyVersion() string { return taxonomy.version }

type loadedTaxonomy struct {
	version string
	tiers   map[string]Tier
}

func mustLoadTaxonomy() loadedTaxonomy {
	lt, err := loadTaxonomy(taxonomyJSON)
	if err != nil {
		panic(fmt.Sprintf("godebug: embedded taxonomy.json is invalid: %v", err))
	}
	return lt
}

// loadTaxonomy parses and validates taxonomy bytes. Exposed unexported for a
// table test that asserts the committed data file stays well-formed.
func loadTaxonomy(raw []byte) (loadedTaxonomy, error) {
	var tf taxonomyFile
	if err := json.Unmarshal(raw, &tf); err != nil {
		return loadedTaxonomy{}, fmt.Errorf("decoding taxonomy: %w", err)
	}
	if tf.Version == "" {
		return loadedTaxonomy{}, fmt.Errorf("taxonomy version is empty")
	}
	tiers := make(map[string]Tier, len(tf.Settings))
	for name, tier := range tf.Settings {
		t, ok := tierFromToken(tier)
		if !ok {
			return loadedTaxonomy{}, fmt.Errorf("setting %q: invalid tier %q (want red, amber, or green)", name, tier)
		}
		tiers[name] = t
	}
	return loadedTaxonomy{version: tf.Version, tiers: tiers}, nil
}

// tierFromToken maps a taxonomy token onto a Tier. Note "unknown" is *not* a
// valid data-file token: a setting absent from the file is unknown, but the
// file may never assert unknown explicitly.
func tierFromToken(s string) (Tier, bool) {
	switch s {
	case "red":
		return TierRed, true
	case "amber":
		return TierAmber, true
	case "green":
		return TierGreen, true
	default:
		return TierUnknown, false
	}
}
