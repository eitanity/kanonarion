package domain

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"strings"
)

// catalogueJSON is the versioned FIPS knowledge file embedded at compile
// time. Mirroring godebug's taxonomy.json, this is a *data file*
// so adding a recognised toolchain variant or a non-FIPS algorithm package
// is a one-line edit plus a CatalogueVersion bump — never a code change.
//
//go:embed catalogue.json
var catalogueJSON []byte

type catalogueFile struct {
	Version    string `json:"version"`
	Comment    string `json:"comment"`
	Toolchains []struct {
		Name          string `json:"name"`
		MatchContains string `json:"match_contains"`
	} `json:"toolchains"`
	NonFIPSAlgorithmPackages []string `json:"non_fips_algorithm_packages"`
}

// catalogue is the parsed, validated catalogue. Built once at package init;
// a malformed embedded file is a build-time asset error surfaced as an init
// panic (a test guards against that).
var catalogue = mustLoadCatalogue()

// CatalogueVersion is the revision string of the embedded catalogue.
// Recorded on every Record and folded into the pipeline fingerprint so a
// catalogue update alone forces re-classification.
func CatalogueVersion() string { return catalogue.version }

// NonFIPSAlgorithmPackages returns the closed set of import paths whose
// presence in the closure classifies as a non-FIPS algorithm deviation.
// Exposed for tests and adapters; the slice is shared — do not mutate.
func NonFIPSAlgorithmPackages() []string { return catalogue.nonFIPSAlgos }

type loadedCatalogue struct {
	version      string
	toolchains   []toolchainEntry
	nonFIPSAlgos []string
	nonFIPSSet   map[string]struct{}
}

type toolchainEntry struct {
	name     string
	contains string
}

func mustLoadCatalogue() loadedCatalogue {
	lc, err := loadCatalogue(catalogueJSON)
	if err != nil {
		panic(fmt.Sprintf("fips: embedded catalogue.json is invalid: %v", err))
	}
	return lc
}

// loadCatalogue parses and validates catalogue bytes. Exposed unexported
// for a table test that asserts the committed data file stays well-formed.
func loadCatalogue(raw []byte) (loadedCatalogue, error) {
	var cf catalogueFile
	if err := json.Unmarshal(raw, &cf); err != nil {
		return loadedCatalogue{}, fmt.Errorf("decoding catalogue: %w", err)
	}
	if cf.Version == "" {
		return loadedCatalogue{}, fmt.Errorf("catalogue version is empty")
	}
	if len(cf.Toolchains) == 0 {
		return loadedCatalogue{}, fmt.Errorf("catalogue has no toolchains")
	}
	tcs := make([]toolchainEntry, 0, len(cf.Toolchains))
	for _, t := range cf.Toolchains {
		if t.Name == "" || t.MatchContains == "" {
			return loadedCatalogue{}, fmt.Errorf("toolchain entry missing name or match_contains: %+v", t)
		}
		tcs = append(tcs, toolchainEntry{name: t.Name, contains: t.MatchContains})
	}
	set := make(map[string]struct{}, len(cf.NonFIPSAlgorithmPackages))
	for _, p := range cf.NonFIPSAlgorithmPackages {
		if p == "" {
			return loadedCatalogue{}, fmt.Errorf("non_fips_algorithm_packages contains an empty entry")
		}
		set[p] = struct{}{}
	}
	return loadedCatalogue{
		version:      cf.Version,
		toolchains:   tcs,
		nonFIPSAlgos: cf.NonFIPSAlgorithmPackages,
		nonFIPSSet:   set,
	}, nil
}

// RecogniseToolchain maps a raw toolchain string (from go.mod toolchain
// directive or runtime/debug.BuildInfo GoVersion) to a catalogue variant
// name. Empty result means the variant is not known to be FIPS-capable —
// per this is recorded explicitly as "not capable", never silently
// assumed compliant. A blank input is also "not capable" (no toolchain
// evidence at all).
func RecogniseToolchain(raw string) string {
	if raw == "" {
		return ""
	}
	for _, t := range catalogue.toolchains {
		if strings.Contains(raw, t.contains) {
			return t.name
		}
	}
	return ""
}

// IsNonFIPSAlgorithmPackage reports whether importPath is a known non-FIPS
// algorithm package. The lookup is exact: a sub-package of a flagged path
// (e.g. crypto/md5/internal) is NOT itself flagged unless explicitly listed
// — keeping the catalogue's reach precise.
func IsNonFIPSAlgorithmPackage(importPath string) bool {
	_, ok := catalogue.nonFIPSSet[importPath]
	return ok
}

// PipelineFingerprint is the cache key suffix that makes a catalogue
// revision part of pipeline identity: re-running an unchanged scan under a
// newer catalogue must not return a stale cached classification.
func PipelineFingerprint() string {
	return PipelineVersion + "+cat." + CatalogueVersion()
}
