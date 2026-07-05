package domain

import (
	"fmt"
	"sort"
	"strings"
)

// ForkCatalogueVersion identifies the version of the static canonical-module
// catalogue backing the name-path fork heuristic. Bump deliberately when
// entries are added or corrected.
const ForkCatalogueVersion = "1.0.0"

// ForkProvenanceStatus distinguishes the three states of the fork heuristic.
// "Not analysed" must never be conflated with "analysed, no indicators": a
// surface that has not run the heuristic reports ForkProvenanceNotAnalysed, a
// surface that ran it over an unrelated path reports ForkProvenanceNone.
type ForkProvenanceStatus int

const (
	// ForkProvenanceNotAnalysed means the heuristic has not been run for this
	// module. It is the zero value so an unfilled field reads as uncertainty,
	// never as a confident negative. InferForkProvenance never returns it.
	ForkProvenanceNotAnalysed ForkProvenanceStatus = iota
	// ForkProvenanceNone means the heuristic ran and the path collides with no
	// catalogued canonical module name.
	ForkProvenanceNone
	// ForkProvenancePathMatch means the path shares its trailing name element
	// with a catalogued canonical module under a different owner or host. This
	// is a caveated inference — "path suggests a fork", never "is a fork".
	ForkProvenancePathMatch
)

// String returns the stable machine-readable name of the status.
func (s ForkProvenanceStatus) String() string {
	switch s {
	case ForkProvenanceNone:
		return "none"
	case ForkProvenancePathMatch:
		return "path_match"
	default:
		return "not_analysed"
	}
}

// ForkIndicator is one caveated fork inference: the module path shares its
// trailing name element with Canonical while living under a different owner
// or host.
type ForkIndicator struct {
	// Canonical is the catalogued canonical module path the name collides with.
	Canonical string
	// Statement is the caveated human-readable inference. It always phrases
	// the finding as a suggestion to verify, never as an established fact.
	Statement string
}

// ForkProvenance is the result of the name-path fork heuristic for one module
// path. Indicators is non-empty exactly when Status is ForkProvenancePathMatch
// and is sorted by Canonical for deterministic output.
type ForkProvenance struct {
	Status           ForkProvenanceStatus
	CatalogueVersion string
	Indicators       []ForkIndicator
}

// forkCanonicalCatalogue lists canonical module paths with distinctive
// trailing name elements. A candidate path whose trailing element matches an
// entry's, but whose owner/host differs, yields a caveated fork indicator.
// Names that are too generic to be a signal (mod, errors, crypto, …) are
// deliberately absent. Dataset version: ForkCatalogueVersion.
var forkCanonicalCatalogue = []string{
	"github.com/gin-gonic/gin",
	"github.com/golang-jwt/jwt/v5",
	"github.com/google/uuid",
	"github.com/gorilla/mux",
	"github.com/gorilla/websocket",
	"github.com/labstack/echo/v4",
	"github.com/prometheus/client_golang",
	"github.com/rs/zerolog",
	"github.com/sirupsen/logrus",
	"github.com/spf13/cobra",
	"github.com/spf13/pflag",
	"github.com/spf13/viper",
	"github.com/stretchr/testify",
	"go.uber.org/zap",
	"google.golang.org/grpc",
	"google.golang.org/protobuf",
	"gopkg.in/yaml.v3",
}

// InferForkProvenance runs the cheap-tier name-path fork heuristic over a
// module path. It is a pure function over the path string and the static
// catalogue: no I/O, no store access. The result is a caveated inference,
// not a verdict — confirming or refuting a fork requires the strong tier
// (shared VCS origin or content overlap), which is out of scope here.
func InferForkProvenance(path string) ForkProvenance {
	return inferForkProvenance(path, forkCanonicalCatalogue)
}

// inferForkProvenance is the catalogue-parameterised core, split out so tests
// can exercise matching and ordering against a controlled catalogue.
func inferForkProvenance(path string, catalogue []string) ForkProvenance {
	norm := normalizeModulePath(path)

	// The candidate being a catalogued canonical itself (any major version)
	// is never a fork indicator, even if another entry shares its name.
	for _, canonical := range catalogue {
		if normalizeModulePath(canonical) == norm {
			return ForkProvenance{Status: ForkProvenanceNone, CatalogueVersion: ForkCatalogueVersion}
		}
	}

	base := moduleBaseName(path)
	var indicators []ForkIndicator
	for _, canonical := range catalogue {
		if moduleBaseName(canonical) == base {
			indicators = append(indicators, ForkIndicator{
				Canonical: canonical,
				Statement: fmt.Sprintf("path suggests a fork of %s — verify via VCS origin or content comparison", canonical),
			})
		}
	}
	if len(indicators) == 0 {
		return ForkProvenance{Status: ForkProvenanceNone, CatalogueVersion: ForkCatalogueVersion}
	}
	sort.Slice(indicators, func(i, j int) bool { return indicators[i].Canonical < indicators[j].Canonical })
	return ForkProvenance{
		Status:           ForkProvenancePathMatch,
		CatalogueVersion: ForkCatalogueVersion,
		Indicators:       indicators,
	}
}

// normalizeModulePath lowercases a module path and strips version markers
// that do not change module identity for name comparison: a trailing
// "/vN" major-version element and a gopkg.in-style ".vN" suffix on the
// final element.
func normalizeModulePath(path string) string {
	p := strings.ToLower(strings.TrimSuffix(path, "/"))
	p = stripMajorSuffix(p)
	if i := strings.LastIndex(p, "/"); i >= 0 {
		return p[:i+1] + stripDotVersionSuffix(p[i+1:])
	}
	return stripDotVersionSuffix(p)
}

// moduleBaseName returns the lowercased trailing path element with version
// markers stripped — the name the heuristic compares across hosts/owners.
func moduleBaseName(path string) string {
	p := normalizeModulePath(path)
	if i := strings.LastIndex(p, "/"); i >= 0 {
		return p[i+1:]
	}
	return p
}

// stripMajorSuffix removes a trailing major-version path element ("/v2",
// "/v10", …) when present.
func stripMajorSuffix(path string) string {
	i := strings.LastIndex(path, "/")
	if i < 0 {
		return path
	}
	if isVersionElement(path[i+1:]) {
		return path[:i]
	}
	return path
}

// stripDotVersionSuffix removes a gopkg.in-style ".vN" suffix from a path
// element ("yaml.v3" → "yaml") when present.
func stripDotVersionSuffix(elem string) string {
	i := strings.LastIndex(elem, ".")
	if i < 0 {
		return elem
	}
	if isVersionElement(elem[i+1:]) {
		return elem[:i]
	}
	return elem
}

// isVersionElement reports whether s is "v" followed by one or more digits.
func isVersionElement(s string) bool {
	if len(s) < 2 || s[0] != 'v' {
		return false
	}
	for _, r := range s[1:] {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}
