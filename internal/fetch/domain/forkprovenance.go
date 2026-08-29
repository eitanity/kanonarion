package domain

import (
	"fmt"
	"regexp"
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

// ForkIndicatorLess is the canonical ordering for ForkIndicator slices. The
// canonical path leads; the statement follows, so a catalogue that names one
// canonical twice still produces one order.
func ForkIndicatorLess(a, b ForkIndicator) bool {
	if a.Canonical != b.Canonical {
		return a.Canonical < b.Canonical
	}
	return a.Statement < b.Statement
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
	sort.Slice(indicators, func(i, j int) bool { return ForkIndicatorLess(indicators[i], indicators[j]) })
	return ForkProvenance{
		Status:           ForkProvenancePathMatch,
		CatalogueVersion: ForkCatalogueVersion,
		Indicators:       indicators,
	}
}

// -- copyright-attribution tier ---------------------------------------------
//
// The name-path heuristic above compares a path against a catalogue of
// canonical paths. It is structurally blind to a republication, because a
// republication is precisely a project that changed its path: when
// github.com/dgrijalva/jwt-go was taken over as github.com/golang-jwt/jwt, no
// element of the new path collides with the old one, so the trailing-name
// comparison has nothing to fire on. The signal is in the licence text instead —
// the republished LICENSE carries the original author's copyright line beside
// the new maintainers'.

// CopyrightAttribution is one copyright line read off a module's licence
// record, reduced to what this inference needs.
//
// It is a plain-string projection rather than the licence domain's own type so
// this package stays independent of that context: the inference is about names
// and paths, and importing another bounded context's aggregate to compare two
// strings would tie the two together for nothing.
type CopyrightAttribution struct {
	// Holder is the parsed copyright holder, best-effort.
	Holder string
	// Verbatim is the exact copyright line, for quoting as evidence.
	Verbatim string
}

// RepublicationSignal names which copyright signal produced an indicator.
type RepublicationSignal int

const (
	// RepublicationMultipleHolders means the licence text attributes copyright
	// to more than one distinct holder. A single project that has always lived
	// at one path normally carries one; a republication carries the original
	// author's line and the new maintainers'.
	RepublicationMultipleHolders RepublicationSignal = iota + 1
	// RepublicationHolderMatchesPath means a copyright holder's name matches the
	// owner element of a DIFFERENT module path this store knows of, related to
	// this one either by a shared module name or by a go.mod replace directive.
	// That is the shape of a project republished under new ownership.
	RepublicationHolderMatchesPath
)

// ModuleRelation says how another module path came to be a candidate for the
// holder-matches-path rule. The rule is one rule; the relation is what put the
// other path in front of it, and it changes both what still has to be checked
// and what the resulting statement can honestly claim.
type ModuleRelation int

const (
	// RelatedByLedger is a path the licence ledger happens to hold. Nothing
	// connects it to this module except its name, so the name overlap is still
	// required before a holder match means anything.
	RelatedByLedger ModuleRelation = iota
	// RelatedByReplace is the module path this one replaces under a go.mod
	// replace directive, as a walk in this store recorded it. The directive is
	// itself the statement that the two are the same library, so no name
	// comparison is needed or wanted: a fork published under a different name is
	// exactly the case the name comparison cannot see, and the directive names it
	// outright.
	RelatedByReplace
)

// RelatedModule is one other module path the copyright tier compares a holder
// against, with the relation that produced it.
//
// The relation is carried rather than the candidate lists being merged because
// the rule reads the two differently: a ledger neighbour has to earn the
// comparison with a matching module name, and a replace counterpart has already
// earned it by being named in the manifest.
type RelatedModule struct {
	// Path is the other module path.
	Path string
	// Relation says why it is a candidate.
	Relation ModuleRelation
}

// LedgerModules projects plain module paths onto ledger-related candidates.
func LedgerModules(paths []string) []RelatedModule {
	out := make([]RelatedModule, 0, len(paths))
	for _, p := range paths {
		out = append(out, RelatedModule{Path: p, Relation: RelatedByLedger})
	}
	return out
}

// ReplacedModules projects replaced module paths onto replace-related
// candidates.
func ReplacedModules(paths []string) []RelatedModule {
	out := make([]RelatedModule, 0, len(paths))
	for _, p := range paths {
		out = append(out, RelatedModule{Path: p, Relation: RelatedByReplace})
	}
	return out
}

// String returns the stable machine-readable name of the signal.
func (s RepublicationSignal) String() string {
	switch s {
	case RepublicationMultipleHolders:
		return "multiple_copyright_holders"
	case RepublicationHolderMatchesPath:
		return "holder_matches_other_module_path"
	default:
		return "unknown"
	}
}

// CopyrightSignalStatus distinguishes the three states of the copyright tier, on
// the same terms as ForkProvenanceStatus: a tier that never ran must never be
// reported as a tier that ran and found nothing.
type CopyrightSignalStatus int

const (
	// CopyrightSignalNotAnalysed is the zero value: no licence record was read,
	// so the copyright lines were never consulted.
	CopyrightSignalNotAnalysed CopyrightSignalStatus = iota
	// CopyrightSignalNone means the copyright lines were read and carry no
	// republication signal.
	CopyrightSignalNone
	// CopyrightSignalRepublication means at least one signal fired.
	CopyrightSignalRepublication
)

// String returns the stable machine-readable name of the status.
func (s CopyrightSignalStatus) String() string {
	switch s {
	case CopyrightSignalNone:
		return "none"
	case CopyrightSignalRepublication:
		return "republication"
	default:
		return "not_analysed"
	}
}

// RepublicationIndicator is one caveated republication inference drawn from a
// module's copyright lines. Like ForkIndicator it is a suggestion to verify,
// never an established fact.
type RepublicationIndicator struct {
	// Signal names which rule fired.
	Signal RepublicationSignal
	// Holders are the copyright holders the inference rests on, sorted.
	Holders []string
	// Evidence quotes the copyright lines verbatim, sorted. The evidence is
	// carried rather than summarised because the reader is being asked to
	// verify, and a claim they cannot check is one they must take on trust.
	Evidence []string
	// Canonical is the other module path a holder's name matched. Empty for the
	// multiple-holders signal, which names no other module.
	Canonical string
	// Statement is the caveated human-readable inference.
	Statement string
}

// InferRepublication runs the copyright-attribution tier over one module's
// licence copyright lines.
//
// related are other module paths known to this store, used only by the
// holder-matches-path rule; passing none disables that rule and leaves the
// multiple-holders rule intact. The result is an inference, never a verdict.
func InferRepublication(modulePath string, attributions []CopyrightAttribution, related []RelatedModule) []RepublicationIndicator {
	holders := distinctHolders(attributions)
	var indicators []RepublicationIndicator

	if len(holders) > 1 {
		evidence := distinctVerbatim(attributions)
		indicators = append(indicators, RepublicationIndicator{
			Signal:   RepublicationMultipleHolders,
			Holders:  holders,
			Evidence: evidence,
			Statement: fmt.Sprintf(
				"licence text attributes copyright to %d distinct holders (%s) — a project republished under a new path carries the original author's line beside the new maintainers'; verify via VCS origin or content comparison",
				len(holders), strings.Join(holders, "; ")),
		})
	}

	indicators = append(indicators, holderPathMatches(modulePath, attributions, holders, dedupeRelated(related))...)

	sort.Slice(indicators, func(i, j int) bool {
		if indicators[i].Signal != indicators[j].Signal {
			return indicators[i].Signal < indicators[j].Signal
		}
		return indicators[i].Canonical < indicators[j].Canonical
	})
	return indicators
}

// dedupeRelated collapses the candidate list to one entry per path, in path
// order, keeping the strongest relation for each.
//
// A replace counterpart can also sit in the licence ledger, and the two
// relations are not equal evidence: the directive says the two modules stand in
// for each other, while ledger membership says only that both were analysed
// here. Ordering by path keeps the indicator list deterministic under a store
// whose listing order is not.
func dedupeRelated(related []RelatedModule) []RelatedModule {
	strongest := make(map[string]ModuleRelation, len(related))
	for _, r := range related {
		if r.Path == "" {
			continue
		}
		if prev, ok := strongest[r.Path]; ok && prev >= r.Relation {
			continue
		}
		strongest[r.Path] = r.Relation
	}
	out := make([]RelatedModule, 0, len(strongest))
	for path, rel := range strongest {
		out = append(out, RelatedModule{Path: path, Relation: rel})
	}
	// Path is a map key here, so no two entries share one and the relation is a
	// tiebreak that can never be reached; it is keyed anyway so the comparator
	// reads as a total order without a reader having to trace the map back.
	sort.Slice(out, func(i, j int) bool {
		if out[i].Path != out[j].Path {
			return out[i].Path < out[j].Path
		}
		return out[i].Relation < out[j].Relation
	})
	return out
}

// holderPathMatches finds related module paths that a copyright holder's name
// names the owner of.
//
// For a ledger neighbour the module names must overlap as well. The owner match
// alone fires on every module a large copyright holder appears in; the name
// overlap alone fires on every unrelated project that happens to share a word.
// Together they describe the one shape this rule is for: the same library, under
// a different owner, still carrying that owner's copyright.
//
// For a replace counterpart the name comparison is skipped, because the manifest
// already asserted what the comparison was standing in for. Requiring it there
// re-acquires the blindness the name-path heuristic is documented as having: the
// replaced module is the one a fork was published to displace, whatever it was
// renamed to on the way.
func holderPathMatches(modulePath string, attributions []CopyrightAttribution, holders []string, related []RelatedModule) []RepublicationIndicator {
	self := normalizeModulePath(modulePath)
	selfBase := moduleBaseName(modulePath)
	var out []RepublicationIndicator

	for _, candidate := range related {
		if normalizeModulePath(candidate.Path) == self {
			continue
		}
		if candidate.Relation == RelatedByLedger && !baseNamesOverlap(selfBase, moduleBaseName(candidate.Path)) {
			continue
		}
		owners := pathOwnerElements(candidate.Path)
		for _, holder := range holders {
			if !holderNamesOwner(holder, owners) {
				continue
			}
			out = append(out, RepublicationIndicator{
				Signal:    RepublicationHolderMatchesPath,
				Holders:   []string{holder},
				Evidence:  verbatimForHolder(attributions, holder),
				Canonical: candidate.Path,
				Statement: relatedStatement(holder, candidate),
			})
			break
		}
	}
	return out
}

// relatedStatement phrases the inference in the terms of the relation that
// produced the candidate, so a reader can tell which fact the tool is standing
// on: a module of the same name that happens to be in this store, or a replace
// directive naming the module this one stands in for.
func relatedStatement(holder string, candidate RelatedModule) string {
	if candidate.Relation == RelatedByReplace {
		return fmt.Sprintf(
			"copyright holder %q names the owner of %s, the module this one replaces under a go.mod replace directive recorded in this store — the replacement carries the replaced module's copyright and no line of its own; verify via VCS origin or content comparison",
			holder, candidate.Path)
	}
	return fmt.Sprintf(
		"copyright holder %q names the owner of %s, a differently-owned module of the same name held in this store — path suggests a republication of it; verify via VCS origin or content comparison",
		holder, candidate.Path)
}

// holderMinTokenLen is the shortest holder-name token allowed to match a path
// owner. It drops the corporate and given-name noise ("inc", "ltd", "the",
// "dave") that would otherwise match owners at random.
const holderMinTokenLen = 5

// baseNameMinLen is the shortest module base name the overlap test accepts. A
// one- or two-character name overlaps almost everything.
const baseNameMinLen = 3

// holderNameTokenRe splits a holder name into alphanumeric tokens.
var holderNameTokenRe = regexp.MustCompile(`[^a-z0-9]+`)

// holderNamesOwner reports whether any sufficiently distinctive token of holder
// appears within one of a path's owner elements, in either direction — "Dave
// Grijalva" names the owner of github.com/dgrijalva/jwt-go.
func holderNamesOwner(holder string, owners []string) bool {
	for _, tok := range holderNameTokenRe.Split(strings.ToLower(holder), -1) {
		if len(tok) < holderMinTokenLen {
			continue
		}
		for _, owner := range owners {
			if strings.Contains(owner, tok) || strings.Contains(tok, owner) {
				return true
			}
		}
	}
	return false
}

// pathOwnerElements returns the lowercased path elements after the host, with
// any trailing major-version element already stripped by normalisation. The host
// is excluded: every module on a forge shares it, so it names no owner.
func pathOwnerElements(path string) []string {
	parts := strings.Split(normalizeModulePath(path), "/")
	if len(parts) <= 1 {
		return nil
	}
	return parts[1:]
}

// baseNamesOverlap reports whether two module base names describe the same
// library name, allowing one to extend the other ("jwt" and "jwt-go").
func baseNamesOverlap(a, b string) bool {
	if len(a) < baseNameMinLen || len(b) < baseNameMinLen {
		return false
	}
	return strings.Contains(a, b) || strings.Contains(b, a)
}

// templatePlaceholderRe matches an unfilled licence-template placeholder token —
// "<name of author>", "[fullname]", "{yyyy}". Licence "how to apply" scaffolds
// ship these literally, and a stored record extracted before they were filtered
// carries them where a holder belongs.
//
// It is applied here as well as at extraction because this tier reads records
// the store already holds: measured over a working store, 219 of 2,454 licence
// records name two or more holders, and among them are records whose "second
// holder" is a bracketed placeholder. Counting one as a holder would report a
// republication on the strength of an unfilled form field.
var templatePlaceholderRe = regexp.MustCompile(`<[^<>]*>|\[[^\[\]]*\]|\{[^{}]*\}`)

// distinctHolders returns the distinct, non-empty copyright holders across the
// attributions, sorted. Holders are compared case-insensitively but reported as
// first written.
func distinctHolders(attributions []CopyrightAttribution) []string {
	seen := make(map[string]string)
	for _, a := range attributions {
		h := strings.TrimSpace(a.Holder)
		if h == "" {
			continue
		}
		// A holder whose text is nothing but a template placeholder names
		// nobody. One that merely mentions a URL in angle brackets beside a real
		// name still names someone, so only a wholly-bracketed value is dropped.
		if strings.TrimSpace(templatePlaceholderRe.ReplaceAllString(h, "")) == "" {
			continue
		}
		key := strings.ToLower(h)
		if _, ok := seen[key]; !ok {
			seen[key] = h
		}
	}
	out := make([]string, 0, len(seen))
	for _, h := range seen {
		out = append(out, h)
	}
	sort.Strings(out)
	return out
}

// distinctVerbatim returns the distinct, non-empty copyright lines, sorted.
func distinctVerbatim(attributions []CopyrightAttribution) []string {
	seen := make(map[string]struct{})
	var out []string
	for _, a := range attributions {
		v := strings.TrimSpace(a.Verbatim)
		if v == "" {
			continue
		}
		if _, ok := seen[v]; ok {
			continue
		}
		seen[v] = struct{}{}
		out = append(out, v)
	}
	sort.Strings(out)
	return out
}

// verbatimForHolder returns the copyright lines belonging to one holder.
func verbatimForHolder(attributions []CopyrightAttribution, holder string) []string {
	var matched []CopyrightAttribution
	for _, a := range attributions {
		if strings.EqualFold(strings.TrimSpace(a.Holder), holder) {
			matched = append(matched, a)
		}
	}
	return distinctVerbatim(matched)
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
