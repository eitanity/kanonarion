package domain

import (
	"strings"
	"testing"
)

// The republication that motivated this tier. github.com/golang-jwt/jwt/v4 is
// the community continuation of github.com/dgrijalva/jwt-go; its LICENSE carries
// both the original author's copyright line and the new maintainers'. The
// name-path heuristic is structurally blind to it — a republication changes the
// path, so nothing about the new path collides with the old one — and the
// signal is in the licence text instead.
func TestInferRepublication_JWTTwoHolders(t *testing.T) {
	attributions := []CopyrightAttribution{
		{Holder: "Dave Grijalva", Verbatim: "Copyright (c) 2012 Dave Grijalva"},
		{Holder: "golang-jwt maintainers", Verbatim: "Copyright (c) 2021 golang-jwt maintainers"},
	}
	got := InferRepublication("github.com/golang-jwt/jwt/v4", attributions, LedgerModules([]string{
		"github.com/dgrijalva/jwt-go",
		"github.com/golang-jwt/jwt/v4",
		"golang.org/x/text",
	}))
	if len(got) != 2 {
		t.Fatalf("indicators = %d, want 2 (multiple holders + holder names another path)\n%+v", len(got), got)
	}

	multi := got[0]
	if multi.Signal != RepublicationMultipleHolders {
		t.Fatalf("first indicator signal = %v, want multiple holders", multi.Signal)
	}
	for _, want := range []string{"Dave Grijalva", "golang-jwt maintainers"} {
		if !containsString(multi.Holders, want) {
			t.Errorf("holders %v do not name %q", multi.Holders, want)
		}
	}
	for _, want := range []string{"Copyright (c) 2012 Dave Grijalva", "Copyright (c) 2021 golang-jwt maintainers"} {
		if !containsString(multi.Evidence, want) {
			t.Errorf("evidence %v does not quote %q", multi.Evidence, want)
		}
	}
	if !strings.Contains(multi.Statement, "verify") {
		t.Errorf("statement %q lacks the verify caveat", multi.Statement)
	}

	match := got[1]
	if match.Signal != RepublicationHolderMatchesPath {
		t.Fatalf("second indicator signal = %v, want holder-matches-path", match.Signal)
	}
	if match.Canonical != "github.com/dgrijalva/jwt-go" {
		t.Errorf("canonical = %q, want github.com/dgrijalva/jwt-go", match.Canonical)
	}
	if !containsString(match.Holders, "Dave Grijalva") {
		t.Errorf("holders = %v, want Dave Grijalva", match.Holders)
	}
	if !strings.Contains(match.Statement, "verify") {
		t.Errorf("statement %q lacks the verify caveat", match.Statement)
	}
}

// A module whose licence names one holder yields nothing. The tier is a signal,
// not a dragnet.
func TestInferRepublication_SingleHolderYieldsNothing(t *testing.T) {
	got := InferRepublication("github.com/spf13/cobra", []CopyrightAttribution{
		{Holder: "Steve Francia", Verbatim: "Copyright © 2013 Steve Francia"},
	}, LedgerModules([]string{"github.com/spf13/pflag", "github.com/dgrijalva/jwt-go"}))
	if len(got) != 0 {
		t.Fatalf("indicators = %+v, want none", got)
	}
}

// The same holder written twice — two files, two years — is one holder.
func TestInferRepublication_RepeatedHolderIsNotTwoHolders(t *testing.T) {
	got := InferRepublication("example.com/mod", []CopyrightAttribution{
		{Holder: "Acme Corp", Verbatim: "Copyright (c) 2019 Acme Corp"},
		{Holder: "acme corp", Verbatim: "Copyright (c) 2021 acme corp"},
	}, nil)
	if len(got) != 0 {
		t.Fatalf("indicators = %+v, want none: one holder written twice", got)
	}
}

// The name-overlap condition is what keeps the holder-matches-path rule from
// firing on every module a large copyright holder appears in. A holder that
// names another path's owner is not a republication signal when the two modules
// are different libraries.
func TestInferRepublication_HolderMatchNeedsNameOverlap(t *testing.T) {
	got := InferRepublication("example.com/widget", []CopyrightAttribution{
		{Holder: "Grijalva Software", Verbatim: "Copyright (c) 2020 Grijalva Software"},
	}, LedgerModules([]string{"github.com/dgrijalva/jwt-go"}))
	if len(got) != 0 {
		t.Fatalf("indicators = %+v, want none: widget and jwt-go are different libraries", got)
	}
}

// The owner condition is the other half. Two modules of the same name under
// unrelated owners are a name collision, which the name-path heuristic already
// reports; this tier only speaks when a copyright holder ties them together.
func TestInferRepublication_NameOverlapAloneIsNotEnough(t *testing.T) {
	got := InferRepublication("example.com/jwt", []CopyrightAttribution{
		{Holder: "Unrelated Author", Verbatim: "Copyright (c) 2020 Unrelated Author"},
	}, LedgerModules([]string{"github.com/dgrijalva/jwt-go"}))
	if len(got) != 0 {
		t.Fatalf("indicators = %+v, want none: no holder ties the two together", got)
	}
}

// The module's own path never matches itself, at any major version.
func TestInferRepublication_SelfPathIsNeverACandidate(t *testing.T) {
	got := InferRepublication("github.com/golang-jwt/jwt/v4", []CopyrightAttribution{
		{Holder: "golang-jwt maintainers", Verbatim: "Copyright (c) 2021 golang-jwt maintainers"},
	}, LedgerModules([]string{"github.com/golang-jwt/jwt/v5", "github.com/golang-jwt/jwt/v4"}))
	for _, ind := range got {
		if ind.Signal == RepublicationHolderMatchesPath && strings.HasPrefix(ind.Canonical, "github.com/golang-jwt/jwt") {
			t.Errorf("module matched a major-version sibling of itself: %+v", ind)
		}
	}
}

// A holder token too short to be distinctive must not match an owner: "Dave"
// alone would name half the forge.
func TestInferRepublication_ShortHolderTokensDoNotMatch(t *testing.T) {
	got := InferRepublication("example.com/jwt-go", []CopyrightAttribution{
		{Holder: "Dave", Verbatim: "Copyright (c) 2012 Dave"},
	}, LedgerModules([]string{"github.com/dave/jwt-go"}))
	if len(got) != 0 {
		t.Fatalf("indicators = %+v, want none: 'Dave' is too short to name an owner", got)
	}
}

// A one- or two-character base name overlaps almost everything, so it is not an
// overlap at all.
func TestInferRepublication_TinyBaseNamesDoNotOverlap(t *testing.T) {
	if baseNamesOverlap("go", "google") {
		t.Error("a two-character base name must not count as an overlap")
	}
	if baseNamesOverlap("google", "go") {
		t.Error("overlap must be symmetric in its length rule")
	}
}

// Blank holders and blank verbatim lines contribute nothing rather than
// counting as a distinct holder or empty evidence.
func TestInferRepublication_BlankAttributionsAreIgnored(t *testing.T) {
	got := InferRepublication("example.com/mod", []CopyrightAttribution{
		{Holder: "", Verbatim: ""},
		{Holder: "  ", Verbatim: "  "},
		{Holder: "Acme Corp", Verbatim: "Copyright (c) 2019 Acme Corp"},
	}, nil)
	if len(got) != 0 {
		t.Fatalf("indicators = %+v, want none: only one real holder", got)
	}
}

// Two holders with no verbatim text still report the signal; the evidence list
// is simply empty rather than the indicator being suppressed.
func TestInferRepublication_HoldersWithoutVerbatim(t *testing.T) {
	got := InferRepublication("example.com/mod", []CopyrightAttribution{
		{Holder: "Alice"},
		{Holder: "Bob"},
	}, nil)
	if len(got) != 1 || got[0].Signal != RepublicationMultipleHolders {
		t.Fatalf("indicators = %+v, want the multiple-holders signal", got)
	}
	if len(got[0].Evidence) != 0 {
		t.Errorf("evidence = %v, want none", got[0].Evidence)
	}
}

// A candidate path with no owner element (a bare host) names no owner.
func TestInferRepublication_HostOnlyCandidateNamesNoOwner(t *testing.T) {
	if owner := pathOwner("example.com"); owner != "" {
		t.Errorf("pathOwner(host only) = %q, want \"\"", owner)
	}
	if holderNamesOwner("Example Corporation", "") {
		t.Error("an empty owner must name nobody")
	}
}

// A candidate listed twice yields one indicator, not two.
func TestInferRepublication_DuplicateStorePathsYieldOneIndicator(t *testing.T) {
	got := InferRepublication("github.com/golang-jwt/jwt/v4", []CopyrightAttribution{
		{Holder: "Dave Grijalva", Verbatim: "Copyright (c) 2012 Dave Grijalva"},
	}, LedgerModules([]string{"github.com/dgrijalva/jwt-go", "github.com/dgrijalva/jwt-go"}))
	if len(got) != 1 {
		t.Fatalf("indicators = %+v, want exactly one", got)
	}
}

// The status and signal names are the machine-readable vocabulary; a renamed
// value silently changes every consumer's parse.
func TestRepublicationVocabulary(t *testing.T) {
	for got, want := range map[string]string{
		CopyrightSignalNotAnalysed.String():     "not_analysed",
		CopyrightSignalNone.String():            "none",
		CopyrightSignalRepublication.String():   "republication",
		CopyrightSignalStatus(99).String():      "not_analysed",
		RepublicationMultipleHolders.String():   "multiple_copyright_holders",
		RepublicationHolderMatchesPath.String(): "holder_matches_other_module_path",
		RepublicationSignal(99).String():        "unknown",
	} {
		if got != want {
			t.Errorf("vocabulary term = %q, want %q", got, want)
		}
	}
}

func containsString(xs []string, want string) bool {
	for _, x := range xs {
		if x == want {
			return true
		}
	}
	return false
}

// Two candidate republication sources sort by path, so the reply is stable
// across store listings that arrive in a different order.
func TestInferRepublication_MultipleHolderMatchesSortByPath(t *testing.T) {
	got := InferRepublication("example.com/newowner/jwt", []CopyrightAttribution{
		{Holder: "Dave Grijalva", Verbatim: "Copyright (c) 2012 Dave Grijalva"},
		{Holder: "Zeta Grijalva", Verbatim: "Copyright (c) 2015 Zeta Grijalva"},
	}, LedgerModules([]string{
		"github.com/zgrijalva/jwt-fork",
		"github.com/dgrijalva/jwt-go",
	}))
	var canonicals []string
	for _, ind := range got {
		if ind.Signal == RepublicationHolderMatchesPath {
			canonicals = append(canonicals, ind.Canonical)
		}
	}
	if len(canonicals) != 2 {
		t.Fatalf("holder-matches-path indicators = %v, want two", canonicals)
	}
	if canonicals[0] > canonicals[1] {
		t.Errorf("indicators are not sorted by canonical path: %v", canonicals)
	}
}

// The same copyright line appearing in two licence files is quoted once.
func TestInferRepublication_DuplicateVerbatimIsQuotedOnce(t *testing.T) {
	got := InferRepublication("example.com/mod", []CopyrightAttribution{
		{Holder: "Alice", Verbatim: "Copyright (c) 2019 Alice"},
		{Holder: "Alice", Verbatim: "Copyright (c) 2019 Alice"},
		{Holder: "Bob", Verbatim: "Copyright (c) 2020 Bob"},
	}, nil)
	if len(got) != 1 {
		t.Fatalf("indicators = %+v, want the multiple-holders signal", got)
	}
	if len(got[0].Evidence) != 2 {
		t.Errorf("evidence = %v, want the two distinct lines", got[0].Evidence)
	}
}

// A stored record can name an unfilled licence-template placeholder where a
// holder belongs — measured over a working store, several of the 219 records
// carrying two or more "holders" have a bracketed scaffold token as the second.
// Counting one as a holder would report a republication on the strength of an
// unfilled form field.
func TestInferRepublication_TemplatePlaceholdersAreNotHolders(t *testing.T) {
	for _, placeholder := range []string{
		"<name of author>",
		"[fullname]",
		"{yyyy} {name of copyright owner}",
	} {
		t.Run(placeholder, func(t *testing.T) {
			got := InferRepublication("example.com/mod", []CopyrightAttribution{
				{Holder: "Acme Corp", Verbatim: "Copyright (c) 2019 Acme Corp"},
				{Holder: placeholder, Verbatim: "Copyright (C) " + placeholder},
			}, nil)
			if len(got) != 0 {
				t.Fatalf("indicators = %+v, want none: %q names nobody", got, placeholder)
			}
		})
	}
}

// A real holder that lists its homepage in angle brackets is still a holder;
// only a wholly-bracketed value is a scaffold.
func TestInferRepublication_HolderWithBracketedURLIsStillAHolder(t *testing.T) {
	got := InferRepublication("example.com/mod", []CopyrightAttribution{
		{Holder: "Acme Corp", Verbatim: "Copyright (c) 2019 Acme Corp"},
		{Holder: "Example Foundation <https://example.org/>", Verbatim: "Copyright (c) 2020 Example Foundation <https://example.org/>"},
	}, nil)
	if len(got) != 1 || got[0].Signal != RepublicationMultipleHolders {
		t.Fatalf("indicators = %+v, want the multiple-holders signal", got)
	}
}

// A holder that owns both the module and a ledger neighbour with an overlapping
// name is one owner, not a copy. The same pair joined by a replace directive
// still reports: the directive is the evidence, whoever owns the two sides.
func TestInferRepublication_SameOwnerLedgerNeighbourIsSkipped(t *testing.T) {
	attributions := []CopyrightAttribution{
		{Holder: "Eitanity Systems VCC", Verbatim: "Copyright (c) 2026 Eitanity Systems VCC"},
	}
	if got := InferRepublication("github.com/eitanity/softmagic", attributions,
		LedgerModules([]string{"github.com/eitanity/softmagic-cli"})); len(got) != 0 {
		t.Fatalf("ledger indicators = %+v, want none: both paths share one owner", got)
	}
	got := InferRepublication("github.com/eitanity/softmagic", attributions,
		ReplacedModules([]string{"github.com/eitanity/softmagic-cli"}))
	if len(got) != 1 || got[0].Canonical != "github.com/eitanity/softmagic-cli" {
		t.Fatalf("replace indicators = %+v, want one for the replaced module", got)
	}
}

// A holder that names the module's own owner is the module's own copyright,
// whatever else it also names: one author's project on two hosts, or one
// vendor's word inside another path. A replace counterpart still reports.
func TestInferRepublication_HolderNamingOwnOwnerIsSkipped(t *testing.T) {
	for name, tc := range map[string]struct {
		module, holder, candidate string
	}{
		"same owner on another host": {
			module:    "gopkg.in/alecthomas/kingpin.v2",
			holder:    "Alec Thomas",
			candidate: "github.com/alecthomas/kingpin/v2",
		},
		"own owner word in another path": {
			module:    "github.com/go-sql-driver/mysql",
			holder:    "The Go-MySQL-Driver Authors. All rights reserved",
			candidate: "gorm.io/driver/mysql",
		},
	} {
		t.Run(name, func(t *testing.T) {
			attributions := []CopyrightAttribution{{Holder: tc.holder, Verbatim: "Copyright " + tc.holder}}
			if got := InferRepublication(tc.module, attributions, LedgerModules([]string{tc.candidate})); len(got) != 0 {
				t.Fatalf("ledger indicators = %+v, want none: %q names %s's own owner", got, tc.holder, tc.module)
			}
			got := InferRepublication(tc.module, attributions, ReplacedModules([]string{tc.candidate}))
			if len(got) != 1 || got[0].Canonical != tc.candidate {
				t.Fatalf("replace indicators = %+v, want one for %s", got, tc.candidate)
			}
		})
	}
}

// Copyright boilerplate names no one: "contributors" must not match an owner
// such as "contrib".
func TestInferRepublication_BoilerplateHolderWordsDoNotMatch(t *testing.T) {
	got := InferRepublication("github.com/prometheus/prometheus", []CopyrightAttribution{
		{Holder: "JS Foundation and other contributors", Verbatim: "Copyright JS Foundation and other contributors"},
	}, LedgerModules([]string{"go.opentelemetry.io/contrib/bridges/prometheus"}))
	if len(got) != 0 {
		t.Fatalf("indicators = %+v, want none: the holder has no distinctive word", got)
	}
}

// Paths differing only by major version are one module and yield one indicator,
// naming the smallest path. A replace relation still outranks a ledger one, and
// its own path is the one named.
func TestInferRepublication_MajorVersionSiblingsYieldOneIndicator(t *testing.T) {
	attributions := []CopyrightAttribution{{Holder: "Masterminds", Verbatim: "Copyright (C) 2013-2020 Masterminds"}}
	got := InferRepublication("github.com/go-task/slim-sprig/v3", attributions,
		LedgerModules([]string{"github.com/Masterminds/sprig/v3", "github.com/Masterminds/sprig"}))
	if len(got) != 1 || got[0].Canonical != "github.com/Masterminds/sprig" {
		t.Fatalf("ledger indicators = %+v, want one naming github.com/Masterminds/sprig", got)
	}
	got = InferRepublication("github.com/go-task/slim-sprig/v3", attributions, append(
		LedgerModules([]string{"github.com/Masterminds/sprig"}),
		ReplacedModules([]string{"github.com/Masterminds/sprig/v3"})...))
	if len(got) != 1 || got[0].Canonical != "github.com/Masterminds/sprig/v3" || !strings.Contains(got[0].Statement, "replace directive") {
		t.Fatalf("indicators = %+v, want one replace indicator naming github.com/Masterminds/sprig/v3", got)
	}
}

// Only the first element after the host is the owner. A repository or package
// name deeper in the path names no owner, however much a holder's name contains
// it.
func TestInferRepublication_OwnerIsFirstElementOnly(t *testing.T) {
	for name, tc := range map[string]struct {
		module, holder, candidate string
	}{
		"repository name": {
			module:    "example.com/fork/websocket",
			holder:    "The Gorilla WebSocket Authors",
			candidate: "github.com/mdlayher/socket",
		},
		"deeper element": {
			module:    "go.opentelemetry.io/otel/exporters/otlp/otlptrace/opentelemetry",
			holder:    "The OpenTelemetry Authors",
			candidate: "github.com/googlecloudplatform/opentelemetry-operations-go/exporter/opentelemetry",
		},
	} {
		t.Run(name, func(t *testing.T) {
			got := InferRepublication(tc.module, []CopyrightAttribution{
				{Holder: tc.holder, Verbatim: "Copyright " + tc.holder},
			}, LedgerModules([]string{tc.candidate}))
			if len(got) != 0 {
				t.Fatalf("indicators = %+v, want none: %q is not the owner of %s", got, tc.holder, tc.candidate)
			}
		})
	}
}

// A short owner would sit inside any long holder token: "linux" contains "x".
// The owner is held to the token's length floor so the substring test compares
// two distinctive names.
func TestInferRepublication_ShortOwnerDoesNotMatchInsideHolderToken(t *testing.T) {
	got := InferRepublication("github.com/opencontainers/image-spec", []CopyrightAttribution{
		{Holder: "The Linux Foundation", Verbatim: "Copyright 2016 The Linux Foundation."},
	}, LedgerModules([]string{"golang.org/x/image"}))
	if len(got) != 0 {
		t.Fatalf("indicators = %+v, want none: owner %q is too short to be named", got, "x")
	}
}

// The ledger statement says what was compared: path owners differ and the
// names overlap. Neither proves different ownership or an identical name.
func TestInferRepublication_LedgerStatementWording(t *testing.T) {
	got := InferRepublication("github.com/golang-jwt/jwt/v4", []CopyrightAttribution{
		{Holder: "Dave Grijalva", Verbatim: "Copyright (c) 2012 Dave Grijalva"},
	}, LedgerModules([]string{"github.com/dgrijalva/jwt-go"}))
	if len(got) != 1 {
		t.Fatalf("indicators = %+v, want one", got)
	}
	want := `copyright holder "Dave Grijalva" names the owner of github.com/dgrijalva/jwt-go, a module under a different path owner with an overlapping name held in this store — path suggests a republication of it; verify via VCS origin or content comparison`
	if got[0].Statement != want {
		t.Errorf("statement = %q\nwant        %q", got[0].Statement, want)
	}
}
