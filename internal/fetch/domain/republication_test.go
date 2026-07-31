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
	got := InferRepublication("github.com/golang-jwt/jwt/v4", attributions, []string{
		"github.com/dgrijalva/jwt-go",
		"github.com/golang-jwt/jwt/v4",
		"golang.org/x/text",
	})
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
	}, []string{"github.com/spf13/pflag", "github.com/dgrijalva/jwt-go"})
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
	}, []string{"github.com/dgrijalva/jwt-go"})
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
	}, []string{"github.com/dgrijalva/jwt-go"})
	if len(got) != 0 {
		t.Fatalf("indicators = %+v, want none: no holder ties the two together", got)
	}
}

// The module's own path never matches itself, at any major version.
func TestInferRepublication_SelfPathIsNeverACandidate(t *testing.T) {
	got := InferRepublication("github.com/golang-jwt/jwt/v4", []CopyrightAttribution{
		{Holder: "golang-jwt maintainers", Verbatim: "Copyright (c) 2021 golang-jwt maintainers"},
	}, []string{"github.com/golang-jwt/jwt/v5", "github.com/golang-jwt/jwt/v4"})
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
	}, []string{"github.com/dave/jwt-go"})
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
	if got := pathOwnerElements("example.com"); got != nil {
		t.Errorf("pathOwnerElements(host only) = %v, want nil", got)
	}
}

// A candidate listed twice yields one indicator, not two.
func TestInferRepublication_DuplicateStorePathsYieldOneIndicator(t *testing.T) {
	got := InferRepublication("github.com/golang-jwt/jwt/v4", []CopyrightAttribution{
		{Holder: "Dave Grijalva", Verbatim: "Copyright (c) 2012 Dave Grijalva"},
	}, []string{"github.com/dgrijalva/jwt-go", "github.com/dgrijalva/jwt-go"})
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
	}, []string{
		"github.com/zgrijalva/jwt-fork",
		"github.com/dgrijalva/jwt-go",
	})
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
