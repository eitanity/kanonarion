package domain_test

import (
	"testing"

	"github.com/eitanity/kanonarion/internal/native/domain"
)

// TestComponentPURL_NamesTheLibraryUnderTheGenericType locks the identity two
// surfaces join on. The SBOM lists the component under this string and a
// vulnerability read names the unsearched component under the same one; if they
// ever spell it differently, a reader joining the two documents joins nothing.
func TestComponentPURL_NamesTheLibraryUnderTheGenericType(t *testing.T) {
	got := domain.ComponentPURL(domain.Component{Name: "SQLite", Version: "3.53.0"})
	if want := "pkg:generic/sqlite@3.53.0"; got != want {
		t.Errorf("ComponentPURL = %q, want %q", got, want)
	}
}

// TestComponentPURL_CarriesNoQualifiers is the rule that keeps this document
// honest. The purl specification offers download_url and checksum, and both
// would describe an upstream release kanonarion never fetched — what it read
// was a declaration inside a Go module's zip.
func TestComponentPURL_CarriesNoQualifiers(t *testing.T) {
	got := domain.ComponentPURL(domain.Component{Name: "SQLite", Version: "3.53.0"})
	for _, forbidden := range []string{"?", "download_url", "checksum", "cpe"} {
		if contains(got, forbidden) {
			t.Errorf("ComponentPURL = %q; it must assert nothing that was not measured (found %q)", got, forbidden)
		}
	}
}

// TestComponentPURL_RefusesHalfAnIdentity: a name with no version, or a version
// with no name, is not an identity. A purl built from half of one would send a
// reader looking for something that does not exist, which is worse than no purl.
func TestComponentPURL_RefusesHalfAnIdentity(t *testing.T) {
	for _, tc := range []struct {
		name string
		c    domain.Component
	}{
		{"no name", domain.Component{Version: "3.53.0"}},
		{"no version", domain.Component{Name: "SQLite"}},
		{"neither", domain.Component{}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := domain.ComponentPURL(tc.c); got != "" {
				t.Errorf("ComponentPURL(%+v) = %q, want the empty string", tc.c, got)
			}
		})
	}
}

// TestComponentPURL_EscapesWhatAPURLMayNotCarry. A recipe names the library and
// a version is read verbatim out of C source, so neither is drawn from a
// vocabulary this code may assume. Anything outside the specification's
// unreserved set is percent-encoded rather than dropped or passed through, so
// the result is always a well-formed purl.
func TestComponentPURL_EscapesWhatAPURLMayNotCarry(t *testing.T) {
	for _, tc := range []struct {
		name string
		c    domain.Component
		want string
	}{
		{"a space in the name", domain.Component{Name: "Open SSL", Version: "3.0.0"}, "pkg:generic/open%20ssl@3.0.0"},
		{"a slash would split the path", domain.Component{Name: "a/b", Version: "1"}, "pkg:generic/a%2Fb@1"},
		{"an at sign would split name from version", domain.Component{Name: "a@b", Version: "1"}, "pkg:generic/a%40b@1"},
		{"a question mark would start qualifiers", domain.Component{Name: "x", Version: "1?y=2"}, "pkg:generic/x@1%3Fy%3D2"},
		{"unreserved characters survive", domain.Component{Name: "lib-a.b_c~d", Version: "1.2.3-rc.1"}, "pkg:generic/lib-a.b_c~d@1.2.3-rc.1"},
		{"non-ASCII is encoded byte by byte", domain.Component{Name: "café", Version: "1"}, "pkg:generic/caf%C3%A9@1"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := domain.ComponentPURL(tc.c); got != tc.want {
				t.Errorf("ComponentPURL(%+v) = %q, want %q", tc.c, got, tc.want)
			}
		})
	}
}

// TestPURLTypeGeneric_IsTheReservedType guards the constant the whole scheme
// rests on: a library published in no registry takes the type the specification
// reserves for exactly that, never a registry's own.
func TestPURLTypeGeneric_IsTheReservedType(t *testing.T) {
	if domain.PURLTypeGeneric != "generic" {
		t.Errorf("PURLTypeGeneric = %q, want \"generic\"", domain.PURLTypeGeneric)
	}
}

func contains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
