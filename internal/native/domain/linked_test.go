package domain_test

import (
	"testing"

	"github.com/eitanity/kanonarion/internal/native/domain"
)

// names renders the libraries a preamble names as "name/kind" pairs, which is
// what every case below is asserting about.
func names(libs []domain.LinkedLibrary) []string {
	out := make([]string, 0, len(libs))
	for _, l := range libs {
		out = append(out, l.Name+"/"+string(l.Kind))
	}
	return out
}

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// The operand forms a directive is read for, and the ones it is not. Each
// rejection is a place a looser read would name a component the directive does
// not name.
func TestLinkedLibrariesIn_OperandForms(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name     string
		preamble string
		want     []string
	}{
		{"dash-l", "#cgo LDFLAGS: -licui18n -licuuc", []string{"icui18n/external", "icuuc/external"}},
		{"framework", "#cgo LDFLAGS: -framework CoreFoundation -framework Security",
			[]string{"CoreFoundation/external", "Security/external"}},
		{"static archive", "#cgo LDFLAGS: ${SRCDIR}/../target/release/libpdf_oxide.a",
			[]string{"pdf_oxide/external"}},
		{"archive without the lib prefix", "#cgo LDFLAGS: ./vendor/foo.a", []string{"foo/external"}},
		{"windows archive path", `#cgo LDFLAGS: C:\build\libfoo.a`, []string{"foo/external"}},
		{"the C runtime is system", "#cgo LDFLAGS: -lm -lpthread -ldl -lc -lstdc++",
			[]string{"m/system", "pthread/system", "dl/system", "c/system", "stdc++/system"}},
		{"a version suffix stays in the name", "#cgo LDFLAGS: -licui18n.57", []string{"icui18n.57/external"}},
		{"quoted framework name", `#cgo LDFLAGS: -framework "Core Foundation"`, []string{"Core Foundation/external"}},

		// Build constraints are not evaluated; the directive is still read.
		{"constrained", "#cgo linux,amd64 LDFLAGS: -lfoo", []string{"foo/external"}},
		{"multiple constraints", "#cgo linux,!android LDFLAGS: -lfoo", []string{"foo/external"}},

		{"a search path names no library", "#cgo LDFLAGS: -L/usr/local/lib", nil},
		{"a linker option names no library", "#cgo LDFLAGS: -Wl,--whole-archive", nil},
		{"a bare -l names nothing", "#cgo LDFLAGS: -l", nil},
		{"CFLAGS is not read", "#cgo CFLAGS: -lnot_a_link -I/usr/include", nil},
		{"CPPFLAGS is not read", "#cgo CPPFLAGS: -lnope", nil},
		{"a template placeholder names nothing", "#cgo linux,amd64 LDFLAGS: {{.LinuxAmd64LDFLAGS}}", nil},
		{"a lowercase verb is not the verb", "#cgo ldflags: -lfoo", nil},
		{"no separator after #cgo", "#cgofoo LDFLAGS: -lbar", nil},
		{"an ordinary include is not a directive", "#include <stdlib.h>", nil},
		{"prose is not a directive", "This preamble links icu.", nil},
		{"a framework with no operand names nothing", "#cgo LDFLAGS: -framework", nil},
		{"a framework followed by a flag names nothing", "#cgo LDFLAGS: -framework -lfoo", []string{"foo/external"}},

		// pkg-config names packages, not linker libraries, and the name is
		// recorded in its own namespace rather than translated into one.
		{"pkg-config", "#cgo pkg-config: libxml-2.0", []string{"libxml-2.0/external"}},
		{"pkg-config names several packages", "#cgo pkg-config: libmongocrypt libbson-1.0",
			[]string{"libmongocrypt/external", "libbson-1.0/external"}},
		{"a pkg-config package is never system", "#cgo pkg-config: m dl", []string{"m/external", "dl/external"}},
		{"a pkg-config flag names no package", "#cgo pkg-config: --static libssl", []string{"libssl/external"}},
		{"a constrained pkg-config line counts", "#cgo linux pkg-config: libxml-2.0", []string{"libxml-2.0/external"}},
		{"pkg-config with no package names nothing", "#cgo pkg-config:", nil},
		{"CXXFLAGS is not read", "#cgo CXXFLAGS: -std=c++17", nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := names(domain.LinkedLibrariesIn("f.go", tc.preamble))
			if !equalStrings(got, tc.want) {
				t.Errorf("LinkedLibrariesIn(%q) = %v, want %v", tc.preamble, got, tc.want)
			}
		})
	}
}

// The directive is recorded verbatim, its own build constraint included, so a
// reader sees which build links the library without the tool evaluating one.
func TestLinkedLibrariesIn_RecordsTheDirectiveVerbatim(t *testing.T) {
	t.Parallel()

	preamble := "#include <stdlib.h>\n  #cgo darwin,amd64 LDFLAGS: ${SRCDIR}/../target/release/libpdf_oxide.a -framework Security\n"
	got := domain.LinkedLibrariesIn("cgo_dev.go", preamble)
	if len(got) != 2 {
		t.Fatalf("linked = %+v, want the archive and the framework", got)
	}
	want := "#cgo darwin,amd64 LDFLAGS: ${SRCDIR}/../target/release/libpdf_oxide.a -framework Security"
	for _, l := range got {
		if l.Directive != want {
			t.Errorf("directive = %q, want %q", l.Directive, want)
		}
		if l.File != "cgo_dev.go" {
			t.Errorf("file = %q, want cgo_dev.go", l.File)
		}
	}
}

// A directive naming several libraries on one line is several entries, so no
// name is lost behind another.
func TestLinkedLibrariesIn_ReadsEveryOperandOnOneLine(t *testing.T) {
	t.Parallel()

	preamble := "#cgo linux,amd64 LDFLAGS: ${SRCDIR}/../target/release/libpdf_oxide.a -lm -lpthread -ldl -lrt -lgcc_s -lutil -lc"
	got := names(domain.LinkedLibrariesIn("cgo_dev.go", preamble))
	want := []string{
		"pdf_oxide/external", "m/system", "pthread/system", "dl/system",
		"rt/system", "gcc_s/system", "util/system", "c/system",
	}
	if !equalStrings(got, want) {
		t.Errorf("linked = %v, want %v", got, want)
	}
}

// The system list is exactly the C runtime a cgo binary links by construction.
// A framework is not on it by decision: it names a component from outside the
// module that a reader may want to see.
func TestKindOf_SeparatesTheRuntimeFromEverythingElse(t *testing.T) {
	t.Parallel()

	for _, name := range []string{
		"m", "c", "dl", "pthread", "rt", "util", "resolv", "nsl",
		"crypt", "anl", "stdc++", "gcc", "gcc_s", "objc", "System",
	} {
		if got := domain.KindOf(name); got != domain.LinkedLibrarySystem {
			t.Errorf("KindOf(%q) = %q, want %q", name, got, domain.LinkedLibrarySystem)
		}
	}
	for _, name := range []string{
		"icui18n", "icuuc", "sqlite3", "pdf_oxide", "CoreFoundation", "Security",
		"iconv", "ws2_32", "crypt32", "systemd", "Systemd", "dll",
	} {
		if got := domain.KindOf(name); got != domain.LinkedLibraryExternal {
			t.Errorf("KindOf(%q) = %q, want %q", name, got, domain.LinkedLibraryExternal)
		}
	}
}

func TestHasExternalLink(t *testing.T) {
	t.Parallel()

	if domain.HasExternalLink(nil) {
		t.Error("an empty set reported an external link")
	}
	systemOnly := []domain.LinkedLibrary{
		{Name: "dl", Kind: domain.LinkedLibrarySystem},
		{Name: "m", Kind: domain.LinkedLibrarySystem},
	}
	if domain.HasExternalLink(systemOnly) {
		t.Error("the C runtime alone reported an external link")
	}
	if !domain.HasExternalLink(append(systemOnly,
		domain.LinkedLibrary{Name: "icui18n", Kind: domain.LinkedLibraryExternal})) {
		t.Error("an external link was not reported")
	}
}

// One directive read once is one entry; the same library named by two
// directives, or by one directive in two files, stays two pieces of evidence.
// Collapsing them would lose the file the claim rests on.
func TestDetector_AddDirectivesDedupesTheWholeEntry(t *testing.T) {
	t.Parallel()

	d := domain.NewDetector()
	d.AddDirectives("cases/icu.go", "#cgo LDFLAGS: -licui18n")
	d.AddDirectives("cases/icu.go", "#cgo LDFLAGS: -licui18n")
	d.AddDirectives("collate/icu.go", "#cgo LDFLAGS: -licui18n")
	d.AddDirectives("cases/icu.go", "#cgo darwin LDFLAGS: -licui18n")
	components, sources, linked := d.Result()

	if len(components) != 0 || len(sources) != 0 {
		t.Fatalf("directives produced sources or components: %+v %+v", components, sources)
	}
	if len(linked) != 3 {
		t.Fatalf("linked = %+v, want three distinct entries", linked)
	}
	// Canonical order: name, kind, file, directive.
	want := []struct{ file, directive string }{
		{"cases/icu.go", "#cgo LDFLAGS: -licui18n"},
		{"cases/icu.go", "#cgo darwin LDFLAGS: -licui18n"},
		{"collate/icu.go", "#cgo LDFLAGS: -licui18n"},
	}
	for i, w := range want {
		if linked[i].File != w.file || linked[i].Directive != w.directive {
			t.Errorf("linked[%d] = %+v, want %s / %s", i, linked[i], w.file, w.directive)
		}
	}
}

// A preamble with no directive at all links nothing, and says so with an empty
// collection rather than an absent one.
func TestDetector_APreambleWithNoDirectiveLinksNothing(t *testing.T) {
	t.Parallel()

	d := domain.NewDetector()
	d.AddDirectives("bind.go", "#include <sqlite3.h>\n#include <stdlib.h>")
	if _, _, linked := d.Result(); len(linked) != 0 {
		t.Errorf("linked = %+v, want none", linked)
	}
}

// A directive with a colon but no verb before it names nothing. Reading the
// empty head as a verb would make every stray colon a build directive.
func TestLinkedLibrariesIn_ADirectiveWithNoVerbNamesNothing(t *testing.T) {
	t.Parallel()

	for _, preamble := range []string{"#cgo : -lfoo", "#cgo LDFLAGS -lfoo"} {
		if got := domain.LinkedLibrariesIn("f.go", preamble); len(got) != 0 {
			t.Errorf("LinkedLibrariesIn(%q) = %+v, want none", preamble, got)
		}
	}
}

// A pkg-config package name is a different namespace from a linker name. The
// package libxml-2.0 resolves to -lxml2 only because a .pc file on the building
// machine says so, and translating it here would state a fact no artefact
// carries.
func TestLinkedLibrariesIn_PkgConfigNamesAreVerbatim(t *testing.T) {
	t.Parallel()

	got := domain.LinkedLibrariesIn("validate.go", "#cgo pkg-config: libxml-2.0")
	if len(got) != 1 {
		t.Fatalf("linked = %+v, want one package", got)
	}
	if got[0].Name != "libxml-2.0" {
		t.Errorf("name = %q, want the package name verbatim, with no lib prefix stripped and no mapping to xml2", got[0].Name)
	}
	if got[0].Kind != domain.LinkedLibraryExternal {
		t.Errorf("kind = %q, want %q: pkg-config is never how the C runtime is linked",
			got[0].Kind, domain.LinkedLibraryExternal)
	}
	// The verbatim directive is what lets a reader tell a pkg-config name from a
	// linker name without the record carrying a field for it.
	if got[0].Directive != "#cgo pkg-config: libxml-2.0" {
		t.Errorf("directive = %q, want the verbatim line", got[0].Directive)
	}
	if got[0].File != "validate.go" {
		t.Errorf("file = %q, want validate.go", got[0].File)
	}
}

// A pkg-config link with no shipped source earns the same value an -l link
// does. It is the same defect: something native reaches the binary and this
// artefact does not carry it.
func TestPresenceOf_PkgConfigLinkWithNoSourcesIsLinkedNotShipped(t *testing.T) {
	t.Parallel()

	d := domain.NewDetector()
	d.AddDirectives("validate.go", "#cgo pkg-config: libxml-2.0")
	components, sources, linked := d.Result()
	if got := domain.PresenceOf(components, sources, linked); got != domain.PresenceLinkedNotShipped {
		t.Errorf("presence = %q, want %q", got, domain.PresenceLinkedNotShipped)
	}
}
