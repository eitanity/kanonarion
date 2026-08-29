package domain

import (
	"path"
	"sort"
	"strings"
)

// CgoDirectivePrefix opens a cgo directive line inside the preamble.
const CgoDirectivePrefix = "#cgo"

// The cgo directive verbs read here. Both name what ends up linked; CFLAGS,
// CPPFLAGS, CXXFLAGS and FFLAGS say how the compiler is invoked rather than
// what the binary carries, and reading a library name out of one would name
// something the build may never link.
const (
	// LDFlagsVerb names libraries by linker flag: `-l<name>`, `-framework
	// <name>`, or a `.a` archive path.
	LDFlagsVerb = "LDFLAGS"

	// PkgConfigVerb names libraries by pkg-config package. It is a different
	// namespace from the linker's: the package `libxml-2.0` resolves to
	// `-lxml2`, and only pkg-config on the building machine knows that. The
	// package name is recorded as written and never translated.
	PkgConfigVerb = "pkg-config"
)

// LinkedLibraryKind separates the C runtime a cgo binary links by construction
// from a named component that comes from outside the module.
type LinkedLibraryKind string

const (
	// LinkedLibraryExternal is a named library from outside the module: an ICU
	// build, a Rust static archive, a macOS framework. It is the kind that
	// makes "the artefact ships no native source" stop meaning "nothing native
	// is linked".
	LinkedLibraryExternal LinkedLibraryKind = "external"

	// LinkedLibrarySystem is the C runtime and its immediate companions. Every
	// cgo binary links them, so flagging them would make the external kind
	// meaningless.
	LinkedLibrarySystem LinkedLibraryKind = "system"
)

// systemLibraries is the C runtime a cgo binary links by construction. The set
// is fixed and small on purpose: a name outside it is reported as external and
// the reader decides what it means, which is the opposite of a catalogue of
// libraries that "do not count".
//
// Frameworks are deliberately absent. `-framework CoreFoundation` names a
// component from outside the module that a reader may want to see, and this
// tool reports evidence rather than verdicts.
var systemLibraries = map[string]bool{
	"m": true, "c": true, "dl": true, "pthread": true, "rt": true,
	"util": true, "resolv": true, "nsl": true, "crypt": true, "anl": true,
	"stdc++": true, "gcc": true, "gcc_s": true, "objc": true, "System": true,
}

// LinkedLibrary is one native library a cgo directive names as linked into the
// binary, recorded whether or not the artefact ships its source.
//
// Nothing here is resolved. A `-l` name is not looked for on any host, a path
// operand is not opened, `${SRCDIR}` is not expanded and no version is read,
// because none of those can be established from an artefact. What is recorded
// is what the directive said and where it said it.
type LinkedLibrary struct {
	// Name is the library as the directive names it: "icui18n" from
	// `-licui18n`, "CoreFoundation" from `-framework CoreFoundation`,
	// "pdf_oxide" from a `libpdf_oxide.a` operand.
	Name string `json:"name"`
	// Kind is LinkedLibraryExternal or LinkedLibrarySystem.
	Kind LinkedLibraryKind `json:"kind"`
	// Directive is the verbatim `#cgo` line the name was read from, so a
	// reader sees the build constraint that governs it without the tool having
	// to evaluate one.
	Directive string `json:"directive"`
	// File is the Go file the directive sits in, relative to the module root.
	File string `json:"file"`
}

// KindOf classifies a linked library name.
func KindOf(name string) LinkedLibraryKind {
	if systemLibraries[name] {
		return LinkedLibrarySystem
	}
	return LinkedLibraryExternal
}

// HasExternalLink reports whether any entry names a library from outside the
// module. It is the condition that separates "nothing native is linked" from
// "something native is linked that this artefact does not carry".
func HasExternalLink(libs []LinkedLibrary) bool {
	for _, l := range libs {
		if l.Kind == LinkedLibraryExternal {
			return true
		}
	}
	return false
}

// LinkedLibrariesIn returns the libraries the `#cgo LDFLAGS` and
// `#cgo pkg-config` lines of one preamble name, in the order the directives
// were read.
//
// Build constraints are not evaluated: a `#cgo linux,amd64 LDFLAGS:` line
// counts, and the verbatim directive carries its own constraint so a reader can
// see which build it governs. Evaluating them would need a target platform this
// tool does not have and does not want.
func LinkedLibrariesIn(file, preamble string) []LinkedLibrary {
	var out []LinkedLibrary
	for _, line := range strings.Split(preamble, "\n") {
		directive, verb, args, ok := cutDirective(line)
		if !ok {
			continue
		}
		for _, l := range namesIn(verb, splitFlags(args)) {
			l.Directive = directive
			l.File = file
			out = append(out, l)
		}
	}
	return out
}

// cutDirective reports whether line is a `#cgo` directive this context reads,
// returning the verbatim directive, the verb, and the operand text after the
// colon.
//
// The shape is cgo's own: `#cgo [constraint...] VERB: args`, split at the first
// colon, with the verb as the last field before it. Reading it any other way
// would either miss a constrained directive or misread a `-D` value containing
// a colon as a verb.
func cutDirective(line string) (directive, verb, args string, ok bool) {
	directive = strings.TrimRight(strings.TrimLeft(line, " \t"), " \t\r")
	rest, found := strings.CutPrefix(directive, CgoDirectivePrefix)
	if !found {
		return "", "", "", false
	}
	trimmed := strings.TrimLeft(rest, " \t")
	if len(trimmed) == len(rest) {
		// No separator, so this is `#cgofoo`, not a directive.
		return "", "", "", false
	}
	head, args, found := strings.Cut(trimmed, ":")
	if !found {
		return "", "", "", false
	}
	fields := strings.Fields(head)
	if len(fields) == 0 {
		return "", "", "", false
	}
	switch verb = fields[len(fields)-1]; verb {
	case LDFlagsVerb, PkgConfigVerb:
		return directive, verb, args, true
	default:
		return "", "", "", false
	}
}

// namesIn returns the libraries one directive's operands name, in order, with
// the kind each earns. Directive and File are filled in by the caller, which is
// what knows them.
func namesIn(verb string, tokens []string) []LinkedLibrary {
	if verb == PkgConfigVerb {
		return pkgConfigNames(tokens)
	}
	return linkerNames(tokens)
}

// linkerNames returns the libraries the LDFLAGS tokens name, in order.
//
// Three operand forms are read and nothing else: `-l<name>`, `-framework
// <name>`, and a `.a` archive path. A `-L` search path names no library, a
// `-Wl,` option is an instruction to the linker rather than a component, and a
// token a build system substitutes later names nothing this artefact can state.
func linkerNames(tokens []string) []LinkedLibrary {
	var out []LinkedLibrary
	add := func(name string) { out = append(out, LinkedLibrary{Name: name, Kind: KindOf(name)}) }
	for i := 0; i < len(tokens); i++ {
		tok := tokens[i]
		switch {
		case tok == "-framework":
			if i+1 < len(tokens) && tokens[i+1] != "" && !strings.HasPrefix(tokens[i+1], "-") {
				add(tokens[i+1])
				i++
			}
		case strings.HasPrefix(tok, "-l") && len(tok) > 2:
			add(tok[2:])
		case !strings.HasPrefix(tok, "-") && strings.HasSuffix(tok, ".a"):
			if name := archiveName(tok); name != "" {
				add(name)
			}
		}
	}
	return out
}

// pkgConfigNames returns the packages a `#cgo pkg-config` directive names, one
// entry each, in order.
//
// The name is recorded verbatim — `libxml-2.0`, `libmongocrypt` — and is never
// normalised towards a linker name. A pkg-config package is a different
// namespace: `libxml-2.0` resolves to `-lxml2` only because a .pc file on the
// building machine says so, and stripping a `lib` prefix or mapping the name
// here would state a fact no artefact carries.
//
// The kind is always external. pkg-config is never how the C runtime is linked,
// so classifying these names against the runtime list would only create a way
// for a real dependency to be dismissed as one.
func pkgConfigNames(tokens []string) []LinkedLibrary {
	var out []LinkedLibrary
	for _, tok := range tokens {
		// A pkg-config line may carry flags of its own; a flag names no package.
		if tok == "" || strings.HasPrefix(tok, "-") {
			continue
		}
		out = append(out, LinkedLibrary{Name: tok, Kind: LinkedLibraryExternal})
	}
	return out
}

// archiveName reads the library name off a static-archive operand:
// `${SRCDIR}/../target/release/libpdf_oxide.a` is the library pdf_oxide. The
// path is not resolved and `${SRCDIR}` is not expanded — only the name the
// directive itself spells out is read.
func archiveName(operand string) string {
	base := path.Base(strings.ReplaceAll(operand, `\`, "/"))
	base = strings.TrimSuffix(base, ".a")
	base = strings.TrimPrefix(base, "lib")
	return base
}

// splitFlags tokenises a flag string on whitespace, honouring the single and
// double quotes cgo itself honours so a quoted framework name survives as one
// operand. An unterminated quote yields what was read up to the end of the
// line rather than dropping the whole directive in silence.
func splitFlags(s string) []string {
	var (
		out   []string
		token strings.Builder
		quote rune
		open  bool
	)
	flush := func() {
		if open {
			out = append(out, token.String())
			token.Reset()
			open = false
		}
	}
	for _, r := range s {
		switch {
		case quote != 0:
			if r == quote {
				quote = 0
				continue
			}
			token.WriteRune(r)
		case r == '\'' || r == '"':
			quote = r
			open = true
		case r == ' ' || r == '\t' || r == '\r':
			flush()
		default:
			open = true
			token.WriteRune(r)
		}
	}
	flush()
	return out
}

// LinkedLibraryLess is the canonical ordering for LinkedLibrary: the library's
// name, the kind it was classified as, the file the directive sits in, then the
// directive itself. Every field is keyed, so two distinct entries always have a
// defined order and the sealed bytes never depend on the order the artefact was
// walked in.
func LinkedLibraryLess(a, b LinkedLibrary) bool {
	if a.Name != b.Name {
		return a.Name < b.Name
	}
	if a.Kind != b.Kind {
		return a.Kind < b.Kind
	}
	if a.File != b.File {
		return a.File < b.File
	}
	return a.Directive < b.Directive
}

// SortLinkedLibraries orders linked libraries by LinkedLibraryLess.
func SortLinkedLibraries(ls []LinkedLibrary) {
	sort.Slice(ls, func(i, j int) bool { return LinkedLibraryLess(ls[i], ls[j]) })
}
