package domain

import "strings"

// PURLTypeGeneric is the package-URL type a native component is named under.
//
// A package URL ("purl") is the short identity string an SBOM reader uses to
// look a component up: `pkg:<type>/<name>@<version>`. Every component
// kanonarion emitted before this was a Go module, under `pkg:golang/`. A C
// library compiled into a module's binary is not a Go module and is not
// published in any package registry, so it takes the purl type the
// specification reserves for exactly that: `generic`.
const PURLTypeGeneric = "generic"

// ComponentPURL is the package URL naming one identified native component.
//
// It is derived here, in the domain, rather than in the SBOM generator that
// first needed it, because two surfaces state this identity and they must state
// the same one: the SBOM lists the component, and a vulnerability read names
// the component whose advisories were not searched. A reader joining the two
// documents joins them on this string.
//
// It carries NO qualifiers. The purl specification offers `download_url` and
// `checksum`, and both would be assertions about an upstream release that
// kanonarion never fetched: what it measured is a declaration inside a module
// zip. The same rule already governs a module component's external references —
// an address assembled rather than measured is a claim this document's reader
// cannot check. The evidence that DID establish the component travels beside it
// instead, naming the file and the verbatim declaration.
//
// The empty string is returned for a component with no name or no version.
// Neither can be an identity, and a purl built from half of one would be a
// worse answer than none.
func ComponentPURL(c Component) string {
	if c.Name == "" || c.Version == "" {
		return ""
	}
	return "pkg:" + PURLTypeGeneric + "/" + purlEncode(strings.ToLower(c.Name)) + "@" + purlEncode(c.Version)
}

// purlEncode percent-encodes every byte a purl component may not carry
// literally, leaving the specification's unreserved set alone.
//
// Total by construction: a recipe names the library and a version is read
// verbatim out of C source, so neither is drawn from a fixed vocabulary this
// function could assume. A byte it does not recognise is escaped rather than
// dropped or passed through, so the result is always a well-formed purl.
func purlEncode(s string) string {
	const hex = "0123456789ABCDEF"
	var b strings.Builder
	b.Grow(len(s))
	for i := range len(s) {
		switch c := s[i]; {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9',
			c == '-', c == '.', c == '_', c == '~':
			b.WriteByte(c)
		default:
			b.WriteByte('%')
			b.WriteByte(hex[c>>4])
			b.WriteByte(hex[c&0x0f])
		}
	}
	return b.String()
}
