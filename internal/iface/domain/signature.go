package domain

import "strings"

// NormalizeSignature returns the canonical form of a declaration signature: the
// go/printer output with any leading doc-comment block removed. go/printer
// includes the doc-comment block verbatim when printing a declaration node, but
// the Signature field of TypeDecl, MethodDecl, and FuncDecl is defined as
// canonical signature text only. This function defines what "canonical" means
// and is the single authority for that invariant.
//
// Only leading line comments ("//") are stripped; block comments ("/* */") are
// left intact, and surrounding whitespace is trimmed.
func NormalizeSignature(s string) string {
	lines := strings.Split(s, "\n")
	for len(lines) > 0 && strings.HasPrefix(strings.TrimSpace(lines[0]), "//") {
		lines = lines[1:]
	}
	return strings.TrimSpace(strings.Join(lines, "\n"))
}
