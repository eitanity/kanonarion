package domain

import (
	"bytes"
	"strings"
)

// RecipeCatalogueVersion is the revision of the recipe set below. Bump it when
// a recipe is added, removed or changed: a stored record is keyed on the
// fingerprint that folds it in, so a module recorded as present-unidentified is
// re-measured against the new catalogue rather than answering from the
// generation that had no recipe for it.
const RecipeCatalogueVersion = "1"

// Recipe identifies one third-party native library from a declaration in its
// own source.
//
// Identification is per-library and declaration-based by decision, not by a
// general C parser and not by inference from a file name or path. An
// amalgamated library states its own version in a macro it publishes as part of
// its API; that macro is the only thing read here, and its value is recorded
// verbatim. A library with no such declaration is not guessed at — it is
// recorded as present and unidentified.
type Recipe struct {
	// Component is the library's name as a reader knows it, not a module path.
	Component string
	// Macro is the object-like macro whose string literal carries the version,
	// e.g. SQLITE_VERSION in `#define SQLITE_VERSION "3.38.0"`.
	Macro string
}

// Recipes returns the catalogue in a fixed order.
//
// SQLite is the first and, today, only entry: it is the library Go modules
// most often amalgamate into their own zip, `github.com/mattn/go-sqlite3`
// carries the whole 8 MB of it as `sqlite3-binding.c`, and its published
// SQLITE_VERSION macro is exactly the named declaration this design is built
// around.
func Recipes() []Recipe {
	return []Recipe{
		{Component: "SQLite", Macro: "SQLITE_VERSION"},
	}
}

// matchMacro returns every distinct string literal content assigned to macro by
// an object-like `#define` in src, together with the verbatim declaration line
// each was read from.
//
// It reads one declaration form and nothing else. That is the point: a general
// C parser would have to model conditional compilation, macro expansion and
// include resolution to say anything more, and every one of those is a place to
// be confidently wrong. A line that does not have the exact shape
// `#define <macro> "<value>"` is not a match, so nothing is inferred from a
// near miss.
func matchMacro(macro string, src []byte) map[string]string {
	out := map[string]string{}
	for line := range bytes.Lines(src) {
		value, decl, ok := parseDefineString(macro, line)
		if !ok {
			continue
		}
		if _, seen := out[value]; !seen {
			out[value] = decl
		}
	}
	return out
}

// parseDefineString reports whether line is `#define <macro> "<value>"`,
// returning the value and the trimmed declaration line it was read from.
func parseDefineString(macro string, line []byte) (value, declaration string, ok bool) {
	rest := strings.TrimRight(strings.TrimLeft(string(line), " \t"), " \t\r\n")
	decl := rest

	rest, found := strings.CutPrefix(rest, "#")
	if !found {
		return "", "", false
	}
	rest = strings.TrimLeft(rest, " \t")
	rest, found = strings.CutPrefix(rest, "define")
	if !found {
		return "", "", false
	}
	// At least one space must separate `define` from the macro name, or
	// `defineSQLITE_VERSION` would read as a definition of it.
	rest, found = cutSpace(rest)
	if !found {
		return "", "", false
	}
	rest, found = strings.CutPrefix(rest, macro)
	if !found {
		return "", "", false
	}
	// The macro name must end here. Without this check SQLITE_VERSION also
	// matches SQLITE_VERSION_NUMBER, whose value is not a version string.
	rest, found = cutSpace(rest)
	if !found {
		return "", "", false
	}
	rest, found = strings.CutPrefix(rest, `"`)
	if !found {
		return "", "", false
	}
	end := strings.IndexByte(rest, '"')
	if end <= 0 {
		return "", "", false
	}
	// Only a comment may follow the closing quote. A concatenation, a line
	// continuation or a second literal means the line is not a plain string
	// definition, and reading a version out of it would be a guess.
	if tail := strings.TrimLeft(rest[end+1:], " \t"); tail != "" &&
		!strings.HasPrefix(tail, "/*") && !strings.HasPrefix(tail, "//") {
		return "", "", false
	}
	return rest[:end], decl, true
}

// cutSpace strips leading spaces and tabs, reporting false when there were
// none. It is what makes a token boundary required rather than assumed.
func cutSpace(s string) (string, bool) {
	trimmed := strings.TrimLeft(s, " \t")
	return trimmed, len(trimmed) != len(s)
}
