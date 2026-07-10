package domain

import (
	"regexp"
	"sort"
	"strings"
)

// CopyrightStatus describes whether copyright extraction has been performed
// and whether any statements were found. Per, NotAnalysed and
// NoneFound MUST remain distinct.
type CopyrightStatus int

const (
	// CopyrightStatusNotAnalysed is the zero value; extraction has not run.
	CopyrightStatusNotAnalysed CopyrightStatus = iota
	// CopyrightStatusFound means extraction ran and at least one copyright
	// statement was identified.
	CopyrightStatusFound
	// CopyrightStatusNoneFound means extraction ran but no copyright lines
	// were identified. Distinct from NotAnalysed per.
	CopyrightStatusNoneFound
	// CopyrightStatusExtractionFailed means extraction could not complete.
	CopyrightStatusExtractionFailed
)

// String returns the human-readable name of the status.
func (s CopyrightStatus) String() string {
	switch s {
	case CopyrightStatusFound:
		return "found"
	case CopyrightStatusNoneFound:
		return "none_found"
	case CopyrightStatusExtractionFailed:
		return "extraction_failed"
	default:
		return "not_analysed"
	}
}

// CopyrightStatement is a single copyright notice identified in a file.
// Verbatim is the primary fact required for correct attribution; Holders and
// Years are best-effort secondary fields parsed from the verbatim text.
type CopyrightStatement struct {
	Verbatim string   // exact line from the source file, trimmed
	Holders  []string // best-effort; may be empty
	Years    string   // best-effort year or year-range (e.g. "2020" or "2019-2021")
	Source   string   // relative path of the file this statement was found in
}

var (
	// copyrightLineRe matches lines that START with a copyright declaration,
	// after stripping leading whitespace and common comment markers (/, *, #, !).
	// Anchoring to the start prevents matching BSD/MIT boilerplate clauses where
	// "copyright" appears mid-sentence (e.g. "IN NO EVENT SHALL THE COPYRIGHT
	// HOLDER") or at the end of a redistribution condition.
	copyrightLineRe = regexp.MustCompile(`(?i)^[-\s*/!#]*(?:copyright|©)`)

	// copyrightBoilerplateRe filters lines where "copyright" is immediately
	// followed by a reference noun rather than a year or holder name. These are
	// license-clause references (e.g. "copyright notice, this list of conditions",
	// "copyright holder") not copyright declarations.
	copyrightBoilerplateRe = regexp.MustCompile(`(?i)^[-\s*/!#]*copyright\s+(?:notice|holder|holders|owner|owners|law|laws)\b`)

	// commentPrefixRe strips the leading whitespace and comment-marker characters
	// so we can check the capitalisation of the keyword that follows.
	commentPrefixRe = regexp.MustCompile(`^[-\s*/!#]*`)

	// yearRe extracts a year or year-range (with hyphen or en-dash).
	yearRe = regexp.MustCompile(`\b(\d{4}(?:\s*[-–]\s*\d{4})?)\b`)

	// copyrightPrefixRe strips the "Copyright (c)?" or "©" prefix for the
	// no-year fallback holder extraction.
	copyrightPrefixRe = regexp.MustCompile(`(?i)^\s*(?:copyright\s*(?:\(c\)|©)?\s*|©\s*|\(c\)\s*)`)

	// trailingConjunctionRe removes trailing prose conjunctions (e.g. " or",
	// " and") that appear in multi-attribution blocks like musl libc's math
	// copyright notice, where consecutive lines are joined by such words.
	trailingConjunctionRe = regexp.MustCompile(`(?i)\s+(?:or|and)$`)

	// placeholderRe matches an unfilled template placeholder token — a
	// bracketed span (angle <>, square [], or curly {}) whose inner text is
	// bare words with none of the punctuation a URL or email carries
	// (@, :, /, .). License "how to apply" scaffolds ship these literally and
	// they are never a real holder:
	//   - GPL/AGPL/LGPL:      "Copyright (C) <year>  <name of author>"
	//   - Apache-2.0 appendix: "Copyright [yyyy] [name of copyright owner]"
	//   - MIT/ISC/BSD:         "Copyright (c) [year] [fullname]"
	//   - curly-brace variants: "Copyright {yyyy} {name of copyright owner}"
	// A URL or email inside brackets (e.g. "<https://fsf.org/>",
	// "<me@example.com>") carries excluded punctuation and is spared, so a real
	// holder that lists its homepage or contact still extracts.
	placeholderRe = regexp.MustCompile(`<[^<>@:/.]+>|\[[^\[\]@:/.]+\]|\{[^{}@:/.]+\}`)

	// fsfLicenseCopyrightRe matches the Free Software Foundation's copyright on
	// the GPL/AGPL/LGPL license *document* itself (e.g. "Copyright (C) 2007
	// Free Software Foundation, Inc."). That is boilerplate about the licence
	// text, not a fact about the licensed work, so it is dropped.
	fsfLicenseCopyrightRe = regexp.MustCompile(`(?i)\bfree software foundation\b`)
)

// ExtractCopyright scans content line-by-line for copyright notices and
// returns one CopyrightStatement per matched line. Statements are sorted
// lexically by Verbatim. source is the relative file path set on each
// statement. Returns nil when no copyright lines are found.
func ExtractCopyright(source string, content []byte) []CopyrightStatement {
	var stmts []CopyrightStatement
	for _, raw := range strings.Split(string(content), "\n") {
		line := strings.TrimSpace(raw)
		if line == "" || !copyrightLineRe.MatchString(line) || copyrightBoilerplateRe.MatchString(line) {
			continue
		}
		// Real declarations start with capital "Copyright", "©", or "(c)".
		// Lowercase "copyright" is almost always a prose reference in license
		// body text (e.g. "copyright staring in 2011 when…", BSD line-wrap
		// "copyright notice, this list of conditions…").
		stripped := trailingConjunctionRe.ReplaceAllString(commentPrefixRe.ReplaceAllString(line, ""), "")
		if !strings.HasPrefix(stripped, "©") &&
			!strings.HasPrefix(stripped, "Copyright") &&
			!strings.HasPrefix(stripped, "(c)") &&
			!strings.HasPrefix(stripped, "(C)") {
			continue
		}
		// Drop template scaffold carrying unfilled placeholder tokens and the
		// license document's own self-copyright: neither states who holds
		// copyright over the licensed work.
		if placeholderRe.MatchString(stripped) || fsfLicenseCopyrightRe.MatchString(stripped) {
			continue
		}
		stmt := CopyrightStatement{
			Verbatim: stripped,
			Source:   source,
		}
		allLocs := yearRe.FindAllStringIndex(stripped, -1)
		if len(allLocs) > 0 {
			// Use first year match for the Years field.
			stmt.Years = normaliseYear(yearRe.FindString(stripped))
			// Extract holder as text after the last year match.
			lastEnd := allLocs[len(allLocs)-1][1]
			if holder := strings.TrimSpace(strings.TrimLeft(stripped[lastEnd:], " \t,")); holder != "" {
				holder = strings.TrimRight(holder, ".,;:")
				holder = strings.TrimSpace(holder)
				if holder != "" {
					stmt.Holders = []string{holder}
				}
			}
		} else {
			// No year; strip the copyright keyword prefix and use the rest.
			holder := copyrightPrefixRe.ReplaceAllString(stripped, "")
			holder = strings.TrimRight(strings.TrimSpace(holder), ".,;:")
			if holder != "" {
				stmt.Holders = []string{holder}
			}
		}
		stmts = append(stmts, stmt)
	}
	sort.Slice(stmts, func(i, j int) bool {
		return stmts[i].Verbatim < stmts[j].Verbatim
	})
	return stmts
}

// normaliseYear normalises the separator in a year range to a plain hyphen and
// collapses surrounding spaces (e.g. "2019 – 2021" → "2019-2021").
func normaliseYear(s string) string {
	s = strings.ReplaceAll(s, "–", "-")
	parts := strings.SplitN(s, "-", 2)
	if len(parts) == 2 {
		return strings.TrimSpace(parts[0]) + "-" + strings.TrimSpace(parts[1])
	}
	return strings.TrimSpace(s)
}

// MatchesCopyrightHolder reports whether any copyright statement across entries
// contains pattern as a case-insensitive substring in either its Verbatim text
// or any of its parsed Holders. Used to identify internally-owned modules by
// organisation name (e.g. "Acme Corp").
func MatchesCopyrightHolder(entries []LicenseFileEntry, pattern string) bool {
	if pattern == "" {
		return false
	}
	lower := strings.ToLower(pattern)
	for _, e := range entries {
		for _, stmt := range e.CopyrightStatements {
			if strings.Contains(strings.ToLower(stmt.Verbatim), lower) {
				return true
			}
			for _, h := range stmt.Holders {
				if strings.Contains(strings.ToLower(h), lower) {
					return true
				}
			}
		}
	}
	return false
}
