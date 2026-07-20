package domain

import (
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strings"

	fetchdomain "github.com/eitanity/kanonarion/internal/fetch/domain"
)

// Third-party code is sometimes transcribed into first-party source rather
// than arriving as a go.mod dependency. Such code carries its licence in a
// comment header, so it is invisible to module-based licence extraction and
// would be silently omitted from THIRD-PARTY-LICENSES.
//
// The detection contract is exactly the REUSE 3.0 / SPDX snippet tags below —
// no free-text heuristics. A block that opts in must be complete: a partially
// tagged block is an error, never a partially rendered attribution.
const (
	snippetBeginTag = "SPDX-SnippetBegin"
	snippetEndTag   = "SPDX-SnippetEnd"

	tagLicenseID     = "SPDX-License-Identifier:"
	tagCopyrightText = "SPDX-SnippetCopyrightText:"
	tagComment       = "SPDX-SnippetComment:"
	tagName          = "SPDX-SnippetName:"
)

// ErrMalformedSnippet is the sentinel for every snippet-block defect: a
// missing required tag, an unterminated block, a compound licence expression,
// or a comment with no origin coordinate.
var ErrMalformedSnippet = errors.New("malformed SPDX snippet block")

// SnippetAttribution is one block of third-party code copied into first-party
// source, recovered from its SPDX snippet tags.
type SnippetAttribution struct {
	// Name is the display name from SPDX-SnippetName, defaulting to the
	// origin coordinate when the tag is absent.
	Name string
	// Coordinate is the canonical origin extracted from SPDX-SnippetComment.
	Coordinate fetchdomain.ModuleCoordinate
	// SPDX is a single SPDX identifier; compound expressions are rejected.
	SPDX string
	// Copyright is the verbatim notice from SPDX-SnippetCopyrightText.
	Copyright string
	// SourcePath is the first-party file the block was found in, relative to
	// the module root. Reported in errors so a defect is locatable.
	SourcePath string
	// StartLine is the 1-based line of the SPDX-SnippetBegin tag.
	StartLine int
}

// coordinateInComment finds a "module/path@version" token inside free text.
// The character class stops at whitespace and at punctuation that commonly
// trails a coordinate in prose (comma, semicolon), so "…capslock@v0.3.2,
// interesting/interesting.cm" yields the coordinate and not the prose after
// it. The token is then validated by fetchdomain.ParseModuleCoordinate, so
// this regex only has to find a candidate, not decide it is well-formed.
var coordinateInComment = regexp.MustCompile(`[A-Za-z0-9._~/-]+@v[0-9][A-Za-z0-9.+\-]*`)

// ParseSnippets recovers every SPDX snippet block in one file's content.
// sourcePath is used only for error messages and for the returned records.
//
// A file with no snippet tags yields no records and no error — the common
// case. A file that opens a block and fails to complete it correctly is an
// error: opting in to the contract means honouring it.
func ParseSnippets(sourcePath string, content []byte) ([]SnippetAttribution, error) {
	lines := strings.Split(string(content), "\n")

	var out []SnippetAttribution
	for i := 0; i < len(lines); i++ {
		if commentTag(lines[i]) != snippetBeginTag {
			continue
		}
		att, next, err := parseSnippetBlock(sourcePath, lines, i)
		if err != nil {
			return nil, err
		}
		out = append(out, att)
		i = next
	}
	return out, nil
}

// parseSnippetBlock reads one block starting at the SPDX-SnippetBegin on
// lines[start], returning the record and the index of the SPDX-SnippetEnd.
func parseSnippetBlock(sourcePath string, lines []string, start int) (SnippetAttribution, int, error) {
	att := SnippetAttribution{SourcePath: sourcePath, StartLine: start + 1}
	fail := func(format string, args ...any) (SnippetAttribution, int, error) {
		return SnippetAttribution{}, 0, fmt.Errorf("%w at %s:%d: %s",
			ErrMalformedSnippet, sourcePath, start+1, fmt.Sprintf(format, args...))
	}

	var (
		spdx, copyright, comment, name string
		end                            = -1
	)
	for i := start + 1; i < len(lines); i++ {
		tag := commentTag(lines[i])
		switch {
		case tag == snippetEndTag:
			end = i
		case tag == snippetBeginTag:
			return fail("nested %s before %s", snippetBeginTag, snippetEndTag)
		case strings.HasPrefix(tag, tagLicenseID):
			spdx = strings.TrimSpace(strings.TrimPrefix(tag, tagLicenseID))
		case strings.HasPrefix(tag, tagCopyrightText):
			copyright = strings.TrimSpace(strings.TrimPrefix(tag, tagCopyrightText))
		case strings.HasPrefix(tag, tagComment):
			comment = strings.TrimSpace(strings.TrimPrefix(tag, tagComment))
		case strings.HasPrefix(tag, tagName):
			name = strings.TrimSpace(strings.TrimPrefix(tag, tagName))
		}
		if end >= 0 {
			break
		}
	}
	if end < 0 {
		return fail("unterminated block: no %s", snippetEndTag)
	}

	if spdx == "" {
		return fail("missing required %s", tagLicenseID)
	}
	if isCompoundExpression(spdx) {
		return fail("compound licence expression %q: only a single SPDX identifier is supported", spdx)
	}
	if copyright == "" {
		return fail("missing required %s", tagCopyrightText)
	}
	if comment == "" {
		return fail("missing required %s", tagComment)
	}

	coordStr := coordinateInComment.FindString(comment)
	if coordStr == "" {
		return fail("%s contains no module@version origin coordinate: %q", tagComment, comment)
	}
	coord, err := fetchdomain.ParseModuleCoordinate(coordStr)
	if err != nil {
		return fail("invalid origin coordinate %q: %v", coordStr, err)
	}

	att.SPDX = spdx
	att.Copyright = copyright
	att.Coordinate = coord
	att.Name = name
	if att.Name == "" {
		att.Name = coord.String()
	}
	return att, end, nil
}

// commentTag returns the tag text of a line-comment, or "" if the line is not
// a line-comment. It tolerates leading indentation and the blank comment lines
// that separate prose from tags inside a block.
func commentTag(line string) string {
	t := strings.TrimSpace(line)
	if !strings.HasPrefix(t, "//") {
		return ""
	}
	return strings.TrimSpace(strings.TrimPrefix(t, "//"))
}

// isCompoundExpression reports whether an SPDX string is an expression rather
// than a bare identifier. Compound expressions are out of scope: rendering one
// correctly means resolving several licence texts and their interaction, which
// the single-text lookup cannot express.
func isCompoundExpression(spdx string) bool {
	if strings.ContainsAny(spdx, "()") {
		return true
	}
	for _, f := range strings.Fields(spdx) {
		switch strings.ToUpper(f) {
		case "AND", "OR", "WITH":
			return true
		}
	}
	return len(strings.Fields(spdx)) > 1
}

// DedupeSnippets collapses attributions sharing an origin coordinate and SPDX
// identifier into one record, and sorts the result by coordinate then name.
//
// Two snippets citing the same coordinate with *different* licences is a hard
// error: one of the two attributions would have to be dropped, and there is no
// safe way to choose which.
func DedupeSnippets(atts []SnippetAttribution) ([]SnippetAttribution, error) {
	bySPDX := make(map[string]SnippetAttribution, len(atts))
	seen := make(map[string]SnippetAttribution, len(atts))
	for _, a := range atts {
		coord := a.Coordinate.String()
		if prev, ok := seen[coord]; ok && prev.SPDX != a.SPDX {
			return nil, fmt.Errorf("%w: conflicting licences for origin %s: %s at %s:%d and %s at %s:%d",
				ErrMalformedSnippet, coord,
				prev.SPDX, prev.SourcePath, prev.StartLine,
				a.SPDX, a.SourcePath, a.StartLine)
		}
		seen[coord] = a
		if _, dup := bySPDX[coord+" "+a.SPDX]; dup {
			continue
		}
		bySPDX[coord+" "+a.SPDX] = a
	}

	out := make([]SnippetAttribution, 0, len(bySPDX))
	for _, a := range bySPDX {
		out = append(out, a)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Coordinate.Path != out[j].Coordinate.Path {
			return out[i].Coordinate.Path < out[j].Coordinate.Path
		}
		if out[i].Coordinate.Version != out[j].Coordinate.Version {
			return out[i].Coordinate.Version < out[j].Coordinate.Version
		}
		return out[i].Name < out[j].Name
	})
	return out, nil
}
