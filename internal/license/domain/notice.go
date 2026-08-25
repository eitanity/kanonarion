package domain

import (
	"fmt"
	"sort"

	"github.com/eitanity/kanonarion/internal/coordinate"
)

// NoticeSource records where an attribution record came from, so the document
// can distinguish a linked module dependency from third-party code transcribed
// into first-party source.
type NoticeSource string

const (
	// NoticeSourceModule is a Go module dependency linked into the target.
	NoticeSourceModule NoticeSource = "module"
	// NoticeSourceCopied is third-party code copied into first-party source,
	// recovered from its SPDX snippet tags.
	NoticeSourceCopied NoticeSource = "copied-source"
)

// NoticeEntry is one module's attribution record in a THIRD-PARTY-LICENSES document.
type NoticeEntry struct {
	// Source distinguishes a module dependency from copied source. Read it
	// through EffectiveSource, which treats the empty zero value as a module
	// so existing module construction sites need no change.
	Source      NoticeSource
	Name        string // display name; set for copied source, empty for modules
	SourcePaths []string
	Coordinate  coordinate.ModuleCoordinate
	SPDX        string
	// Expression is the module's whole licence expression, e.g.
	// "Apache-2.0 AND MIT". SPDX names only the primary, which understates a
	// module governed by more than one grant, and the document is read by a
	// person building an obligations list. It is set only where it says
	// something SPDX does not; see writeNoticeDocument.
	Expression   string
	LicenseTexts []NoticeLicenseFile // root-level non-vendored license files, sorted by Path
	Copyrights   []string            // verbatim copyright statements, deduped, sorted
	// Declaration is the operator's recorded copyright for this module, when
	// one is configured; nil otherwise. It is carried alongside Copyrights, not
	// merged into it, because the document must be able to say which lines were
	// measured from the archive and which a person asserted.
	Declaration        *CopyrightDeclaration
	EmbeddedComponents []NoticeEmbeddedComponent // vendored/embedded third-party components
}

// DeclarationAttributes reports whether the recorded declaration is what this
// entry attributes, as opposed to corroborating an extracted notice.
//
// The test is on the extracted lines that actually reached the entry, not on the
// record's copyright status: an extracted line present is the measurement, and a
// measurement always wins. Only where extraction yielded nothing does the
// operator's assertion become the attribution.
func (e NoticeEntry) DeclarationAttributes() bool {
	return e.Declaration != nil && len(e.Copyrights) == 0
}

// NoticeLicenseFile holds one license file's attribution, and says what the
// pipeline was able to identify in it. The document must never present bytes
// under an identifier they do not carry, so every field a renderer needs to
// label the block honestly lives here rather than being taken from the
// module's primary identifier.
type NoticeLicenseFile struct {
	Path string
	// Content is the verbatim file content, reproduced when the file
	// classified as a licence or is a NOTICE-style attribution file. It is
	// empty when Classification is ClassificationUnclassified: bytes the
	// pipeline could not identify are recorded, not printed.
	Content string
	// SPDX is THIS FILE'S own identifier, not the module's. Empty when the
	// file did not classify.
	SPDX           string
	Classification NoticeClassification
	FileSize       int64
	FileHash       string // "sha256:<hex>"
	// LowConfidenceSPDX and LowConfidenceCoverage carry a recognisable but
	// sub-threshold licence fragment, so an unclassified file reads as
	// "licence-like, not identified" rather than as bare absence.
	LowConfidenceSPDX     string
	LowConfidenceCoverage float64
}

// NoticeClassification says what the licence detector made of a file, so the
// document can label the block with the truth rather than with the module's
// identifier.
type NoticeClassification int

const (
	// ClassificationLicence means the detector identified a licence in the
	// file; SPDX names it and the text is reproduced verbatim.
	ClassificationLicence NoticeClassification = iota
	// ClassificationNotice means the file is a NOTICE-style attribution
	// document rather than a licence grant. It carries no identifier of its
	// own and is reproduced verbatim regardless, because Apache-2.0 section
	// 4(d) requires a NOTICE file to be redistributed with the work.
	ClassificationNotice
	// ClassificationUnclassified means the detector identified no licence in
	// the file. The document records the file — path, size, hash, and any
	// low-confidence fragment — and does NOT reproduce its content: bytes with
	// no identified grant are not a grant, and printing them under a licence
	// heading is how scanner fixture markup reached the document.
	ClassificationUnclassified
)

// NoticeEmbeddedComponent holds attribution data for a vendored/embedded
// third-party component within a module.
type NoticeEmbeddedComponent struct {
	PathPrefix   string              // directory prefix relative to module root (e.g. "vendor/github.com/google/snappy")
	SPDXs        []string            // distinct SPDX identifiers for this component (sorted)
	LicenseTexts []NoticeLicenseFile // verbatim license file content for this component, sorted by Path
}

// ReviewItem records a module that cannot be automatically included in the
// THIRD-PARTY-LICENSES document and requires human review.
type ReviewItem struct {
	Coordinate coordinate.ModuleCoordinate
	Reason     string
	// MissingCopyright is true when the module was held back solely because no
	// copyright notice could be extracted — the one review class an operator can
	// clear by recording what they read upstream. Carried as a field rather than
	// recovered by matching Reason, so the remedy the caller prints is keyed to
	// the gate that fired.
	MissingCopyright bool
}

// EffectiveSource returns the entry's source, treating the empty zero value as
// NoticeSourceModule.
func (e NoticeEntry) EffectiveSource() NoticeSource {
	if e.Source == "" {
		return NoticeSourceModule
	}
	return e.Source
}

// NoticeEntriesFromSnippets converts deduplicated snippet attributions into
// notice entries, resolving each SPDX identifier against the embedded licence
// text table. An identifier the table does not cover is a hard error: a record
// without its licence text is a partial attribution, which is worse than a
// loud failure because it looks complete.
//
// Snippets citing the same coordinate and licence from several files collapse
// to one entry listing every source path.
func NoticeEntriesFromSnippets(atts []SnippetAttribution) ([]NoticeEntry, error) {
	deduped, err := DedupeSnippets(atts)
	if err != nil {
		return nil, err
	}

	// Group the original attributions by the deduped key so every contributing
	// source path is listed, not just the first one encountered.
	paths := make(map[string][]string, len(deduped))
	for _, a := range atts {
		key := a.Coordinate.String() + " " + a.SPDX
		paths[key] = append(paths[key], a.SourcePath)
	}

	out := make([]NoticeEntry, 0, len(deduped))
	for _, a := range deduped {
		text, terr := SPDXLicenseText(a.SPDX)
		if terr != nil {
			return nil, fmt.Errorf("resolving licence text for %s (%s:%d): %w",
				a.Coordinate, a.SourcePath, a.StartLine, terr)
		}
		srcPaths := dedupeSorted(paths[a.Coordinate.String()+" "+a.SPDX])
		out = append(out, NoticeEntry{
			Source:      NoticeSourceCopied,
			Name:        a.Name,
			SourcePaths: srcPaths,
			Coordinate:  a.Coordinate,
			SPDX:        a.SPDX,
			// No Path: the text comes from the embedded SPDX table, not from a
			// file in a module archive, so there is no path to cite.
			LicenseTexts: []NoticeLicenseFile{{
				Content:        text,
				SPDX:           a.SPDX,
				Classification: ClassificationLicence,
			}},
			Copyrights: []string{a.Copyright},
		})
	}
	return out, nil
}

func dedupeSorted(in []string) []string {
	seen := make(map[string]struct{}, len(in))
	out := make([]string, 0, len(in))
	for _, s := range in {
		if _, dup := seen[s]; dup {
			continue
		}
		seen[s] = struct{}{}
		out = append(out, s)
	}
	sort.Strings(out)
	return out
}

// SortNoticeEntries sorts entries by module path, then version.
func SortNoticeEntries(entries []NoticeEntry) {
	sort.Slice(entries, func(i, j int) bool {
		if entries[i].Coordinate.Path() != entries[j].Coordinate.Path() {
			return entries[i].Coordinate.Path() < entries[j].Coordinate.Path()
		}
		return entries[i].Coordinate.Version() < entries[j].Coordinate.Version()
	})
}
