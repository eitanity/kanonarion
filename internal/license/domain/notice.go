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
	Source             NoticeSource
	Name               string // display name; set for copied source, empty for modules
	SourcePaths        []string
	Coordinate         coordinate.ModuleCoordinate
	SPDX               string
	LicenseTexts       []NoticeLicenseFile       // root-level non-vendored license files, sorted by Path
	Copyrights         []string                  // verbatim copyright statements, deduped, sorted
	EmbeddedComponents []NoticeEmbeddedComponent // vendored/embedded third-party components
}

// NoticeLicenseFile holds the verbatim content of one license file.
type NoticeLicenseFile struct {
	Path    string
	Content string
}

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
			LicenseTexts: []NoticeLicenseFile{{Content: text}},
			Copyrights:   []string{a.Copyright},
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
		if entries[i].Coordinate.Path != entries[j].Coordinate.Path {
			return entries[i].Coordinate.Path < entries[j].Coordinate.Path
		}
		return entries[i].Coordinate.Version < entries[j].Coordinate.Version
	})
}
