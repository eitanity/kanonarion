package domain

import (
	"sort"

	fetchdomain "github.com/eitanity/kanonarion/internal/fetch/domain"
)

// NoticeEntry is one module's attribution record in a THIRD-PARTY-LICENSES document.
type NoticeEntry struct {
	Coordinate         fetchdomain.ModuleCoordinate
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
	Coordinate fetchdomain.ModuleCoordinate
	Reason     string
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
