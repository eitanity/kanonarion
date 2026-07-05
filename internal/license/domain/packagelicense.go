package domain

import (
	"sort"
	"strings"
)

// DerivePackageLicenses extracts license attributions for non-root,
// non-vendored sub-package directories. Each directory that owns its own
// license file gets one PackageLicense entry; the highest-confidence file
// in that directory wins when multiple files are present.
//
// Packages that do not carry their own license file are absent from the
// result — they implicitly inherit the module root license. Notice files
// (NOTICE, NOTICE.txt, NOTICE.md) are excluded.
//
// Like EffectiveLicenseSet, PackageLicenses is derived from LicenseFiles
// and is not included in the content hash — recompute it after
// deserialisation rather than storing it separately.
func DerivePackageLicenses(entries []LicenseFileEntry) []PackageLicense {
	// best tracks the highest-confidence entry seen for each package dir.
	type candidate struct {
		entry LicenseFileEntry
		dir   string
	}
	best := make(map[string]candidate) // dir → best candidate

	for _, e := range entries {
		if e.IsVendored {
			continue
		}
		if exprIsRootLevel(e.Path) {
			continue
		}
		if exprIsNoticeName(e.Path) {
			continue
		}
		dir := packageDir(e.Path)
		if cur, ok := best[dir]; !ok || e.Confidence > cur.entry.Confidence {
			best[dir] = candidate{entry: e, dir: dir}
		}
	}

	if len(best) == 0 {
		return nil
	}

	dirs := make([]string, 0, len(best))
	for d := range best {
		dirs = append(dirs, d)
	}
	sort.Strings(dirs)

	result := make([]PackageLicense, 0, len(dirs))
	for _, d := range dirs {
		c := best[d]
		result = append(result, PackageLicense{
			PackagePath: d,
			SPDX:        c.entry.SPDX,
			Confidence:  c.entry.Confidence,
			SourceFile:  c.entry.Path,
		})
	}
	return result
}

// packageDir returns the directory portion of a module-relative file path.
// e.g. "internal/foo/LICENSE" → "internal/foo"
func packageDir(relPath string) string {
	if idx := strings.LastIndex(relPath, "/"); idx >= 0 {
		return relPath[:idx]
	}
	return relPath
}
