// Package snippetscan walks a module's first-party Go source for SPDX snippet
// blocks marking third-party code transcribed into it.
package snippetscan

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	licensedomain "github.com/eitanity/kanonarion/internal/license/domain"
)

// generatedMarker is the Go convention for machine-generated files. Generated
// files are excluded: their attribution belongs to whatever generated them, and
// re-generation would silently drop or duplicate a hand-placed snippet tag.
const generatedMarker = "// Code generated"

// Scanner reads first-party Go source from a directory tree.
type Scanner struct {
	root string
}

// New returns a Scanner rooted at a module directory.
func New(root string) *Scanner { return &Scanner{root: root} }

// Scan returns every SPDX snippet attribution found under the root, with paths
// relative to it. A malformed block anywhere in the tree fails the whole scan:
// the caller is building an attribution document, and a partial scan would
// publish a document that looks complete.
//
// The walk runs through os.Root, so every read is confined to the root by the
// kernel. A symlink planted mid-walk cannot redirect a read outside the module
// being attributed.
func (s *Scanner) Scan() ([]licensedomain.SnippetAttribution, error) {
	root, err := os.OpenRoot(s.root)
	if err != nil {
		return nil, fmt.Errorf("opening module root %s: %w", s.root, err)
	}
	defer func() { _ = root.Close() }()

	var out []licensedomain.SnippetAttribution
	// fs.WalkDir over root.FS() yields slash-separated paths relative to the
	// root — exactly the form the attribution records report.
	err = fs.WalkDir(root.FS(), ".", func(rel string, d fs.DirEntry, werr error) error {
		if werr != nil {
			return fmt.Errorf("walking %s: %w", rel, werr)
		}
		if d.IsDir() {
			if skipDir(rel, d.Name()) {
				return fs.SkipDir
			}
			return nil
		}
		if !isFirstPartyGoFile(d.Name()) {
			return nil
		}

		content, rerr := root.ReadFile(filepath.FromSlash(rel))
		if rerr != nil {
			return fmt.Errorf("reading %s: %w", rel, rerr)
		}
		if isGenerated(content) {
			return nil
		}

		atts, perr := licensedomain.ParseSnippets(rel, content)
		if perr != nil {
			return fmt.Errorf("parsing snippets in %s: %w", rel, perr)
		}
		out = append(out, atts...)
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("walking %s: %w", s.root, err)
	}
	return out, nil
}

// isGenerated reports whether a file carries the Go generated-code marker on
// any line. The marker is not always first: build tags and a licence header
// commonly precede it.
func isGenerated(content []byte) bool {
	s := string(content)
	return strings.HasPrefix(s, generatedMarker) || strings.Contains(s, "\n"+generatedMarker)
}

// skipDir excludes directories that are not first-party source.
//
// vendor/ holds copies of module dependencies, which module licence extraction
// already covers. testdata/ holds fixtures — including, in this package's own
// tests, deliberately malformed snippet blocks that must not fail a real scan.
// Dot-directories hold VCS and tool state.
func skipDir(rel, name string) bool {
	if rel == "." {
		return false
	}
	switch name {
	case "vendor", "testdata", "node_modules":
		return true
	}
	return strings.HasPrefix(name, ".")
}

// isFirstPartyGoFile reports whether a filename is Go source eligible for
// scanning. Test files are excluded: they are not distributed in the binary the
// NOTICE describes.
func isFirstPartyGoFile(name string) bool {
	return strings.HasSuffix(name, ".go") && !strings.HasSuffix(name, "_test.go")
}
