package domain

import (
	"bytes"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/eitanity/kanonarion/internal/coordinate"

	"golang.org/x/mod/module"
	modzip "golang.org/x/mod/zip"
)

// ModuleZipHasher computes the dirhash h1 of a module ZIP. It is implemented by
// the shared ziparchive adapter and injected into Verifier so the domain holds
// no archive/zip dependency — only the pure verification rule.
type ModuleZipHasher interface {
	HashModuleZip(data []byte) (string, error)
}

// Verifier is a domain service for cross-checking module artefacts.
// Its rules are pure: no persistent I/O, no network access. Archive parsing is
// delegated to the injected ModuleZipHasher.
type Verifier struct {
	hasher ModuleZipHasher
}

// NewVerifier constructs a Verifier backed by hasher.
func NewVerifier(hasher ModuleZipHasher) Verifier {
	return Verifier{hasher: hasher}
}

// HashDirAsModuleZip builds a module zip from a git checkout of dir and returns
// its h1 hash. Every file in the tree is offered to golang.org/x/mod/zip.Create,
// as the go command offers it the files git archives, so the zip rules decide
// what is left out (vendor/, nested modules, symlinks). CreateFromDir is not
// used: it also drops .hg, .svn and .bzr directories, which git does archive.
func (v Verifier) HashDirAsModuleZip(dir string, coord coordinate.ModuleCoordinate) (ModuleHash, error) {
	files, err := checkoutFiles(dir)
	if err != nil {
		return ModuleHash{}, fmt.Errorf("listing checkout files: %w", err)
	}
	var buf bytes.Buffer
	mv := module.Version{Path: coord.Path(), Version: coord.Version()}
	if err = modzip.Create(&buf, mv, files); err != nil {
		return ModuleHash{}, fmt.Errorf("creating module zip from checkout: %w", err)
	}
	h, err := v.hasher.HashModuleZip(buf.Bytes())
	if err != nil {
		return ModuleHash{}, fmt.Errorf("hashing checkout zip: %w", err)
	}
	return ParseModuleHash(h)
}

// checkoutFiles lists every non-directory entry under dir, without following
// symlinks, with slash-separated paths relative to dir.
func checkoutFiles(dir string) ([]modzip.File, error) {
	var files []modzip.File
	err := filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		rel, err := relPath(dir, p)
		if err != nil {
			return fmt.Errorf("relativising %s: %w", p, err)
		}
		files = append(files, checkoutFile{path: p, slashPath: filepath.ToSlash(rel)})
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("walking %s: %w", dir, err)
	}
	return files, nil
}

// relPath is a seam over filepath.Rel: every path the walk yields lies under
// dir, so its error branch is reachable only through it.
var relPath = filepath.Rel

// checkoutFile is one file of a checkout, as golang.org/x/mod/zip reads it.
type checkoutFile struct {
	path      string
	slashPath string
}

func (f checkoutFile) Path() string { return f.slashPath }

func (f checkoutFile) Lstat() (os.FileInfo, error) {
	info, err := os.Lstat(f.path)
	if err != nil {
		return nil, fmt.Errorf("stat %s: %w", f.slashPath, err)
	}
	return info, nil
}

func (f checkoutFile) Open() (io.ReadCloser, error) {
	r, err := os.Open(f.path) // #nosec G304 -- a path the walk of the checkout produced
	if err != nil {
		return nil, fmt.Errorf("opening %s: %w", f.slashPath, err)
	}
	return r, nil
}

// VerifyPseudoVersionCommit checks that a pseudo-version's embedded commit
// prefix matches the first 12 chars of the resolved commit hash.
func (Verifier) VerifyPseudoVersionCommit(coord coordinate.ModuleCoordinate, commitHash string) error {
	prefix, err := coord.ExtractCommitPrefix()
	if err != nil {
		return fmt.Errorf("extracting commit prefix: %w", err)
	}
	if len(commitHash) < 12 {
		return fmt.Errorf("commit hash too short: %q", commitHash)
	}
	actual := strings.ToLower(commitHash[:12])
	expected := strings.ToLower(prefix)
	if actual != expected {
		return fmt.Errorf("pseudo-version commit prefix %q does not match resolved commit %q", expected, actual)
	}
	return nil
}
