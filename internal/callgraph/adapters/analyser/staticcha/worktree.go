package staticcha

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
)

// worktreeDigest identifies a working tree by what it contains, so two analyses
// of one module path can be told apart when they read different trees.
//
// It exists because a worktree record has no artefact identity — nothing was
// fetched, so there is nothing to name — and the coordinate cannot fill the gap
// either: every checkout of a module path shares one. Without a discriminator,
// two trees are one row, and appending them to a ledger composes two different
// bodies of code into one answer.
//
// What it deliberately is NOT: the absolute path the analysis ran in. Where a
// tree happens to be mounted is provenance. Two different trees at one path — a
// branch switch, a rebuild, a re-clone — share it, and two copies of one tree do
// not, so it is wrong in both directions.
//
// The digest covers every .go file under root, plus go.mod and go.sum, by
// relative path and content. Two properties follow, and both are the right way
// round:
//
//   - It over-reports change. A .go file in a nested module, or under testdata,
//     is not part of this module's packages but still moves the digest. The cost
//     is an extra ledger generation that records the same graph; the alternative
//     — deciding which files the loader "really" read — would let a tree change
//     without the digest noticing, which is the failure that matters.
//   - It never claims two trees are the same when they are not. File names are
//     hashed alongside contents and lengths are framed, so no rename or move
//     collides with the tree it came from.
//
// An unreadable file is an error rather than an omission. A digest computed over
// less than the tree would silently identify two different trees as one, which
// is precisely what this function exists to prevent.
func worktreeDigest(root string) (string, error) {
	files, err := worktreeFiles(root)
	if err != nil {
		return "", err
	}
	sort.Strings(files)

	h := sha256.New()
	// The framing is explicit: each entry contributes its path length, path, and
	// content length before its bytes, so no concatenation of one file's name and
	// another's contents can reproduce a different tree's digest.
	for _, rel := range files {
		writeFramed(h, rel)
		info, serr := os.Stat(filepath.Join(root, rel))
		if serr != nil {
			return "", fmt.Errorf("stating %s for worktree digest: %w", rel, serr)
		}
		if _, werr := io.WriteString(h, strconv.FormatInt(info.Size(), 10)+"\x00"); werr != nil {
			return "", fmt.Errorf("hashing worktree entry %s: %w", rel, werr)
		}
		f, oerr := os.Open(filepath.Join(root, rel)) /* #nosec G304 -- rel comes from walking root, which the caller chose to analyse */
		if oerr != nil {
			return "", fmt.Errorf("opening %s for worktree digest: %w", rel, oerr)
		}
		_, cerr := io.Copy(h, f)
		if clErr := f.Close(); clErr != nil && cerr == nil {
			cerr = clErr
		}
		if cerr != nil {
			return "", fmt.Errorf("hashing %s for worktree digest: %w", rel, cerr)
		}
	}
	return "sha256:" + hex.EncodeToString(h.Sum(nil)), nil
}

// writeFramed writes a length-prefixed string into the digest.
func writeFramed(h io.Writer, s string) {
	// hash.Hash never returns an error from Write, which is why the interface's
	// own documentation says so; the values are ignored here rather than in a
	// wrapper that would have to invent an error path with no producer.
	_, _ = io.WriteString(h, strconv.Itoa(len(s))+"\x00"+s+"\x00")
}

// worktreeFiles lists the slash-separated relative paths the digest covers.
// Version-control metadata is skipped: .git changes on every commit, fetch and
// index refresh without the analysed source changing at all, so including it
// would make the digest report a different tree on every operation.
func worktreeFiles(root string) ([]string, error) {
	var out []string
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return fmt.Errorf("walking %s: %w", path, err)
		}
		if d.IsDir() {
			if d.Name() == ".git" {
				return filepath.SkipDir
			}
			return nil
		}
		if !d.Type().IsRegular() {
			return nil
		}
		name := d.Name()
		if !strings.HasSuffix(name, ".go") && name != "go.mod" && name != "go.sum" {
			return nil
		}
		rel, rerr := filepath.Rel(root, path)
		if rerr != nil {
			return fmt.Errorf("relativising %s: %w", path, rerr)
		}
		out = append(out, filepath.ToSlash(rel))
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("listing worktree files under %s: %w", root, err)
	}
	return out, nil
}
