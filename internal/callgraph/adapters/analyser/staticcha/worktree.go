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

// Digest schemes. A worktree digest says WHICH tree an analysis read, and the
// prefix says how that was established, because the two ways of establishing it
// are different claims and must never be compared as though they were one.
//
//   - analysedDigestScheme covers the files the LOADER resolved: symlinks
//     already followed, build tags already applied, testdata and nested modules
//     already excluded. It describes the bytes that were analysed.
//   - scannedDigestScheme covers every .go file under the root, and is used only
//     when the load produced no file list at all — a failed analysis still has to
//     identify the tree it failed on. It is a proxy, and it is inaccurate in both
//     directions, which is why it is never the primary.
//
// Records written before these schemes existed carry a bare "sha256:" digest
// computed by the scan. It is a truthful identity of that tree under the rule it
// was computed by; it is not comparable with either scheme here, and the prefix
// is what makes that visible instead of silent.
const (
	analysedDigestScheme = "analysed-sha256:"
	scannedDigestScheme  = "scanned-sha256:"
)

// analysedTreeDigest identifies a working tree by the files the LOADER read.
//
// It exists because a worktree record has no artefact identity — nothing was
// fetched, so there is nothing to name — and the coordinate cannot fill the gap
// either: every checkout of a module path shares one. Without a discriminator,
// two trees are one row, and appending them to a ledger composes two different
// bodies of code into one answer.
//
// What it deliberately is NOT: the absolute path the analysis ran in. Where a
// tree happens to be mounted is provenance, not identity. Two different trees at
// one path — a branch switch, a rebuild, a re-clone — share it, and two copies of
// one tree do not, so as an IDENTITY it is wrong in both directions. (Which tree
// a READER wants is a different question, and CallGraphRecord.AnalysisRoot is
// what answers that one.)
//
// files are the absolute paths go/packages resolved. Each is hashed by its path
// RELATIVE TO ROOT and its content, so:
//
//   - A file reached through a symlink whose target is outside the root is
//     hashed under the in-tree path that reached it. Editing the target moves the
//     digest, which a filesystem walk cannot manage: a symlink is not a regular
//     file, so the walk skips the link and never reaches the target, and two
//     trees whose analysed source differs came out identical.
//   - A file the loader never opened — under testdata, in a nested module,
//     excluded by a build tag — does not move it. That is a deliberate change from
//     the walk, which moved on all three: it minted a generation recording an
//     identical graph, and under a tree-scoped read a redundant generation is not
//     free, because it is one more content state the caller's own tree does not
//     match.
//   - Two copies of one tree at different paths still agree, because nothing
//     absolute reaches the hash.
//
// Anything outside root is dropped rather than hashed under an invented name: a
// dependency in the module cache is not part of this tree, and the loader lists
// those too.
//
// An unreadable file is an error rather than an omission. The loader has already
// read every file in this list, so a failure here is not a property of the tree;
// and a digest computed over less than the tree would silently identify two
// different trees as one, which is precisely what this exists to prevent.
func analysedTreeDigest(root string, files []string) (string, error) {
	rel, err := relativeUnderRoot(root, files)
	if err != nil {
		return "", err
	}
	return hashTreeFiles(root, rel, analysedDigestScheme)
}

// relativeUnderRoot maps absolute loader paths onto slash-separated paths
// relative to root, dropping everything outside it, and de-duplicating: one file
// is listed by every package variant that compiles it, and hashing it twice
// would make the digest depend on how go/packages happened to group the tree.
func relativeUnderRoot(root string, files []string) ([]string, error) {
	seen := make(map[string]bool, len(files))
	out := make([]string, 0, len(files))
	for _, f := range files {
		rel, err := filepath.Rel(root, f)
		if err != nil {
			// Rel fails only when the two paths cannot be compared at all (one
			// relative, one absolute). That is a defect in what was handed here, not
			// a file outside the tree, so it is reported rather than dropped.
			return nil, fmt.Errorf("relativising %s against %s: %w", f, root, err)
		}
		rel = filepath.ToSlash(rel)
		if rel == ".." || strings.HasPrefix(rel, "../") {
			continue
		}
		if seen[rel] {
			continue
		}
		seen[rel] = true
		out = append(out, rel)
	}
	return out, nil
}

// worktreeDigest identifies a working tree by scanning it, and is the FALLBACK
// for the case analysedTreeDigest cannot answer: a load that failed before it
// resolved any files at all still produced a record, and a worktree record with
// no digest is one that silently merges with every other checkout of the same
// module path.
//
// It covers every .go file under root plus go.mod and go.sum. As a description
// of what was analysed it is wrong in both directions — it includes files the
// loader ignores and excludes source the loader follows out of the tree through
// a symlink — which is why it carries its own scheme prefix and why nothing
// compares it with an analysed digest.
func worktreeDigest(root string) (string, error) {
	files, err := worktreeFiles(root)
	if err != nil {
		return "", err
	}
	return hashTreeFiles(root, files, scannedDigestScheme)
}

// hashTreeFiles hashes rel — slash-separated paths relative to root — into one
// digest under the given scheme.
//
// The framing is explicit: each entry contributes its path length, path, and
// content length before its bytes, so no concatenation of one file's name and
// another's contents can reproduce a different tree's digest.
func hashTreeFiles(root string, rel []string, scheme string) (string, error) {
	rel = append([]string(nil), rel...)
	sort.Strings(rel)

	h := sha256.New()
	for _, name := range rel {
		writeFramed(h, name)
		info, serr := os.Stat(filepath.Join(root, name))
		if serr != nil {
			return "", fmt.Errorf("stating %s for worktree digest: %w", name, serr)
		}
		if _, werr := io.WriteString(h, strconv.FormatInt(info.Size(), 10)+"\x00"); werr != nil {
			return "", fmt.Errorf("hashing worktree entry %s: %w", name, werr)
		}
		f, oerr := os.Open(filepath.Join(root, name)) /* #nosec G304 -- name is relative to root, which the caller chose to analyse */
		if oerr != nil {
			return "", fmt.Errorf("opening %s for worktree digest: %w", name, oerr)
		}
		_, cerr := io.Copy(h, f)
		if clErr := f.Close(); clErr != nil && cerr == nil {
			cerr = clErr
		}
		if cerr != nil {
			return "", fmt.Errorf("hashing %s for worktree digest: %w", name, cerr)
		}
	}
	return scheme + hex.EncodeToString(h.Sum(nil)), nil
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
