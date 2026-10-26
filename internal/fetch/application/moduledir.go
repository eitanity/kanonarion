package application

import (
	"fmt"
	"os"
	"path"
	"path/filepath"
	"strings"

	domain2 "code.eitanity.com/kanonarion/internal/fetch/domain"
	"golang.org/x/mod/modfile"
	"golang.org/x/mod/module"
)

// moduleLocation is where in its repository a module's files live, derived by
// the go command's rule: the code directory, and the major-version
// subdirectory the go command would also consult beneath it.
type moduleLocation struct {
	// codeDir is the module's directory relative to the repository root,
	// slash-separated; empty is the root. It also prefixes the module's tags.
	codeDir string
	// pathMajor is the module path's major-version suffix ("/v3", ".v2", "").
	pathMajor string
	// majorSubdir permits <codeDir>/vN to hold the module: false for a gopkg.in
	// path or one whose repository root is the whole module path.
	majorSubdir bool
}

// originLocation is the location named by a proxy Origin's Subdir, which is
// the code directory without any major-version subdirectory.
func originLocation(modulePath, subdir string) moduleLocation {
	_, pathMajor, _ := module.SplitPathVersion(modulePath)
	return moduleLocation{
		codeDir:     subdir,
		pathMajor:   pathMajor,
		majorSubdir: strings.HasPrefix(pathMajor, "/"),
	}
}

// inferredLocation derives the location from the module path against the
// repository root inferRepoURL names: the path below that root, less the
// major-version suffix. ok is false when no repository root can be inferred
// or the root does not contain the module.
func inferredLocation(modulePath string) (moduleLocation, bool) {
	elems := splitPath(modulePath, 3)
	if len(elems) < 2 {
		return moduleLocation{}, false
	}
	root := strings.Join(elems, "/")
	prefix, pathMajor, ok := module.SplitPathVersion(modulePath)
	if !ok {
		return moduleLocation{}, false
	}
	if root == modulePath {
		return moduleLocation{pathMajor: pathMajor}, true
	}
	if prefix != root && !strings.HasPrefix(prefix, root+"/") {
		return moduleLocation{}, false
	}
	return moduleLocation{
		codeDir:     strings.Trim(prefix[len(root):], "/"),
		pathMajor:   pathMajor,
		majorSubdir: strings.HasPrefix(pathMajor, "/"),
	}, true
}

// tagRef is the tag a module version is released under: prefixed by the code
// directory, as the go command looks it up.
func (l moduleLocation) tagRef(tagVersion string) string {
	if l.codeDir == "" {
		return "refs/tags/" + tagVersion
	}
	return "refs/tags/" + l.codeDir + "/" + tagVersion
}

// selectModuleDir picks the one directory of a checkout that holds the module,
// by the go command's rule: <codeDir>/vN when its go.mod declares the module's
// major version, else <codeDir> when its go.mod does or, for a v0/v1 module at
// the root, when it has none. It returns that directory relative to root, or a
// detail saying why no directory holds the module; it never falls back to
// another directory. at names the revision for the detail.
func selectModuleDir(root string, loc moduleLocation, at string) (string, string) {
	mpath1, exists1, err := readModulePath(root, loc.codeDir)
	if err != nil {
		return "", err.Error()
	}
	// The go command also accepts an unversioned gopkg.in path here, for
	// compatibility with a historical bug it keeps honouring.
	found1 := exists1 && (isMajor(mpath1, loc.pathMajor) ||
		(loc.pathMajor == "" && strings.HasPrefix(mpath1, "gopkg.in/")))

	if dir, detail, decided := selectMajorSubdir(root, loc, found1, at); decided {
		return dir, detail
	}

	switch {
	case found1:
		return loc.codeDir, ""
	case exists1:
		return "", fmt.Sprintf("go.mod at %s declares %q at %s", displayDir(loc.codeDir), mpath1, at)
	case loc.codeDir == "" && (loc.pathMajor == "" || strings.HasPrefix(loc.pathMajor, ".")):
		// A v0/v1 or gopkg.in module may have no go.mod at the repository root.
		return "", ""
	}
	if _, err := os.Lstat(filepath.Join(root, filepath.FromSlash(loc.codeDir))); err != nil {
		return "", fmt.Sprintf("module directory %s not found at %s", displayDir(loc.codeDir), at)
	}
	return "", fmt.Sprintf("no go.mod at %s at %s", displayDir(loc.codeDir), at)
}

// selectMajorSubdir applies the go command's major-version subdirectory rule:
// decided is false when <codeDir>/vN has no go.mod and the code directory
// alone decides.
func selectMajorSubdir(root string, loc moduleLocation, found1 bool, at string) (string, string, bool) {
	if !loc.majorSubdir {
		return "", "", false
	}
	dir2 := path.Join(loc.codeDir, loc.pathMajor[1:])
	mpath2, exists2, err := readModulePath(root, dir2)
	if err != nil {
		return "", err.Error(), true
	}
	found2 := exists2 && isMajor(mpath2, loc.pathMajor)
	switch {
	case found1 && found2:
		return "", fmt.Sprintf("go.mod at %s and at %s both declare a %s module path at %s",
			displayDir(loc.codeDir), dir2, loc.pathMajor, at), true
	case found2:
		return dir2, "", true
	case exists2:
		return "", fmt.Sprintf("go.mod at %s declares %q at %s", dir2, mpath2, at), true
	}
	return "", "", false
}

// containedModuleDir resolves rel within root and refuses it when symlinks
// carry it outside the checkout.
func containedModuleDir(root, rel string) (string, error) {
	realRoot, err := filepath.EvalSymlinks(root)
	if err != nil {
		return "", fmt.Errorf("resolving checkout root: %w", err)
	}
	dir, err := filepath.EvalSymlinks(filepath.Join(realRoot, filepath.FromSlash(rel)))
	if err != nil {
		return "", fmt.Errorf("resolving module directory %s: %w", displayDir(rel), err)
	}
	if dir != realRoot && !strings.HasPrefix(dir, realRoot+string(filepath.Separator)) {
		return "", fmt.Errorf("module directory %s resolves outside the checkout", displayDir(rel))
	}
	return dir, nil
}

// readModulePath reads the module path a directory's go.mod declares. exists
// is false when there is no go.mod, or it is not a regular file.
func readModulePath(root, dir string) (string, bool, error) {
	p := filepath.Join(root, filepath.FromSlash(dir), "go.mod")
	if info, err := os.Lstat(p); err != nil || !info.Mode().IsRegular() {
		return "", false, nil //nolint:nilerr // an unreadable go.mod is an absent one, as git would not serve it
	}
	data, err := os.ReadFile(p) // #nosec G304 -- p is inside the verification checkout
	if err != nil {
		return "", false, fmt.Errorf("reading %s: %w", path.Join(dir, "go.mod"), err)
	}
	return modfile.ModulePath(data), true, nil
}

// isMajor reports whether a go.mod's module path is compatible with the major
// version the module path implies; only the major suffix is compared, so a
// fork that keeps its upstream path still matches, as it does for the go
// command.
func isMajor(mpath, pathMajor string) bool {
	if mpath == "" {
		return false
	}
	_, mpathMajor, ok := module.SplitPathVersion(mpath)
	if !ok {
		return false
	}
	if pathMajor == "" {
		switch module.PathMajorPrefix(mpathMajor) {
		case "", "v0", "v1":
			return true
		default:
			return false
		}
	}
	if mpathMajor == "" {
		return false
	}
	return pathMajor[1:] == mpathMajor[1:]
}

func displayDir(rel string) string {
	if rel == "" {
		return "the repository root"
	}
	return rel
}

// OriginSubdirOf recovers the go command's Origin.Subdir (the code directory)
// from a record's git_subdir by inverting the rule selectModuleDir applies. ok
// is false when the record names no directory, or when the directory fits no
// code directory of the module path or fits more than one: a guess is never
// returned.
func OriginSubdirOf(modulePath, gitSubdir string) (string, bool) {
	if gitSubdir == "" {
		return "", false
	}
	hashed := gitSubdir
	if hashed == domain2.RepoRoot {
		hashed = ""
	}
	prefix, pathMajor, ok := module.SplitPathVersion(modulePath)
	if !ok {
		return "", false
	}
	candidates := []string{hashed}
	if strings.HasPrefix(pathMajor, "/") {
		if major := pathMajor[1:]; hashed == major {
			candidates = append(candidates, "")
		} else if strings.HasSuffix(hashed, "/"+major) {
			candidates = append(candidates, strings.TrimSuffix(hashed, "/"+major))
		}
	}
	var found []string
	for _, codeDir := range candidates {
		loc := originLocation(modulePath, codeDir)
		selectable := hashed == codeDir || (loc.majorSubdir && hashed == path.Join(codeDir, pathMajor[1:]))
		belongs := codeDir == "" || strings.HasSuffix(prefix, "/"+codeDir)
		if selectable && belongs {
			found = append(found, codeDir)
		}
	}
	if len(found) != 1 {
		return "", false
	}
	return found[0], true
}
