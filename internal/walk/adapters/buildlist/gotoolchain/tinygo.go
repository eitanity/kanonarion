package gotoolchain

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"code.eitanity.com/kanonarion/internal/adapters/childproc"
	walkdomain "code.eitanity.com/kanonarion/internal/walk/domain"
)

// attributeTinyGo lists the closure's packages under the TinyGo frame, with the
// arguments the vuln scan lists it with, and attributes every package outside
// the module graph to the tree its files really live in.
func (r *Resolver) attributeTinyGo(ctx context.Context, dir string) (standardSplit, error) {
	out, err := r.run(ctx, dir, "list", "-deps", "-json", "./...")
	if err != nil {
		return standardSplit{}, fmt.Errorf("listing the packages of the closure to attribute the standard library to TinyGo or Go%s: %w", r.tinygo.ResolutionClause(), err)
	}
	goRoot, err := r.goRoot(ctx, dir)
	if err != nil {
		return standardSplit{}, err
	}
	split, err := attributeStandard(out, r.tinygo.SourceRoot(), goRoot)
	if err != nil {
		return standardSplit{}, fmt.Errorf("attributing the standard library to TinyGo or Go%s: %w", r.tinygo.ResolutionClause(), err)
	}
	split.facts.Target = r.tinygo.Target()
	return split, nil
}

// goRoot is Go's own GOROOT, asked without the TinyGo frame, whose GOROOT is the
// merged tree that links into this one.
func (r *Resolver) goRoot(ctx context.Context, dir string) (string, error) {
	cmd := childproc.CommandContext(ctx, r.goBin(), "env", "GOROOT") // #nosec G204 -- binary path is either "go" (hardcoded) or caller-supplied and trusted
	cmd.Dir = dir
	cmd.Env = r.target.Apply(os.Environ())
	out, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("go env GOROOT, to tell Go's standard library from TinyGo's: %w", err)
	}
	root := strings.TrimSpace(string(out))
	if root == "" {
		return "", errors.New("go env GOROOT printed nothing, so Go's standard library cannot be told from TinyGo's")
	}
	return root, nil
}

type listedStdPackage struct {
	ImportPath string
	Dir        string
	GoFiles    []string
	CgoFiles   []string
	// The other lists of files a package compiles; with GoFiles and CgoFiles
	// they are what TinyGo custody covers.
	CFiles, CXXFiles, MFiles, HFiles, FFiles, SFiles []string `json:",omitempty"`
	SwigFiles, SwigCXXFiles, SysoFiles, EmbedFiles   []string `json:",omitempty"`
	Module                                           *struct{ Path string }
}

// compiledFiles is every file the package compiles, in no particular order.
func (p listedStdPackage) compiledFiles() []string {
	return slices.Concat(p.GoFiles, p.CgoFiles, p.CFiles, p.CXXFiles, p.MFiles, p.HFiles, p.FFiles,
		p.SFiles, p.SwigFiles, p.SwigCXXFiles, p.SysoFiles, p.EmbedFiles)
}

// standardSplit is attributeStandard's answer: TinyGo's packages, Go's, and
// every file TinyGo's packages compile from TinyGo's own tree.
type standardSplit struct {
	facts  *walkdomain.TinyGoFacts
	goPkgs []string
	files  []walkdomain.TinyGoSourceFile
}

// attributeStandard partitions the packages of a `go list -deps -json` stream
// that belong to no module. A file whose real path is under tinygoRoot/src is
// TinyGo's and one under goRoot/src is Go's; a package holding both is TinyGo's,
// with Go's files named. A file under neither is an error, never a guess.
func attributeStandard(listOut []byte, tinygoRoot, goRoot string) (standardSplit, error) {
	tinygoSrc, err := realSrc(tinygoRoot)
	if err != nil {
		return standardSplit{}, err
	}
	goSrc, err := realSrc(goRoot)
	if err != nil {
		return standardSplit{}, err
	}
	facts := &walkdomain.TinyGoFacts{}
	var goPkgs []string
	var sources []walkdomain.TinyGoSourceFile
	dec := json.NewDecoder(bytes.NewReader(listOut))
	for {
		var p listedStdPackage
		if derr := dec.Decode(&p); errors.Is(derr, io.EOF) {
			break
		} else if derr != nil {
			return standardSplit{}, fmt.Errorf("decoding go list output: %w", derr)
		}
		if p.Module != nil {
			continue
		}
		tinygoFiles, goFiles, serr := splitBySupplier(p, tinygoSrc, goSrc)
		if serr != nil {
			return standardSplit{}, serr
		}
		switch {
		case len(tinygoFiles) == 0:
			goPkgs = append(goPkgs, p.ImportPath)
			continue
		case len(goFiles) == 0:
			facts.Packages = append(facts.Packages, p.ImportPath)
		default:
			facts.Packages = append(facts.Packages, p.ImportPath)
			if facts.Mixed == nil {
				facts.Mixed = map[string][]string{}
			}
			slices.Sort(goFiles)
			facts.Mixed[p.ImportPath] = goFiles
		}
		pkgFiles, ferr := tinygoSourceFiles(p, tinygoSrc)
		if ferr != nil {
			return standardSplit{}, ferr
		}
		sources = append(sources, pkgFiles...)
	}
	slices.Sort(facts.Packages)
	slices.Sort(goPkgs)
	slices.SortFunc(sources, func(a, b walkdomain.TinyGoSourceFile) int { return strings.Compare(a.Path, b.Path) })
	sources = slices.CompactFunc(sources, func(a, b walkdomain.TinyGoSourceFile) bool { return a.Path == b.Path })
	return standardSplit{facts: facts, goPkgs: goPkgs, files: sources}, nil
}

// splitBySupplier names the package's Go and cgo files TinyGo supplies and the
// ones Go supplies; a package with neither is judged by its directory.
func splitBySupplier(p listedStdPackage, tinygoSrc, goSrc string) (tinygoFiles, goFiles []string, err error) {
	files := append(append([]string(nil), p.GoFiles...), p.CgoFiles...)
	if len(files) == 0 {
		files = []string{"."}
	}
	for _, f := range files {
		real, rerr := filepath.EvalSymlinks(filepath.Join(p.Dir, f))
		if rerr != nil {
			return nil, nil, fmt.Errorf("resolving %s of package %s: %w", f, p.ImportPath, rerr)
		}
		switch {
		case under(real, tinygoSrc):
			tinygoFiles = append(tinygoFiles, f)
		case under(real, goSrc):
			goFiles = append(goFiles, f)
		default:
			return nil, nil, fmt.Errorf("%s of package %s is at %s, under neither TinyGo's source root %s nor Go's %s", f, p.ImportPath, real, tinygoSrc, goSrc)
		}
	}
	return tinygoFiles, goFiles, nil
}

// tinygoSourceFiles hashes every file a TinyGo package compiles out of TinyGo's
// own tree, named by its slash path under that tree's src. A file Go supplies
// is the standard library's custody, not TinyGo's, and is left out.
func tinygoSourceFiles(p listedStdPackage, tinygoSrc string) ([]walkdomain.TinyGoSourceFile, error) {
	var out []walkdomain.TinyGoSourceFile
	for _, f := range p.compiledFiles() {
		real, err := filepath.EvalSymlinks(filepath.Join(p.Dir, f))
		if err != nil {
			return nil, fmt.Errorf("resolving %s of package %s: %w", f, p.ImportPath, err)
		}
		if !under(real, tinygoSrc) {
			continue
		}
		data, err := os.ReadFile(real) // #nosec G304 -- a file the toolchain listed, resolved under TINYGOROOT/src
		if err != nil {
			return nil, fmt.Errorf("reading %s of package %s: %w", f, p.ImportPath, err)
		}
		rel, err := filepath.Rel(tinygoSrc, real)
		if err != nil {
			return nil, fmt.Errorf("naming %s of package %s under %s: %w", f, p.ImportPath, tinygoSrc, err)
		}
		sum := sha256.Sum256(data)
		out = append(out, walkdomain.TinyGoSourceFile{Path: filepath.ToSlash(rel), SHA256: hex.EncodeToString(sum[:])})
	}
	return out, nil
}

func realSrc(root string) (string, error) {
	real, err := filepath.EvalSymlinks(filepath.Join(root, "src"))
	if err != nil {
		return "", fmt.Errorf("resolving the source root %s: %w", root, err)
	}
	return real, nil
}

func under(path, root string) bool {
	return strings.HasPrefix(path, root+string(filepath.Separator))
}
