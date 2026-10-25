package gotoolchain

import (
	"bufio"
	"fmt"
	"go/build/constraint"
	"io"
	"regexp"
	"slices"
	"strings"
)

// notInStd is the go command refusing an import it looked for in GOROOT.
var notInStd = regexp.MustCompile(`package (\S+) is not in std\b`)

// MissingStdPackages returns, in first-seen order, every package a load failure
// says is not in std.
func MissingStdPackages(detail string) []string {
	var out []string
	for _, m := range notInStd.FindAllStringSubmatch(detail, -1) {
		if !slices.Contains(out, m[1]) {
			out = append(out, m[1])
		}
	}
	return out
}

// tinyGoOwnPackages are the top-level paths TinyGo adds to the standard
// library; they name TinyGo's packages when no tinygo is installed to ask.
var tinyGoOwnPackages = []string{"machine", "device", "runtime/interrupt", "runtime/volatile", "tinygo"}

// IsTinyGoOwnPackage reports whether pkg is one of tinyGoOwnPackages or below one.
func IsTinyGoOwnPackage(pkg string) bool {
	for _, p := range tinyGoOwnPackages {
		if pkg == p || strings.HasPrefix(pkg, p+"/") {
			return true
		}
	}
	return false
}

// TinyGoPackageRemedy names the packages TinyGo provides and rerun, the
// command that analyses the TinyGo build.
func TinyGoPackageRemedy(pkgs []string, rerun string) string {
	verb := " is"
	if len(pkgs) > 1 {
		verb = " are"
	}
	return "  " + strings.Join(pkgs, ", ") + verb + " provided by TinyGo, not Go: analyse the TinyGo build with\n" +
		"  " + rerun + "\n" +
		"  (`tinygo targets` lists the targets)"
}

// TinyGoFlag is what a remedy appends to re-run a command for a TinyGo target.
const TinyGoFlag = " --tinygo <target>"

// maxConstraintTags bounds the assignments BuildsOnlyUnderTinyGo enumerates. A
// constraint naming more tags is not counted, so a crafted header costs nothing.
const maxConstraintTags = 16

// BuildsOnlyUnderTinyGo reports whether the build constraint in a Go file's
// header can be satisfied only with the tinygo tag set: some assignment of its
// own tags satisfies it, and none with tinygo unset does. A //go:build line wins
// over legacy // +build lines, which are ANDed as the go command reads them.
// An error reading the header is returned, never read as "no constraint".
func BuildsOnlyUnderTinyGo(src io.Reader) (bool, error) {
	expr, err := headerConstraint(src)
	if err != nil || expr == nil {
		return false, err
	}
	var tags []string
	expr.Eval(func(tag string) bool {
		if tag != "tinygo" && !slices.Contains(tags, tag) {
			tags = append(tags, tag)
		}
		return false
	})
	if len(tags) > maxConstraintTags {
		return false, nil
	}
	return satisfiable(expr, tags, true) && !satisfiable(expr, tags, false), nil
}

// satisfiable reports whether any assignment of tags satisfies expr with the
// tinygo tag fixed to tinygo.
func satisfiable(expr constraint.Expr, tags []string, tinygo bool) bool {
	for bits := 0; bits < 1<<len(tags); bits++ {
		if expr.Eval(func(tag string) bool {
			if tag == "tinygo" {
				return tinygo
			}
			return bits&(1<<slices.Index(tags, tag)) != 0
		}) {
			return true
		}
	}
	return false
}

// headerConstraint reads the build constraint from the comment lines ahead of
// the package clause, nil when there is none or it does not parse.
func headerConstraint(src io.Reader) (constraint.Expr, error) {
	var goBuild, plusBuild constraint.Expr
	sc := bufio.NewScanner(src)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		if !strings.HasPrefix(line, "//") {
			break
		}
		// A line that does not parse constrains nothing here; the go command
		// refuses such a file on its own account.
		e, err := constraint.Parse(line)
		switch {
		case err != nil:
		case constraint.IsGoBuild(line):
			if goBuild == nil {
				goBuild = e
			}
		case plusBuild == nil:
			plusBuild = e
		default:
			plusBuild = &constraint.AndExpr{X: plusBuild, Y: e}
		}
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("reading the build constraint: %w", err)
	}
	if goBuild != nil {
		return goBuild, nil
	}
	return plusBuild, nil
}
