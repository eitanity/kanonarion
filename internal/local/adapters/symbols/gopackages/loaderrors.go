package gopackages

import (
	"fmt"
	"io"
	"path/filepath"
	"strconv"
	"strings"

	"golang.org/x/tools/go/packages"
)

// reportLoadErrors writes one line per distinct problem the load reported and
// returns the number of lines written.
//
// It stands in for packages.PrintErrors, which spells one problem three ways:
// the go command's package banner ("# example.com/pb"), the go command's own
// rendering of the problem at a path relative to the load directory, and the
// type checker's rendering of the same problem at an absolute path. A reader
// counts three problems where there is one, and cannot tell which path is real.
//
// Nothing is dropped but an exact repeat of a problem already reported. Two
// entries differing in file, line, column or message are two lines: where they
// cannot be told apart they are both printed, because missing a real second
// problem is worse than a repeated line.
func reportLoadErrors(w io.Writer, root string, pkgs []*packages.Package) int {
	root = filepath.Clean(root)
	seen := make(map[string]bool)
	n := 0
	emit := func(attribution, msg string) {
		msg = flattenMessage(msg)
		key := attribution + "\x00" + msg
		if seen[key] {
			return
		}
		seen[key] = true
		_, _ = fmt.Fprintf(w, "%s: %s\n", attribution, msg)
		n++
	}
	packages.Visit(pkgs, nil, func(p *packages.Package) {
		reportPackage(emit, root, p)
	})
	return n
}

// reportPackage emits every problem attached to one package.
func reportPackage(emit func(attribution, msg string), root string, p *packages.Package) {
	var banners []string
	attributed := 0
	for _, e := range p.Errors {
		for _, pr := range splitProblems(e) {
			if pr.pos == "" && isPackageBanner(pr.msg) {
				banners = append(banners, pr.msg)
				continue
			}
			attributed++
			emit(errorAttribution(root, p, pr.pos), pr.msg)
		}
	}
	// The banner names no file and states no problem, and the package it names
	// is implied by the file paths beneath it. It is still reported when it is
	// all a package had to say: a problem attributed to nothing is a problem.
	if attributed == 0 {
		for _, msg := range banners {
			emit(packageAttribution(p), msg)
		}
	}
	if p.Module != nil && p.Module.Error != nil {
		emit(moduleAttribution(p), strings.TrimSpace(p.Module.Error.Err))
	}
}

// problem is one thing that went wrong: where it is, and what it says.
type problem struct {
	pos string
	msg string
}

// splitProblems breaks one go/packages error into the problems it carries.
//
// A type-check error carries one, in Pos and Msg. A driver error carries the go
// command's whole stderr block in Msg with no Pos at all: a "# package" banner
// followed by one "file:line:col: message" line per problem, sometimes with
// indented continuation lines. Printed as a single error it occupies several
// lines that nothing can match against the type checker's account of the very
// same problems, which is how one problem came to be spelled three ways.
func splitProblems(e packages.Error) []problem {
	msg := strings.TrimRight(e.Msg, "\n")
	if e.Pos != "" && e.Pos != "-" {
		return []problem{{pos: e.Pos, msg: strings.TrimSpace(msg)}}
	}
	if !strings.Contains(msg, "\n") {
		pos, text := splitPosPrefix(strings.TrimSpace(msg))
		return []problem{{pos: pos, msg: text}}
	}
	var out []problem
	for _, line := range strings.Split(msg, "\n") {
		if strings.TrimSpace(line) == "" {
			continue
		}
		// An indented line continues the one above it ("have ..." / "want ..."
		// under a signature mismatch). It is kept with that message rather than
		// reported as a problem of its own, which would drop its context.
		if len(out) > 0 && (line[0] == '\t' || line[0] == ' ') {
			out[len(out)-1].msg += " " + strings.TrimSpace(line)
			continue
		}
		pos, text := splitPosPrefix(strings.TrimSpace(line))
		out = append(out, problem{pos: pos, msg: text})
	}
	return out
}

// splitPosPrefix separates a leading "file:line[:col]" from the message after
// it, as the go command prints them. A candidate prefix is accepted only when
// it carries a line number: a message that merely contains ": " somewhere — a
// wrapped module error, say — has no position, and must keep all of its text.
func splitPosPrefix(line string) (pos, msg string) {
	for i := 0; i+1 < len(line); i++ {
		if line[i] != ':' || line[i+1] != ' ' {
			continue
		}
		candidate := line[:i]
		if _, ln, _, ok := splitPos(candidate); ok && ln > 0 {
			return candidate, strings.TrimSpace(line[i+2:])
		}
	}
	return "", line
}

// errorAttribution renders where a problem sits: a file:line:col a reader can
// open, or the package path when the problem names no file.
//
// The file is shown relative to the analysis root, slash-separated. That is the
// form the rest of the tool uses for a working tree — the call-graph analyser
// relativises its source-file list against the root the same way — and it is
// close to what the go command itself prints, so the surviving line is the one
// already familiar rather than the loader's absolute duplicate. A file outside
// the root keeps its absolute path, where a relative one would be a ../.. chain.
func errorAttribution(root string, p *packages.Package, pos string) string {
	file, line, col, ok := splitPos(pos)
	if !ok {
		return packageAttribution(p)
	}
	// A relative position comes from the go command, which prints file names
	// relative to the directory it ran in — packages.Config.Dir, which is root.
	if !filepath.IsAbs(file) {
		file = filepath.Join(root, file)
	}
	display := filepath.Clean(file)
	if rel, err := filepath.Rel(root, display); err == nil {
		if slash := filepath.ToSlash(rel); slash != ".." && !strings.HasPrefix(slash, "../") {
			display = slash
		}
	}
	switch {
	case line == 0:
		return display
	case col == 0:
		return display + ":" + strconv.Itoa(line)
	default:
		return display + ":" + strconv.Itoa(line) + ":" + strconv.Itoa(col)
	}
}

// packageAttribution names the package a placeless problem belongs to. PkgPath
// is empty for the package go/packages synthesises when a pattern resolved to
// nothing, so the driver's ID stands in; "-" is the last resort, and is what
// the position field itself renders as when it is empty.
func packageAttribution(p *packages.Package) string {
	switch {
	case p.PkgPath != "":
		return p.PkgPath
	case p.ID != "":
		return p.ID
	default:
		return "-"
	}
}

// moduleAttribution names the module a module-level error belongs to. That
// error is attached to every package of the module, so the caller's
// de-duplication is what reduces it to one line.
func moduleAttribution(p *packages.Package) string {
	if p.Module.Path != "" {
		return p.Module.Path
	}
	return packageAttribution(p)
}

// splitPos breaks a position into file, line and column. The position is a
// token.Position rendering: "file:line:col", "file:line", "file", or "" / "-"
// when there is no place at all. Numbers are read from the right, so a colon
// inside a path is never mistaken for a line number.
func splitPos(pos string) (file string, line, col int, ok bool) {
	pos = strings.TrimSpace(pos)
	if pos == "" || pos == "-" {
		return "", 0, 0, false
	}
	rest := pos
	var nums []int
	for len(nums) < 2 {
		i := strings.LastIndex(rest, ":")
		if i < 0 {
			break
		}
		n, err := strconv.Atoi(rest[i+1:])
		if err != nil {
			break
		}
		nums = append(nums, n)
		rest = rest[:i]
	}
	if rest == "" {
		return "", 0, 0, false
	}
	switch len(nums) {
	case 2:
		return rest, nums[1], nums[0], true
	case 1:
		return rest, nums[0], 0, true
	default:
		return rest, 0, 0, true
	}
}

// flattenMessage folds a message that runs over several lines onto one, so that
// a problem occupies exactly one line however the toolchain chose to lay it
// out. The go command wraps a type mismatch as a heading plus indented "have"
// and "want" lines, and the type checker wraps the same problem the same way;
// unfolded, the two renderings never compare equal and the problem is reported
// twice. No text is dropped — only the line breaks between its parts.
func flattenMessage(msg string) string {
	if !strings.Contains(msg, "\n") {
		return strings.TrimSpace(msg)
	}
	parts := make([]string, 0, 4)
	for _, line := range strings.Split(msg, "\n") {
		if trimmed := strings.TrimSpace(line); trimmed != "" {
			parts = append(parts, trimmed)
		}
	}
	return strings.Join(parts, " ")
}

// isPackageBanner reports whether msg is the go command's package header, the
// "# example.com/pb" line it prints above a package's build errors.
func isPackageBanner(msg string) bool {
	return strings.HasPrefix(msg, "# ") && !strings.Contains(msg, "\n")
}
