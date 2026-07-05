// Package xmod implements the GoModParser port using golang.org/x/mod/modfile.
package xmod

import (
	"fmt"
	"strings"

	fetchdomain "github.com/eitanity/kanonarion/internal/fetch/domain"
	walkdomain "github.com/eitanity/kanonarion/internal/walk/domain"
	"golang.org/x/mod/modfile"
	"golang.org/x/mod/semver"
)

// Parser implements ports.GoModParser using golang.org/x/mod/modfile.
type Parser struct{}

// New returns a new Parser.
func New() *Parser {
	return &Parser{}
}

// Parse parses the go.mod bytes into a ParsedGoMod value object.
// filename is used only in error messages. Errors carry line information
// as returned by modfile.Parse.
func (p *Parser) Parse(filename string, data []byte) (walkdomain.ParsedGoMod, error) {
	f, err := modfile.Parse(filename, data, nil)
	if err != nil {
		return walkdomain.ParsedGoMod{}, fmt.Errorf("parsing %s: %w", filename, err)
	}

	out := walkdomain.ParsedGoMod{}

	if f.Module != nil {
		out.ModulePath = f.Module.Mod.Path
	}
	if f.Go != nil {
		out.GoVersion = f.Go.Version
	}
	if f.Toolchain != nil {
		out.Toolchain = f.Toolchain.Name
	}

	out.Require = make([]walkdomain.Requirement, 0, len(f.Require))
	for _, r := range f.Require {
		c, err := fetchdomain.NewModuleCoordinate(r.Mod.Path, r.Mod.Version)
		if err != nil {
			return walkdomain.ParsedGoMod{}, fmt.Errorf("invalid require %s@%s in %s: %w",
				r.Mod.Path, r.Mod.Version, filename, err)
		}
		out.Require = append(out.Require, walkdomain.Requirement{
			Coordinate: c,
			Indirect:   r.Indirect,
		})
	}

	out.Replace = make([]walkdomain.Replacement, 0, len(f.Replace))
	for _, r := range f.Replace {
		repl := walkdomain.Replacement{
			OldPath:    r.Old.Path,
			OldVersion: r.Old.Version,
		}
		if isLocalPath(r.New.Path) {
			repl.IsLocal = true
			repl.LocalPath = r.New.Path
		} else {
			nc, err := newCoordinateFromReplace(r.New.Path, r.New.Version, filename)
			if err != nil {
				return walkdomain.ParsedGoMod{}, err
			}
			repl.NewCoordinate = nc
		}
		out.Replace = append(out.Replace, repl)
	}

	out.Exclude = make([]walkdomain.Exclusion, 0, len(f.Exclude))
	for _, e := range f.Exclude {
		c, err := fetchdomain.NewModuleCoordinate(e.Mod.Path, e.Mod.Version)
		if err != nil {
			return walkdomain.ParsedGoMod{}, fmt.Errorf("invalid exclude %s@%s in %s: %w",
				e.Mod.Path, e.Mod.Version, filename, err)
		}
		out.Exclude = append(out.Exclude, walkdomain.Exclusion{Coordinate: c})
	}

	out.Retract = make([]walkdomain.RetractRange, 0, len(f.Retract))
	for _, r := range f.Retract {
		out.Retract = append(out.Retract, walkdomain.RetractRange{
			Low:       r.Low,
			High:      r.High,
			Rationale: r.Rationale,
		})
	}

	out.Tools = make([]string, 0, len(f.Tool))
	for _, t := range f.Tool {
		out.Tools = append(out.Tools, t.Path)
	}

	return out, nil
}

// isLocalPath reports whether a replace directive target is a local directory
// rather than a module path. Local paths start with "." or "/".
func isLocalPath(path string) bool {
	return strings.HasPrefix(path, "./") ||
		strings.HasPrefix(path, "../") ||
		strings.HasPrefix(path, "/") ||
		path == "." ||
		path == ".."
}

// newCoordinateFromReplace creates a ModuleCoordinate from a replace directive's
// New field. Replace targets may omit the version (wildcard replaces) in which
// case we pass the version through; modfile validates it. If the version is
// empty (or invalid) but the path looks like a module (not local), the
// coordinate is returned with an empty Version — the canonical form for a
// path-only replace target — and the caller decides how to handle it.
func newCoordinateFromReplace(path, version, filename string) (fetchdomain.ModuleCoordinate, error) {
	if version == "" || !semver.IsValid(version) {
		// Replace pointing to a module path without a valid version is unusual;
		// store path with empty version so the caller can decide what to do.
		return fetchdomain.ModuleCoordinate{Path: path, Version: version}, nil
	}
	c, err := fetchdomain.NewModuleCoordinate(path, version)
	if err != nil {
		return fetchdomain.ModuleCoordinate{}, fmt.Errorf("invalid replace new-coord %s@%s in %s: %w",
			path, version, filename, err)
	}
	return c, nil
}
