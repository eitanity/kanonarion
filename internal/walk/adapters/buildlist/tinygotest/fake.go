// Package tinygotest installs a fake tinygo command for tests: a script that
// answers `version`, `info -json -target=<t>` and `list -target=<t> -json
// runtime` from fixtures, exits 1 for any other target, and logs every call.
package tinygotest

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// VersionLine is what the fake prints for `tinygo version`.
const VersionLine = "tinygo version 0.42.0 linux/amd64 (using go version go1.27.2 and LLVM version 22.1.4)"

// Target is one target the fake knows.
type Target struct {
	GOOS, GOARCH, GOARM string
	Tags                []string
	// GOROOT is the root whose src/runtime the fake's list names. Empty makes
	// a fresh directory holding only src/runtime.
	GOROOT string
}

// Pico is a pico-shaped target over a fake GOROOT.
func Pico() Target {
	return Target{GOOS: "linux", GOARCH: "arm", GOARM: "6", Tags: []string{"cortexm", "baremetal", "linux", "arm", "rp2040", "rp", "pico", "tinygo"}}
}

// Fake is an installed fake tinygo.
type Fake struct {
	// Dir holds the script as "tinygo"; put it on PATH.
	Dir string
	// Bin is the script's path.
	Bin string
	log string
}

// Install writes the fake into a fresh directory. The script shell-quotes
// nothing it is given, so fixture names must be plain words.
func Install(t testing.TB, targets map[string]Target) Fake {
	t.Helper()
	dir := t.TempDir()
	fixtures := filepath.Join(dir, "fixtures")
	if err := os.MkdirAll(fixtures, 0o750); err != nil {
		t.Fatalf("creating the fake tinygo: %v", err)
	}
	for name, tg := range targets {
		root := tg.GOROOT
		if root == "" {
			root = filepath.Join(dir, "goroot-"+name)
			if err := os.MkdirAll(filepath.Join(root, "src", "runtime"), 0o750); err != nil {
				t.Fatalf("creating the fake GOROOT: %v", err)
			}
		}
		writeJSON(t, filepath.Join(fixtures, "info-"+name+".json"), map[string]any{
			"goroot": filepath.Join(dir, "info-goroot-is-never-read"), "goos": tg.GOOS, "goarch": tg.GOARCH,
			"goarm": tg.GOARM, "build_tags": tg.Tags,
		})
		writeJSON(t, filepath.Join(fixtures, "list-"+name+".json"), map[string]any{
			"Dir": filepath.Join(root, "src", "runtime"), "ImportPath": "runtime",
		})
	}
	log := filepath.Join(dir, "calls.log")
	script := strings.Join([]string{
		"#!/bin/sh",
		`echo "$*" >> ` + log,
		`case "$1" in`,
		`version) echo "` + VersionLine + `" ;;`,
		`info) t="${3#-target=}"; f=` + fixtures + `/info-"$t".json`,
		`  if [ -f "$f" ]; then cat "$f"; else echo "open /fake/tinygo/targets/$t.json: no such file or directory" >&2; exit 1; fi ;;`,
		`list) t="${2#-target=}"; cat ` + fixtures + `/list-"$t".json ;;`,
		`*) echo "unexpected tinygo $*" >&2; exit 2 ;;`,
		`esac`,
		"",
	}, "\n")
	bin := filepath.Join(dir, "tinygo")
	if err := os.WriteFile(bin, []byte(script), 0o700); err != nil { // #nosec G306 -- an executable test fixture
		t.Fatalf("writing the fake tinygo: %v", err)
	}
	return Fake{Dir: dir, Bin: bin, log: log}
}

// Calls is every invocation the fake has answered, one argument line each.
func (f Fake) Calls(t testing.TB) []string {
	t.Helper()
	b, err := os.ReadFile(f.log)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		t.Fatalf("reading the fake tinygo's log: %v", err)
	}
	return strings.Split(strings.TrimRight(string(b), "\n"), "\n")
}

func writeJSON(t testing.TB, path string, v any) {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("encoding %s: %v", path, err)
	}
	if err := os.WriteFile(path, b, 0o600); err != nil {
		t.Fatalf("writing %s: %v", path, err)
	}
}
