package golden_test

// The hermetic fixture `audit` is recorded against.
//
// audit is the surface this detector exists for and the one phase one could not
// cover: it derives a live walk and a live vulnerability scan before it prints a
// row, so a fixture store alone cannot make it print one. The consequence was
// measured and stated rather than assumed — an added field on auditModuleResult
// moved no golden — which left one of the four ungoverned surfaces undetected.
//
// What makes it recordable is that audit already has a fully offline mode. With
// --from-modcache the run sources module bytes from a Go module cache, verifies
// them against the project's own go.sum, and answers the staleness column from
// the ledger alone. Nothing reaches the network on that path, so the whole
// derivation can be driven for real against fixture inputs.
//
// The inputs are built here and depend on NOTHING ambient:
//
//   - The modules are generated in this file, published into a file:// module
//     proxy in a temp directory, and downloaded into a temp GOMODCACHE. No
//     version of any real module is required, so no golden can pass here because
//     a particular version happens to be cached on the machine and fail on a
//     cold runner. GOPROXY is `off` for the recorded run itself.
//   - The advisory database is a real govulncheck file:// database built below,
//     sealed as a snapshot and stored, so the scan runs offline against known
//     advisories rather than downloading vuln.go.dev.
//   - The staleness ledger carries a lookup for one of the two modules and none
//     for the other, so the measured and unmeasured halves of that column are
//     both recorded rather than one standing for both.
//
// What is deliberately NOT avoided: the run mints a walk id and a scan-run id,
// and it reports the host's Go toolchain version. Those are normalised to stable
// tokens (see normaliser) rather than dropped, so their presence and absence
// still register in the golden. Everything else is compared byte for byte.

import (
	"archive/zip"
	"bytes"
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/eitanity/kanonarion/internal/adapters/sqlitestore"

	fetchsqlite "github.com/eitanity/kanonarion/internal/adapters/factstore/sqlite"
	cgsqlite "github.com/eitanity/kanonarion/internal/callgraph/adapters/store/sqlite"
	licsqlite "github.com/eitanity/kanonarion/internal/license/adapters/store/sqlite"
	stalesqlite "github.com/eitanity/kanonarion/internal/staleness/adapters/store/sqlite"
	staledomain "github.com/eitanity/kanonarion/internal/staleness/domain"
	vulnsqlite "github.com/eitanity/kanonarion/internal/vuln/adapters/store/sqlite"
	"github.com/eitanity/kanonarion/internal/vuln/vulntest"
	walksqlite "github.com/eitanity/kanonarion/internal/walk/adapters/walks/sqlite"
)

// auditSnapshotVersion names the advisory database generation the audit fixture
// is judged against. It is the `modified` field of the database's own
// index/db.json as well as the sealed snapshot's version: the scanner refuses a
// database that does not state the generation the record names, so the two are
// written from one constant rather than kept in step by hand.
const auditSnapshotVersion = "2026-02-14T00:00:00Z"

// auditAdvisoryID is the advisory the fixture database carries. It affects
// example.com/mod below v1.3.0 and nothing else, which is what makes the audit
// table hold an affected row and a clean row rather than one uniform verdict.
const auditAdvisoryID = "GO-2026-0001"

// auditFixture is the project, module cache and store roots one audit case runs
// against.
type auditFixture struct {
	project  string
	modcache string
}

// buildAuditFixture publishes the fixture modules into a file:// proxy and
// downloads them into a temp module cache, leaving a project whose go.sum was
// written from those exact bytes.
func buildAuditFixture(t *testing.T) *auditFixture {
	t.Helper()
	root := t.TempDir()
	proxy := filepath.Join(root, "proxy")
	modcache := filepath.Join(root, "modcache")
	project := filepath.Join(root, "project")
	for _, d := range []string{proxy, modcache, project} {
		if err := os.MkdirAll(d, 0o750); err != nil {
			t.Fatalf("creating audit fixture dir %s: %v", d, err)
		}
	}

	// audit's scan shells out to govulncheck. Taking it from the ambient PATH
	// would make the recorded output depend on whether the machine happens to
	// have it: measured, an absent govulncheck turns every module's verdict into
	// "(not scanned)", so the golden would pass here and fail on a runner that
	// does not install it — the exact ambient-state dependence a golden must not
	// have. Build the version this module already pins and put THAT on PATH.
	buildFixtureGovulncheck(t, root)

	publishFixtureModule(t, proxy, "example.com/mod", "v1.2.0", mitLicenseText,
		"package mod\n\n// Handle is the symbol the fixture advisory names.\nfunc Handle() {}\n")
	publishFixtureModule(t, proxy, "example.com/clean", "v1.0.0", bsd3LicenseText,
		"package clean\n\n// Ping is reached from the project's main package.\nfunc Ping() {}\n")

	writeFile(t, filepath.Join(project, "go.mod"),
		"module example.com/app\n\ngo 1.24\n\nrequire (\n\texample.com/clean v1.0.0\n\texample.com/mod v1.2.0\n)\n")
	writeFile(t, filepath.Join(project, "main.go"),
		"package main\n\nimport (\n\t\"example.com/clean\"\n\t\"example.com/mod\"\n)\n\nfunc main() {\n\tmod.Handle()\n\tclean.Ping()\n}\n")

	// go.sum is written from the published bytes, by the toolchain, against the
	// file proxy. --from-modcache verifies every module against it, so a fixture
	// whose go.sum was hand-written would be verifying nothing.
	publishEnv := []string{
		"GOPROXY=file://" + proxy,
		"GOMODCACHE=" + modcache,
		"GOSUMDB=off",
		"GOFLAGS=-mod=mod",
	}
	runGo(t, project, publishEnv, "mod", "tidy")
	// tidy caches each module's go.mod and zip but not its .info, and the walk
	// reads the build list with `go list -m -json all`, which wants the version
	// metadata. Without this the recorded run reports the build list as
	// unavailable under GOPROXY=off — a degradation of the fixture, recorded as
	// though it were the product's behaviour. Warming it here is what makes the
	// offline run the same run an operator with a full cache gets.
	runGo(t, project, publishEnv, "list", "-m", "-json", "all")

	// A Go module cache is written read-only, so the test framework cannot
	// remove its own temp directory afterwards. Restore write permission before
	// that cleanup runs — cleanups are LIFO, and this one is registered after
	// the TempDir it repairs.
	t.Cleanup(func() { makeWritable(modcache) })

	return &auditFixture{project: project, modcache: modcache}
}

// gomod is the project manifest the audit cases name.
func (a *auditFixture) gomod() string { return filepath.Join(a.project, "go.mod") }

// env is the environment every audit case runs under: the fixture module cache,
// no proxy at all, and no checksum database. GOPROXY=off is the assertion that
// the recorded run fetched nothing — if a module were missing from the cache the
// case would fail rather than reach upstream for it.
func (a *auditFixture) env() map[string]string {
	return map[string]string{
		"GOMODCACHE": a.modcache,
		"GOPROXY":    "off",
		"GOSUMDB":    "off",
		"GOFLAGS":    "-mod=mod",
	}
}

// newStore builds a store holding the advisory database and the staleness
// ledger, and nothing else. Every audit case gets its own: audit WRITES — a
// walk, fetch records, licences, a scan run — so a shared store would make each
// case's output depend on which case ran before it.
func (a *auditFixture) newStore(t *testing.T) string {
	t.Helper()
	root := t.TempDir()

	migrations := fetchsqlite.Migrations()
	migrations = append(migrations, walksqlite.Migrations()...)
	migrations = append(migrations, vulnsqlite.Migrations()...)
	migrations = append(migrations, cgsqlite.Migrations()...)
	migrations = append(migrations, licsqlite.Migrations()...)
	migrations = append(migrations, stalesqlite.Migrations()...)

	db, err := sqlitestore.Open(filepath.Join(root, "mirror.db"), migrations, sqlitestore.IntentCreate)
	if err != nil {
		t.Fatalf("opening audit fixture store: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })

	ctx := context.Background()
	blob := auditVulnDB(t)
	snapshot := vulntest.MustSealOver("vuln.go.dev", auditSnapshotVersion,
		time.Date(2026, 2, 14, 0, 0, 0, 0, time.UTC), blob)
	if err := vulnsqlite.New(db).PutDatabaseSnapshot(ctx, snapshot, bytes.NewReader(blob)); err != nil {
		t.Fatalf("filing the audit fixture advisory database: %v", err)
	}

	// One module has a recorded lookup and the other has none, so the recorded
	// table holds a measured staleness row beside an unmeasured one. A fixture
	// where every row is measured proves nothing about the unmeasured branch,
	// and one where none is proves nothing about the measured one.
	ledger := stalesqlite.New(db)
	row := staledomain.Record{
		ModulePath:        "example.com/mod",
		LatestVersion:     "v1.3.0",
		LatestPublishedAt: fixtureReleasedAt,
		NewerMajor:        staledomain.NewerMajor{Probed: true, FromMajor: 2},
		LookedUpAt:        fixtureLookedUpAt,
	}
	if err := ledger.PutStaleness(ctx, row); err != nil {
		t.Fatalf("filing the audit fixture staleness row: %v", err)
	}
	return root
}

// auditVulnDB builds a govulncheck file:// advisory database carrying one
// advisory against example.com/mod and none against example.com/clean.
func auditVulnDB(t *testing.T) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	add := func(name, body string) {
		w, err := zw.Create(name)
		if err != nil {
			t.Fatalf("creating %s in the advisory database: %v", name, err)
		}
		if _, err := w.Write([]byte(body)); err != nil {
			t.Fatalf("writing %s in the advisory database: %v", name, err)
		}
	}
	add("index/db.json", `{"modified":"`+auditSnapshotVersion+`"}`)
	add("index/modules.json", `[{"path":"example.com/mod","vulns":[{"id":"`+auditAdvisoryID+
		`","modified":"`+auditSnapshotVersion+`","fixed":"1.3.0"}]}]`)
	add("ID/"+auditAdvisoryID+".json", auditAdvisoryJSON)
	if err := zw.Close(); err != nil {
		t.Fatalf("closing the advisory database: %v", err)
	}
	return buf.Bytes()
}

// auditAdvisoryJSON is the OSV entry the fixture database serves.
const auditAdvisoryJSON = `{
  "schema_version": "1.3.1",
  "id": "` + auditAdvisoryID + `",
  "modified": "` + auditSnapshotVersion + `",
  "published": "2026-01-05T00:00:00Z",
  "aliases": ["CVE-2026-00001"],
  "summary": "example vulnerability in example.com/mod",
  "details": "A fixture advisory. It names Handle so a reachability analysis has a symbol to reach.",
  "affected": [
    {
      "package": {"name": "example.com/mod", "ecosystem": "Go"},
      "ranges": [{"type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": "1.3.0"}]}],
      "ecosystem_specific": {
        "imports": [{"path": "example.com/mod", "symbols": ["Handle"]}]
      }
    }
  ],
  "references": [{"type": "ADVISORY", "url": "https://example.com/advisories/` + auditAdvisoryID + `"}],
  "database_specific": {"url": "https://pkg.go.dev/vuln/` + auditAdvisoryID + `"}
}
`

// publishFixtureModule writes one module version into a file:// module proxy.
func publishFixtureModule(t *testing.T, proxy, path, version, license, source string) {
	t.Helper()
	dir := filepath.Join(proxy, filepath.FromSlash(path), "@v")
	if err := os.MkdirAll(dir, 0o750); err != nil {
		t.Fatalf("creating proxy dir for %s: %v", path, err)
	}
	gomod := "module " + path + "\n\ngo 1.24\n"
	writeFile(t, filepath.Join(dir, version+".mod"), gomod)
	writeFile(t, filepath.Join(dir, version+".info"),
		`{"Version":"`+version+`","Time":"2025-06-01T00:00:00Z"}`)
	writeFile(t, filepath.Join(dir, "list"), version+"\n")

	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	prefix := path + "@" + version + "/"
	// A slice, not a map: the zip's entry order is part of its bytes, and a map
	// would publish a different archive on every run.
	entries := []struct{ name, body string }{
		{"go.mod", gomod},
		{"LICENSE", license},
		{filepath.Base(path) + ".go", source},
	}
	for _, e := range entries {
		w, err := zw.Create(prefix + e.name)
		if err != nil {
			t.Fatalf("creating %s in the %s zip: %v", e.name, path, err)
		}
		if _, err := w.Write([]byte(e.body)); err != nil {
			t.Fatalf("writing %s in the %s zip: %v", e.name, path, err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatalf("closing the %s zip: %v", path, err)
	}
	writeFile(t, filepath.Join(dir, version+".zip"), buf.String())
}

// writeFile writes one fixture file or fails the test.
func writeFile(t *testing.T, path, body string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("writing %s: %v", path, err)
	}
}

// runGo runs the Go toolchain in dir with extra environment, failing the test
// with the command's own output. It is used only to PUBLISH the fixture, never
// to record anything: the recorded runs go through cli.Run.
func runGo(t *testing.T, dir string, extraEnv []string, args ...string) {
	t.Helper()
	cmd := exec.Command("go", args...) //nolint:gosec // arguments are literals in this file.
	cmd.Dir = dir
	cmd.Env = append(append(os.Environ(), "GOTOOLCHAIN=local"), extraEnv...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("go %s in %s: %v\n%s", strings.Join(args, " "), dir, err, out)
	}
}

// The licence texts the fixture modules carry. They are the real, full texts:
// the extractor classifies by reading the file, so a truncated notice would be
// reported Unclassified and the licence column would carry one absence twice
// instead of two different detected licences.
const mitLicenseText = `MIT License

Copyright (c) 2026 Example

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
`

const bsd3LicenseText = `BSD 3-Clause License

Copyright (c) 2026 Example
All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:

1. Redistributions of source code must retain the above copyright notice, this
   list of conditions and the following disclaimer.

2. Redistributions in binary form must reproduce the above copyright notice,
   this list of conditions and the following disclaimer in the documentation
   and/or other materials provided with the distribution.

3. Neither the name of the copyright holder nor the names of its contributors
   may be used to endorse or promote products derived from this software
   without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
`

// makeWritable restores write permission across a module cache so the test
// framework can delete it. Failures are ignored: this is cleanup, and a
// permission that cannot be restored is reported by the removal that follows.
func makeWritable(root string) {
	_ = filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return nil //nolint:nilerr // a path that cannot be read cannot be repaired either.
		}
		mode := os.FileMode(0o600)
		if d.IsDir() {
			mode = 0o700
		}
		_ = os.Chmod(path, mode) // #nosec G122 -- the tree is a module cache this test created in its own temp dir.
		return nil
	})
}

// buildFixtureGovulncheck compiles the govulncheck this module pins into a bin
// directory and prepends it to PATH for the rest of the test.
//
// The version comes from the module's own tool block, so the scanner under test
// is the one the project ships against rather than whatever a machine installed.
func buildFixtureGovulncheck(t *testing.T, root string) {
	t.Helper()
	bin := filepath.Join(root, "bin")
	if err := os.MkdirAll(bin, 0o750); err != nil {
		t.Fatalf("creating the fixture bin dir: %v", err)
	}
	runGo(t, ".", nil, "build", "-o", filepath.Join(bin, "govulncheck"), "golang.org/x/vuln/cmd/govulncheck")
	t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))
}
