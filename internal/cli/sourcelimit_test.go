package cli

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/eitanity/kanonarion/internal/adapters/blobstore/localfs"
	fetchsqlite "github.com/eitanity/kanonarion/internal/adapters/factstore/sqlite"
	"github.com/eitanity/kanonarion/internal/adapters/sqlitestore"
	"github.com/eitanity/kanonarion/internal/coordinate"
	"github.com/eitanity/kanonarion/internal/coordinate/coordinatetest"
	extractdomain "github.com/eitanity/kanonarion/internal/extract/domain"
	fetchapp "github.com/eitanity/kanonarion/internal/fetch/application"
	fetchdomain "github.com/eitanity/kanonarion/internal/fetch/domain"
	"github.com/eitanity/kanonarion/internal/fetch/fetchtest"
	"github.com/eitanity/kanonarion/internal/gotoolchain"
)

var limitProbe = coordinatetest.MustNew("example.com/genmeth", "v1.0.0")

// limitStore holds the probe module fetched, its zip and go.mod in the blob
// store, so `interface` and `examples` extract it through the real stores. One
// non-test and one test file stand in for the generic method: unparseable by
// any parser, under a go directive newer than the Go the seam reports.
func limitStore(t *testing.T) string {
	t.Helper()
	goMod := "module example.com/genmeth\n\ngo 1.27.2\n"
	var zbuf bytes.Buffer
	zw := zip.NewWriter(&zbuf)
	for name, src := range map[string]string{
		"go.mod":          goMod,
		"genmeth.go":      "package genmeth\n\nfunc (b Box) Map[T any](f func(int) T) T {\n",
		"box.go":          "package genmeth\n\n// Box holds a value.\ntype Box struct{ V int }\n",
		"example_test.go": "package genmeth_test\n\nfunc ExampleBox() {\n",
		"plain/p_test.go": "package plain_test\n\nfunc ExamplePlain() {\n\tprintln(1)\n\t// Output: 1\n}\n",
		"plain/plain.go":  "package plain\n\n// Plain returns one.\nfunc Plain() int { return 1 }\n",
	} {
		f, err := zw.Create(limitProbe.Path() + "@" + limitProbe.Version() + "/" + name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := f.Write([]byte(src)); err != nil {
			t.Fatal(err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	r := fetchtest.Record(t,
		fetchtest.Coordinate(limitProbe),
		fetchtest.PipelineVersion(fetchapp.PipelineVersion),
		fetchtest.Status(fetchdomain.Verified),
		fetchtest.Content("zip"),
		fetchtest.GoMod("gomod"),
	)
	root := asideStore(t, func(ctx context.Context, db sqlitestore.DB) {
		sealed, err := fetchdomain.Rehydrate(r)
		if err != nil {
			t.Fatal(err)
		}
		if err := fetchsqlite.New(db).PutFetchRecord(ctx, sealed); err != nil {
			t.Fatal(err)
		}
	})
	blobs := localfs.New(root)
	ctx := context.Background()
	if err := blobs.Put(ctx, fetchtest.ZipIdentity(t, r), bytes.NewReader(zbuf.Bytes())); err != nil {
		t.Fatal(err)
	}
	if err := blobs.Put(ctx, fetchtest.GoModIdentity(t, r), strings.NewReader(goMod)); err != nil {
		t.Fatal(err)
	}
	return root
}

// The extracting commands store the record, state the limit and its remedy,
// and exit 20; the same store read by a binary the limit does not bind is
// measured again rather than served, and the refusal is then the module's.
func TestExtractingCommands_AnalyserLimitExitsConfig(t *testing.T) {
	for _, cmd := range []string{"interface", "examples"} {
		t.Run(cmd, func(t *testing.T) {
			root := limitStore(t)
			restore := gotoolchain.SetAnalysingGo("go1.26.6")
			stdout, stderr, err := runAside(cmd, limitProbe.String(), "--store-root", root)
			restore()
			var ee *exitError
			if !errors.As(err, &ee) || ee.code != ExitConfig {
				t.Fatalf("%s: err %v, want exit %d\n%s%s", cmd, err, ExitConfig, stdout, stderr)
			}
			if !strings.Contains(err.Error(), "this kanonarion cannot read this code: it was built with go1.26.6 and the code requires go1.27.2") {
				t.Errorf("refusal lacks the statement: %v", err)
			}
			for _, want := range []string{"not analysed:", "Use a kanonarion built with go1.27.2 or newer"} {
				if !strings.Contains(stdout, want) {
					t.Errorf("stdout lacks %q:\n%s", want, stdout)
				}
			}
			if strings.Contains(stdout, "[parse failure]") || strings.Contains(stdout, "parse failures in") {
				t.Errorf("the unread files were reported as the module's parse failures:\n%s", stdout)
			}

			// Run again under --json: the refusal still exits 20, and the record
			// carries the field.
			restore = gotoolchain.SetAnalysingGo("go1.26.6")
			stdout, _, err = runAside(cmd, limitProbe.String(), "--json", "--store-root", root)
			restore()
			if !errors.As(err, &ee) || ee.code != ExitConfig {
				t.Fatalf("%s --json: err %v, want exit %d", cmd, err, ExitConfig)
			}
			if !strings.Contains(stdout, `"analyser_limit"`) && !strings.Contains(stdout, `"AnalyserLimit"`) {
				t.Errorf("%s --json does not carry the limit:\n%s", cmd, stdout)
			}

			// A binary the directive does not outrank re-measures: the files fail
			// to parse for it too, and that failure is the module's.
			stdout, stderr, err = runAside(cmd, limitProbe.String(), "--store-root", root)
			if err != nil {
				t.Fatalf("%s by an unbound binary: %v\n%s", cmd, err, stderr)
			}
			if strings.Contains(stdout, "(cached)") || strings.Contains(stdout, "not analysed") {
				t.Errorf("the limit record was served to a binary it does not bind:\n%s", stdout)
			}
		})
	}
}

// The readers state the limit in text and carry it under --json.
func TestReaders_StateTheAnalyserLimit(t *testing.T) {
	root := limitStore(t)
	restore := gotoolchain.SetAnalysingGo("go1.26.6")
	defer restore()
	for _, cmd := range []string{"interface", "examples"} {
		if _, _, err := runAside(cmd, limitProbe.String(), "--store-root", root); err == nil {
			t.Fatalf("%s did not refuse", cmd)
		}
	}
	for _, tc := range []struct {
		args []string
		in   string // "stdout" or "stderr"
		want string
	}{
		{[]string{"interface-show", limitProbe.String()}, "stdout", "not analysed: 1 file (genmeth.go)"},
		{[]string{"interface-show", limitProbe.String(), "--json"}, "stdout", `"analyser_limit": {`},
		{[]string{"interface-list", "--json"}, "stdout", `"analyser_limit": {`},
		{[]string{"interface-list"}, "stdout", "not analysed: 1 file (genmeth.go)"},
		{[]string{"interface-list", limitProbe.String()}, "stderr", "not analysed: 1 file (genmeth.go)"},
		{[]string{"examples-list", limitProbe.String()}, "stderr", "not analysed: 1 file (example_test.go)"},
		{[]string{"context", limitProbe.String()}, "stdout", "Analyser limit:  not analysed: 1 file (example_test.go)"},
		{[]string{"context", limitProbe.String()}, "stdout", "Analyser limit:  not analysed: 1 file (genmeth.go)"},
		{[]string{"context", limitProbe.String(), "--json"}, "stdout", `"analyser_limit": {`},
	} {
		stdout, stderr, _ := runAside(append(tc.args, "--store-root", root)...)
		got := stdout
		if tc.in == "stderr" {
			got = stderr
		}
		if !strings.Contains(got, tc.want) {
			t.Errorf("%v: %s lacks %q:\nstdout:\n%s\nstderr:\n%s", tc.args, tc.in, tc.want, stdout, stderr)
		}
	}
	_, _, err := runAside("examples-show", limitProbe.String(), "ExampleBox", "--store-root", root)
	if err == nil || !strings.Contains(err.Error(), "not analysed: 1 file (example_test.go)") {
		t.Errorf("examples-show for an example in an unread file: %v", err)
	}
}

// An extraction run whose stage met a limit binding this binary exits 20 with
// the statement and the remedy; once this binary clears it, the run is the
// partial it records.
func TestExtractionExit_AnalyserLimitIsConfig(t *testing.T) {
	l := gotoolchain.AnalyserLimit{Required: "go1.27.2", Built: "go1.26.6"}
	run := extractdomain.ExtractionRun{
		ID:            "run-1",
		OverallStatus: extractdomain.ExtractionRunPartial,
		PerModuleResults: map[coordinate.ModuleCoordinate]extractdomain.ModuleExtractionResult{
			limitProbe: {Stages: map[string]extractdomain.StageResult{
				"interface": {Status: extractdomain.StageFailed, Error: "interface stage status=Partial: x; " + l.Statement()},
			}},
		},
	}
	restore := gotoolchain.SetAnalysingGo("go1.26.6")
	err := extractionExit(run)
	restore()
	var ee *exitError
	if !errors.As(err, &ee) || ee.code != ExitConfig || !strings.Contains(err.Error(), l.Remedy()) {
		t.Errorf("bound: %v, want exit 20 with the remedy", err)
	}
	restore = gotoolchain.SetAnalysingGo("go1.27.2")
	err = extractionExit(run)
	restore()
	if !errors.As(err, &ee) || ee.code != ExitPartial {
		t.Errorf("cleared: %v, want exit %d", err, ExitPartial)
	}
}

func TestAnalyserLimitJSON_RemedyOnlyWhileBound(t *testing.T) {
	u := gotoolchain.NewUnreadSource(gotoolchain.AnalyserLimit{Required: "go1.27.2", Built: "go1.26.6"}, []string{"a.go"})
	restore := gotoolchain.SetAnalysingGo("go1.27.2")
	defer restore()
	b, err := json.Marshal(toAnalyserLimitJSON(u))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(b), "remedy") {
		t.Errorf("a cleared limit carries a remedy: %s", b)
	}
	if toAnalyserLimitJSON(nil) != nil {
		t.Error("no limit made a JSON value")
	}
}

// A local analysis that met the limit refuses at 20; any other failure is the
// wrapped error it always was.
func TestLocalAnalysisErr(t *testing.T) {
	lim := &gotoolchain.AnalyserLimitError{Limit: gotoolchain.AnalyserLimit{Required: "go1.27.2", Built: "go1.26.6"}}
	var ee *exitError
	if err := localAnalysisErr("local reachability analysis", fmt.Errorf("building symbol probe: %w", lim)); !errors.As(err, &ee) ||
		ee.code != ExitConfig || !strings.Contains(err.Error(), "Use a kanonarion built with go1.27.2") {
		t.Errorf("limit: %v, want exit 20 with the remedy", err)
	}
	other := errors.New("go list failed")
	if err := localAnalysisErr("local reachability analysis", other); errors.As(err, &ee) || !errors.Is(err, other) {
		t.Errorf("other: %v, want the wrapped error", err)
	}
}
