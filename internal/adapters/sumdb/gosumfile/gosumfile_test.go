package gosumfile

import (
	"bytes"
	"context"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"code.eitanity.com/kanonarion/internal/coordinate"
)

const sampleGoSum = `github.com/example/mod v1.2.3 h1:ziphashvalue=
github.com/example/mod v1.2.3/go.mod h1:gomodhashvalue=
github.com/other/dep v0.4.0/go.mod h1:onlygomod=
`

func writeGoSum(t *testing.T, content string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "go.sum")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("writing go.sum: %v", err)
	}
	return path
}

func coord(t *testing.T, path, version string) coordinate.ModuleCoordinate {
	t.Helper()
	c, err := coordinate.NewModuleCoordinate(path, version)
	if err != nil {
		t.Fatalf("NewModuleCoordinate(%s, %s): %v", path, version, err)
	}
	return c
}

func TestLookup_HitReturnsBothHashes(t *testing.T) {
	c, err := New(writeGoSum(t, sampleGoSum), nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	res := c.Lookup(context.Background(), coord(t, "github.com/example/mod", "v1.2.3"))
	if !res.Available {
		t.Fatalf("Available = false, want true; reason=%q", res.Reason)
	}
	if res.ZipHash.String() != "h1:ziphashvalue=" {
		t.Errorf("ZipHash = %q, want h1:ziphashvalue=", res.ZipHash)
	}
	if res.GoModHash.String() != "h1:gomodhashvalue=" {
		t.Errorf("GoModHash = %q, want h1:gomodhashvalue=", res.GoModHash)
	}
}

func TestLookup_MissingModuleUnavailable(t *testing.T) {
	c, err := New(writeGoSum(t, sampleGoSum), nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	res := c.Lookup(context.Background(), coord(t, "github.com/absent/mod", "v9.9.9"))
	if res.Available {
		t.Fatalf("Available = true, want false for a module absent from go.sum")
	}
	if res.Reason == "" {
		t.Errorf("Reason is empty; want a diagnostic")
	}
}

func TestLookup_GoModOnlyEntryHasNoZipHash(t *testing.T) {
	// github.com/other/dep has only a /go.mod line (a graph-only dependency);
	// with no zip entry the lookup is unavailable.
	c, err := New(writeGoSum(t, sampleGoSum), nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	res := c.Lookup(context.Background(), coord(t, "github.com/other/dep", "v0.4.0"))
	if res.Available {
		t.Fatalf("Available = true, want false for a go.mod-only entry")
	}
}

func TestNew_MissingFileIsEmptyClient(t *testing.T) {
	c, err := New(filepath.Join(t.TempDir(), "nonexistent-go.sum"), nil)
	if err != nil {
		t.Fatalf("New on missing file returned error: %v", err)
	}
	res := c.Lookup(context.Background(), coord(t, "github.com/example/mod", "v1.2.3"))
	if res.Available {
		t.Fatalf("Available = true, want false for an empty client")
	}
}

// Lines without three fields are not hash lines and are skipped: a blank line,
// a two-field line, a four-field one.
func TestNew_LinesWithoutThreeFieldsAreSkipped(t *testing.T) {
	content := "#comment\n\ngithub.com/example/mod v1.2.3 h1:good=\nonly two\ngarbage line with four\n"
	c, err := New(writeGoSum(t, content), nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	res := c.Lookup(context.Background(), coord(t, "github.com/example/mod", "v1.2.3"))
	if !res.Available || res.ZipHash.String() != "h1:good=" {
		t.Fatalf("well-formed line not parsed alongside skipped ones: %+v", res)
	}
}

// A three-field line whose hash does not parse does not refuse the file, as
// the go command does not. When the module has no other line of that kind
// that parses, its lookup fails naming the line and the parse error, never
// reporting it absent, while a neighbour still verifies.
func TestLookup_AnUnparseableLineFailsOnlyItsModulesLookup(t *testing.T) {
	const zipOK, goModOK = "github.com/bad/mod v1.0.0 h1:zip=", "github.com/bad/mod v1.0.0/go.mod h1:gomod="
	for name, lines := range map[string][2]string{
		"zip line, no separator":       {"github.com/bad/mod v1.0.0 notahash", goModOK},
		"zip line, empty value":        {"github.com/bad/mod v1.0.0 h1:", goModOK},
		"zip line, recorded absence":   {"github.com/bad/mod v1.0.0 :", goModOK},
		"go.mod line, empty algorithm": {"github.com/bad/mod v1.0.0/go.mod :value=", zipOK},
	} {
		t.Run(name, func(t *testing.T) {
			content := "github.com/example/mod v1.2.3 h1:good=\n\n" + lines[0] + "\n" + lines[1] + "\n"
			c, err := New(writeGoSum(t, content), nil)
			if err != nil {
				t.Fatalf("New refused a go.sum the go command reads: %v", err)
			}
			res := c.Lookup(context.Background(), coord(t, "github.com/bad/mod", "v1.0.0"))
			if res.Available || !res.LookupFailed() || res.Err == nil {
				t.Fatalf("Lookup = %+v, want a failed lookup carrying its error, never available or absent", res)
			}
			if !strings.Contains(res.Reason, "malformed go.sum line 3") || !strings.Contains(res.Reason, "invalid module hash") {
				t.Errorf("Reason = %q, want it to name line 3 and the hash parse error", res.Reason)
			}
			good := c.Lookup(context.Background(), coord(t, "github.com/example/mod", "v1.2.3"))
			if !good.Available || good.ZipHash.String() != "h1:good=" {
				t.Errorf("neighbour on line 1 = %+v, want it to verify as before", good)
			}
		})
	}
}

// When a line of the same kind parses, it answers for the module, as in the
// go command, and the bad line is tolerated and stated at warn naming it.
func TestLookup_AGoodLineAnswersBesideABadOneWhichIsStated(t *testing.T) {
	for name, content := range map[string]string{
		"bad zip line":    "github.com/bad/mod v1.0.0 h1:zip=\ngithub.com/bad/mod v1.0.0/go.mod h1:gomod=\ngithub.com/bad/mod v1.0.0 garbage\n",
		"bad go.mod line": "github.com/bad/mod v1.0.0 h1:zip=\ngithub.com/bad/mod v1.0.0/go.mod h1:gomod=\ngithub.com/bad/mod v1.0.0/go.mod garbage\n",
	} {
		t.Run(name, func(t *testing.T) {
			var buf bytes.Buffer
			logger := slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug}))
			c, err := New(writeGoSum(t, content), logger)
			if err != nil {
				t.Fatalf("New: %v", err)
			}
			res := c.Lookup(context.Background(), coord(t, "github.com/bad/mod", "v1.0.0"))
			if !res.Available || res.ZipHash.String() != "h1:zip=" || res.GoModHash.String() != "h1:gomod=" {
				t.Fatalf("Lookup = %+v, want the lines that parse to answer", res)
			}
			out := buf.String()
			if !strings.Contains(out, "level=WARN") || !strings.Contains(out, "malformed go.sum line 3") ||
				!strings.Contains(out, `invalid module hash \"garbage\"`) || !strings.Contains(out, "github.com/bad/mod@v1.0.0") {
				t.Errorf("log = %q, want a warn naming the module, line 3 and the parse error", out)
			}
		})
	}
}
