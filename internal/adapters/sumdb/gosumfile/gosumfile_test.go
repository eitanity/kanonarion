package gosumfile

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	domain2 "github.com/eitanity/kanonarion/internal/fetch/domain"
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

func coord(t *testing.T, path, version string) domain2.ModuleCoordinate {
	t.Helper()
	c, err := domain2.NewModuleCoordinate(path, version)
	if err != nil {
		t.Fatalf("NewModuleCoordinate(%s, %s): %v", path, version, err)
	}
	return c
}

func TestLookup_HitReturnsBothHashes(t *testing.T) {
	c, err := New(writeGoSum(t, sampleGoSum))
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
	c, err := New(writeGoSum(t, sampleGoSum))
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
	c, err := New(writeGoSum(t, sampleGoSum))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	res := c.Lookup(context.Background(), coord(t, "github.com/other/dep", "v0.4.0"))
	if res.Available {
		t.Fatalf("Available = true, want false for a go.mod-only entry")
	}
}

func TestNew_MissingFileIsEmptyClient(t *testing.T) {
	c, err := New(filepath.Join(t.TempDir(), "nonexistent-go.sum"))
	if err != nil {
		t.Fatalf("New on missing file returned error: %v", err)
	}
	res := c.Lookup(context.Background(), coord(t, "github.com/example/mod", "v1.2.3"))
	if res.Available {
		t.Fatalf("Available = true, want false for an empty client")
	}
}

func TestNew_MalformedLinesAreSkipped(t *testing.T) {
	content := "# a comment\n\ngithub.com/example/mod v1.2.3 h1:good=\ngarbage line without enough fields extra\n"
	c, err := New(writeGoSum(t, content))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	res := c.Lookup(context.Background(), coord(t, "github.com/example/mod", "v1.2.3"))
	if !res.Available || res.ZipHash.String() != "h1:good=" {
		t.Fatalf("well-formed line not parsed alongside malformed ones: %+v", res)
	}
}
