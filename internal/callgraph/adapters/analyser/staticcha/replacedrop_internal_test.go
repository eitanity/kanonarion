package staticcha

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// writeGoMod puts a go.mod in a fresh directory and returns the directory.
func writeGoMod(t *testing.T, content string) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "go.mod"), []byte(content), 0o600); err != nil {
		t.Fatalf("writing go.mod: %v", err)
	}
	return dir
}

func readGoMod(t *testing.T, dir string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(dir, "go.mod")) //nolint:gosec // dir is the test's own temp dir
	if err != nil {
		t.Fatalf("reading go.mod: %v", err)
	}
	return string(b)
}

// TestDropLocalReplaces_DropsTargetsOutsideTheTreeAndKeepsTheRest is the whole
// rule in one table. A target outside the extracted tree cannot resolve here and
// applies to no consumer's build; a target inside it resolves exactly as
// published; a target that is a module version resolves with no filesystem at
// all.
func TestDropLocalReplaces_DropsTargetsOutsideTheTreeAndKeepsTheRest(t *testing.T) {
	t.Parallel()

	const monorepo = `module example.com/mod/config

go 1.21

require (
	example.com/mod v1.42.0
	example.com/mod/creds v1.19.24
	example.com/other v1.0.0
	example.com/nested v1.0.0
)

replace example.com/mod => ../

replace example.com/mod/creds => ../creds/

replace example.com/other v1.0.0 => example.com/fork v1.2.3

replace example.com/nested => ./nested/
`

	dir := writeGoMod(t, monorepo)
	dropped, err := dropLocalReplaces(dir)
	if err != nil {
		t.Fatalf("dropLocalReplaces: %v", err)
	}
	if len(dropped) != 2 {
		t.Fatalf("dropped %d directive(s), want the 2 filesystem ones: %v", len(dropped), dropped)
	}
	// Sorted by path, so the order is a fact about the record rather than about
	// the order they happened to appear in the file.
	if got, want := dropped[0].String(), "example.com/mod => ../"; got != want {
		t.Errorf("dropped[0] = %q, want %q", got, want)
	}
	if got, want := dropped[1].String(), "example.com/mod/creds => ../creds/"; got != want {
		t.Errorf("dropped[1] = %q, want %q", got, want)
	}

	rewritten := readGoMod(t, dir)
	if strings.Contains(rewritten, "../") {
		t.Errorf("a replace targeting a directory outside the tree survived the rewrite:\n%s", rewritten)
	}
	// A zip can carry a nested module and replace onto it. That directive resolves
	// exactly as published, and dropping it would send the load hunting for a
	// version of a module sitting in the extraction directory.
	if !strings.Contains(rewritten, "example.com/nested => ./nested/") {
		t.Errorf("a replace targeting a directory inside the tree was dropped:\n%s", rewritten)
	}
	// The version-to-version replace resolves without a filesystem, so nothing
	// about the extraction breaks it and it must be exactly as published.
	if !strings.Contains(rewritten, "example.com/other v1.0.0 => example.com/fork v1.2.3") {
		t.Errorf("the version-to-version replace was not left alone:\n%s", rewritten)
	}
	// The requirements are what the module declares; dropping a replace must not
	// touch them.
	for _, want := range []string{"example.com/mod v1.42.0", "example.com/mod/creds v1.19.24", "example.com/nested v1.0.0"} {
		if !strings.Contains(rewritten, want) {
			t.Errorf("require %q was lost:\n%s", want, rewritten)
		}
	}
}

// TestDropLocalReplaces_AbsoluteTargetGoesToo. An absolute path names a
// directory on the publisher's own machine. It is no more resolvable here than a
// relative one, and if it DOES resolve on this host it is worse: an unrelated
// tree would silently enter the analysis.
func TestDropLocalReplaces_AbsoluteTargetGoesToo(t *testing.T) {
	t.Parallel()

	dir := writeGoMod(t, "module example.com/mod\n\ngo 1.21\n\nrequire example.com/dep v1.0.0\n\nreplace example.com/dep => /home/publisher/dep\n")
	dropped, err := dropLocalReplaces(dir)
	if err != nil {
		t.Fatalf("dropLocalReplaces: %v", err)
	}
	if len(dropped) != 1 || dropped[0].Target != "/home/publisher/dep" {
		t.Fatalf("dropped = %v, want the absolute-path directive", dropped)
	}
}

// TestDropLocalReplaces_LeavesAFileWithNothingToDropByteIdentical is what makes
// this a no-op for the overwhelming majority of modules. A rewrite that
// reformatted every go.mod would change the analysed tree of modules this fix has
// no business touching.
func TestDropLocalReplaces_LeavesAFileWithNothingToDropByteIdentical(t *testing.T) {
	t.Parallel()

	// Deliberately not gofmt-shaped for a go.mod: extra blank lines and a comment
	// that modfile.Format would normalise away if the file were rewritten.
	const published = "module example.com/mod\n\n\ngo 1.21\n\n// a comment the module ships\nrequire example.com/dep v1.0.0\n\nreplace example.com/dep v1.0.0 => example.com/fork v2.0.0\n"

	dir := writeGoMod(t, published)
	dropped, err := dropLocalReplaces(dir)
	if err != nil {
		t.Fatalf("dropLocalReplaces: %v", err)
	}
	if len(dropped) != 0 {
		t.Fatalf("dropped %v from a file with no filesystem replace", dropped)
	}
	if got := readGoMod(t, dir); got != published {
		t.Errorf("go.mod was rewritten when nothing was dropped:\ngot:\n%s\nwant:\n%s", got, published)
	}
}

// TestDropLocalReplaces_AbsentAndUnparseableAreNoOps. A module published before
// Go modules ships no go.mod, and a malformed one is about to be reported by the
// load with a line number this cannot produce. Neither is this function's
// business, and neither may be turned into an error of its own.
func TestDropLocalReplaces_AbsentAndUnparseableAreNoOps(t *testing.T) {
	t.Parallel()

	t.Run("absent", func(t *testing.T) {
		t.Parallel()
		dropped, err := dropLocalReplaces(t.TempDir())
		if err != nil {
			t.Fatalf("dropLocalReplaces on a directory with no go.mod: %v", err)
		}
		if len(dropped) != 0 {
			t.Errorf("dropped = %v, want none", dropped)
		}
	})

	t.Run("unparseable", func(t *testing.T) {
		t.Parallel()
		const broken = "module example.com/mod\n\nthis is not a directive\n"
		dir := writeGoMod(t, broken)
		dropped, err := dropLocalReplaces(dir)
		if err != nil {
			t.Fatalf("dropLocalReplaces on an unparseable go.mod: %v", err)
		}
		if len(dropped) != 0 {
			t.Errorf("dropped = %v, want none", dropped)
		}
		if got := readGoMod(t, dir); got != broken {
			t.Errorf("an unparseable go.mod was rewritten:\n%s", got)
		}
	})
}

// TestDropLocalReplaces_KeepsAnInsideTargetThatDoesNotExist. The go command then
// says "replacement directory ./dep does not exist", which is a true statement
// about the published bytes and is the module's own fault. Dropping it would
// replace a real diagnosis with a search for a module nobody published.
func TestDropLocalReplaces_KeepsAnInsideTargetThatDoesNotExist(t *testing.T) {
	t.Parallel()

	const published = "module example.com/mod\n\ngo 1.21\n\nrequire example.com/dep v1.0.0\n\nreplace example.com/dep => ./dep\n"
	dir := writeGoMod(t, published)
	dropped, err := dropLocalReplaces(dir)
	if err != nil {
		t.Fatalf("dropLocalReplaces: %v", err)
	}
	if len(dropped) != 0 {
		t.Fatalf("dropped %v: a target inside the tree must be left for the load to report on", dropped)
	}
	if got := readGoMod(t, dir); got != published {
		t.Errorf("go.mod was rewritten:\n%s", got)
	}
}

// TestDropLocalReplaces_IsIdempotent. Analyse runs once per extraction, but the
// function must not depend on that: a second pass over a rewritten file has
// nothing to drop and must leave it alone.
func TestDropLocalReplaces_IsIdempotent(t *testing.T) {
	t.Parallel()

	dir := writeGoMod(t, "module example.com/mod\n\ngo 1.21\n\nrequire example.com/dep v1.0.0\n\nreplace example.com/dep => ../dep/\n")
	if _, err := dropLocalReplaces(dir); err != nil {
		t.Fatalf("first pass: %v", err)
	}
	first := readGoMod(t, dir)
	dropped, err := dropLocalReplaces(dir)
	if err != nil {
		t.Fatalf("second pass: %v", err)
	}
	if len(dropped) != 0 {
		t.Errorf("second pass dropped %v", dropped)
	}
	if got := readGoMod(t, dir); got != first {
		t.Errorf("second pass rewrote the file:\ngot:\n%s\nwant:\n%s", got, first)
	}
}
