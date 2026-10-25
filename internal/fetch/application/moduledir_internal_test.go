package application

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"path"
	"path/filepath"
	"strings"
	"testing"

	"github.com/eitanity/kanonarion/internal/adapters/ziparchive"
	"github.com/eitanity/kanonarion/internal/coordinate/coordinatetest"
	domain2 "github.com/eitanity/kanonarion/internal/fetch/domain"
	"github.com/eitanity/kanonarion/internal/fetch/ports"
)

const layoutCommit = "0123456789abcdef0123456789abcdef01234567"

// layoutVCS is a repository whose checkout holds a root go.mod and LICENSE, an
// unrelated sibling module, and the module under test at dir (omitted when
// absent). It records every tag it is asked to resolve.
type layoutVCS struct {
	refs       []string
	dir        string
	modulePath string
	// noGoMod leaves the module directory without a go.mod, the shape of a
	// +incompatible module at the root.
	noGoMod bool
	absent  bool
	// symlinkTo makes dir a symlink to this directory instead.
	symlinkTo string
}

func (v *layoutVCS) ResolveTag(_ context.Context, _, ref string) (string, error) {
	v.refs = append(v.refs, ref)
	return layoutCommit, nil
}

func (v *layoutVCS) CheckoutToDir(_ context.Context, _, _, root string) error {
	files := map[string]string{
		"LICENSE":            "root licence\n",
		"other/go.mod":       "module github.com/acme/repo/other\n",
		"other/other.go":     "package other\n",
		"README.md":          "root readme\n",
		"rootpkg/rootpkg.go": "package rootpkg\n",
	}
	if v.dir != "" {
		files["go.mod"] = "module github.com/acme/repo\n"
	}
	if !v.absent && v.symlinkTo == "" {
		if !v.noGoMod {
			files[path.Join(v.dir, "go.mod")] = "module " + v.modulePath + "\n"
		}
		files[path.Join(v.dir, "mod.go")] = "package mod\n"
	}
	for name, body := range files {
		p := filepath.Join(root, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(p), 0o750); err != nil {
			return fmt.Errorf("creating %s: %w", name, err)
		}
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			return fmt.Errorf("writing %s: %w", name, err)
		}
	}
	if v.symlinkTo != "" {
		link := filepath.Join(root, filepath.FromSlash(v.dir))
		if err := os.MkdirAll(filepath.Dir(link), 0o750); err != nil {
			return fmt.Errorf("creating link parent: %w", err)
		}
		if err := os.Symlink(v.symlinkTo, link); err != nil {
			return fmt.Errorf("linking %s: %w", v.dir, err)
		}
	}
	return nil
}

// expectedModuleHash is the hash the go command's zip of the module would
// carry: the module directory's files, plus the root LICENSE below the root.
func expectedModuleHash(t *testing.T, v *layoutVCS, modulePath, version string) domain2.ModuleHash {
	t.Helper()
	root := t.TempDir()
	probe := *v
	if err := probe.CheckoutToDir(context.Background(), "", "", root); err != nil {
		t.Fatalf("building expected tree: %v", err)
	}
	dir := filepath.Join(root, filepath.FromSlash(v.dir))
	if v.dir != "" {
		if err := os.WriteFile(filepath.Join(dir, "LICENSE"), []byte("root licence\n"), 0o600); err != nil {
			t.Fatalf("copying LICENSE: %v", err)
		}
	}
	h, err := domain2.NewVerifier(ziparchive.Hasher{}).HashDirAsModuleZip(dir, coordinatetest.MustNew(modulePath, version))
	if err != nil {
		t.Fatalf("hashing expected tree: %v", err)
	}
	return h
}

// layoutShape is one way the go command places a module in a repository.
type layoutShape struct {
	name       string
	modulePath string
	version    string
	codeDir    string // what the proxy's Origin.Subdir carries
	dir        string // where the module's go.mod lives
	tag        string // the tag the inferred route must ask for; "" for none
	noGoMod    bool
}

// Every module shape the go command places in a repository, on both routes to
// the repository, against a tree that matches, one that differs and one where
// the module's directory is absent. The leg must hash exactly the module's
// directory, and say so, or name the missing directory; it must never fall
// back to hashing another directory.
func TestCrossVerify_ModuleDirectoryPermutations(t *testing.T) {
	shapes := []layoutShape{
		{name: "root", modulePath: "github.com/acme/repo", version: "v1.2.0", tag: "refs/tags/v1.2.0"},
		{name: "depth 1", modulePath: "github.com/acme/repo/api", version: "v1.2.0", codeDir: "api", dir: "api", tag: "refs/tags/api/v1.2.0"},
		{name: "depth 2", modulePath: "github.com/acme/repo/service/s3", version: "v1.104.0", codeDir: "service/s3", dir: "service/s3", tag: "refs/tags/service/s3/v1.104.0"},
		{name: "depth 3", modulePath: "github.com/acme/repo/sdk/storage/azblob", version: "v1.8.0", codeDir: "sdk/storage/azblob", dir: "sdk/storage/azblob", tag: "refs/tags/sdk/storage/azblob/v1.8.0"},
		{name: "root major subdirectory", modulePath: "github.com/acme/repo/v3", version: "v3.1.0", dir: "v3", tag: "refs/tags/v3.1.0"},
		{name: "code directory major subdirectory", modulePath: "github.com/acme/repo/client/v3", version: "v3.6.14", codeDir: "client", dir: "client/v3", tag: "refs/tags/client/v3.6.14"},
		{name: "incompatible", modulePath: "github.com/acme/repo", version: "v2.3.0+incompatible", tag: "refs/tags/v2.3.0", noGoMod: true},
		{name: "pseudo-version", modulePath: "github.com/acme/repo/service/s3", version: "v0.0.0-20240101000000-0123456789ab", codeDir: "service/s3", dir: "service/s3"},
	}
	for _, s := range shapes {
		for _, route := range []string{"origin", "inferred"} {
			for _, outcome := range []string{"matches", "differs", "absent"} {
				t.Run(s.name+"/"+route+"/"+outcome, func(t *testing.T) {
					runLayoutPermutation(t, s, route, outcome)
				})
			}
		}
	}
}

func runLayoutPermutation(t *testing.T, s layoutShape, route, outcome string) {
	t.Helper()
	coord := coordinatetest.MustNew(s.modulePath, s.version)
	vcs := &layoutVCS{dir: s.dir, modulePath: s.modulePath, noGoMod: s.noGoMod}
	proxyHash := expectedModuleHash(t, vcs, s.modulePath, s.version)
	switch {
	case outcome == "differs":
		h, err := domain2.ParseModuleHash("h1:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=")
		if err != nil {
			t.Fatal(err)
		}
		proxyHash = h
	case outcome == "absent" && s.dir == "":
		// A root module is never absent; its go.mod names another module.
		vcs.modulePath, vcs.noGoMod = "github.com/acme/elsewhere/v9", false
	case outcome == "absent":
		vcs.absent = true
	}

	info := ports.ModuleInfo{}
	if route == "origin" {
		info.Origin = &ports.ModuleOrigin{VCS: "git", URL: "https://github.com/acme/repo",
			Ref: s.tag, Hash: layoutCommit, Subdir: s.codeDir}
	}
	uc := &FetchModuleUseCase{vcs: vcs, verifier: domain2.NewVerifier(ziparchive.Hasher{})}
	gitRef, status, detail, refusal, _, _, loc := uc.resolveGitRef(context.Background(),
		slog.Default(), coord, info, domain2.DefaultVCSHostAllowlist())
	if status != domain2.Verified || refusal != "" {
		t.Fatalf("resolveGitRef = %q (%q, refusal %q), want a ref to cross-verify", status, detail, refusal)
	}
	if route == "inferred" {
		want := []string{s.tag}
		if s.tag == "" {
			want = nil
		}
		if strings.Join(vcs.refs, ",") != strings.Join(want, ",") {
			t.Errorf("tags requested = %v, want exactly %v", vcs.refs, want)
		}
	}

	status, detail, hashed, _ := uc.crossVerify(context.Background(), slog.Default(), coord, gitRef, loc, proxyHash)
	assertLayoutOutcome(t, s.dir, outcome, status, detail, hashed)
}

func assertLayoutOutcome(t *testing.T, dir, outcome string, status domain2.VerificationStatus, detail, hashed string) {
	t.Helper()
	recorded := dir
	if recorded == "" {
		recorded = domain2.RepoRoot
	}
	switch outcome {
	case "matches":
		if status != domain2.Verified || hashed != recorded {
			t.Errorf("got %q in %q (detail %q), want Verified in %q", status, hashed, detail, dir)
		}
	case "differs":
		if status != domain2.UnverifiedHashMismatch || hashed != recorded || !strings.HasSuffix(detail, " of "+displayDir(dir)) {
			t.Errorf("got %q in %q (detail %q), want a mismatch naming %q", status, hashed, detail, dir)
		}
	case "absent":
		if status == domain2.Verified || status == domain2.UnverifiedHashMismatch || hashed != "" {
			t.Errorf("got %q in %q (detail %q), want no hash of any directory", status, hashed, detail)
		}
		if !strings.Contains(detail, "not found at") && !strings.Contains(detail, "declares") {
			t.Errorf("detail %q does not say why no directory holds the module", detail)
		}
	}
}

// A proxy is untrusted, so a subdirectory that could name a place outside the
// checkout refuses the whole Origin; the inferred route takes over.
func TestResolveGitRef_RefusesUnsafeOriginSubdir(t *testing.T) {
	for _, subdir := range []string{"/abs", "../x", "a/../../b", `a\b`, "a\x00b", "./a", "a/"} {
		t.Run(subdir, func(t *testing.T) {
			vcs := &layoutVCS{}
			uc := &FetchModuleUseCase{vcs: vcs}
			coord := coordinatetest.MustNew("github.com/acme/repo/api", "v1.2.0")
			info := ports.ModuleInfo{Origin: &ports.ModuleOrigin{VCS: "git", URL: "https://github.com/acme/repo",
				Ref: "refs/tags/api/v1.2.0", Hash: layoutCommit, Subdir: subdir}}
			_, _, _, refusal, binding, _, loc := uc.resolveGitRef(context.Background(), slog.Default(),
				coord, info, domain2.DefaultVCSHostAllowlist())
			if !strings.Contains(refusal, "refused") || !strings.Contains(refusal, "subdirectory") {
				t.Errorf("refusal = %q, want the Origin refused for its subdirectory", refusal)
			}
			if binding != domain2.VCSURLBindingCoordinateDerived || loc.codeDir != "api" {
				t.Errorf("binding %q, code dir %q: want the inferred route's", binding, loc.codeDir)
			}
		})
	}
}

// A module directory that is a symlink out of the checkout is refused, never
// hashed: the bytes would not be the repository's.
func TestCrossVerify_RefusesModuleDirectoryOutsideCheckout(t *testing.T) {
	outside := t.TempDir()
	if err := os.WriteFile(filepath.Join(outside, "go.mod"), []byte("module github.com/acme/repo/api\n"), 0o600); err != nil {
		t.Fatalf("writing outside go.mod: %v", err)
	}
	vcs := &layoutVCS{dir: "api", modulePath: "github.com/acme/repo/api", symlinkTo: outside}
	uc := &FetchModuleUseCase{vcs: vcs, verifier: domain2.NewVerifier(ziparchive.Hasher{})}
	coord := coordinatetest.MustNew("github.com/acme/repo/api", "v1.2.0")
	status, detail, hashed, _ := uc.crossVerify(context.Background(), slog.Default(), coord,
		domain2.GitReference{URL: "https://github.com/acme/repo", Ref: "refs/tags/api/v1.2.0", CommitHash: layoutCommit},
		originLocation(coord.Path(), "api"), domain2.ModuleHash{})
	if status != domain2.UnverifiedNoVCS || hashed != "" || !strings.Contains(detail, "outside the checkout") {
		t.Errorf("got %q in %q (detail %q), want the directory refused as outside the checkout", status, hashed, detail)
	}
}

// The root LICENSE is copied as git serves it, and never through a symlink:
// a link's target text is the content, and a module's own LICENSE entry, even a
// dangling link, means nothing is copied, so nothing outside the checkout is
// read or written.
func TestCopyRootLicenseIfMissing_DoesNotFollowSymlinks(t *testing.T) {
	outside := t.TempDir()
	secret := filepath.Join(outside, "secret")
	if err := os.WriteFile(secret, []byte("outside\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	root := t.TempDir()
	mod := filepath.Join(root, "api")
	if err := os.MkdirAll(mod, 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(secret, filepath.Join(root, "LICENSE")); err != nil {
		t.Fatal(err)
	}
	copyRootLicenseIfMissing(root, mod, slog.Default(), context.Background())
	got, err := os.ReadFile(filepath.Join(mod, "LICENSE"))
	if err != nil || string(got) != secret {
		t.Errorf("copied LICENSE = %q (%v), want the link text %q", got, err, secret)
	}

	victim := filepath.Join(outside, "victim")
	mod2 := filepath.Join(root, "web")
	if err := os.MkdirAll(mod2, 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(victim, filepath.Join(mod2, "LICENSE")); err != nil {
		t.Fatal(err)
	}
	copyRootLicenseIfMissing(root, mod2, slog.Default(), context.Background())
	if _, err := os.Lstat(victim); err == nil {
		t.Error("the copy wrote through the module's LICENSE link to a file outside the checkout")
	}
}

// OriginSubdirOf inverts the directory rule and refuses to guess.
func TestOriginSubdirOf(t *testing.T) {
	cases := []struct {
		path, gitSubdir, want string
		ok                    bool
	}{
		{"github.com/google/uuid", ".", "", true},
		{"cloud.google.com/go/compute/metadata", "compute/metadata", "compute/metadata", true},
		{"go.etcd.io/etcd/client/v3", "client/v3", "client", true},
		{"modernc.org/gc/v3", "v3", "", true},
		{"github.com/acme/repo/v3", ".", "", true},
		{"go.etcd.io/etcd/client/v3", "", "", false},
		// A directory the module path cannot name: never guessed.
		{"github.com/acme/repo/api", "elsewhere", "", false},
		// Either the code directory or its v2 subdirectory: ambiguous.
		{"example.com/v2/v2/v2", "v2/v2", "", false},
	}
	for _, tc := range cases {
		got, ok := OriginSubdirOf(tc.path, tc.gitSubdir)
		if got != tc.want || ok != tc.ok {
			t.Errorf("OriginSubdirOf(%q, %q) = %q, %v; want %q, %v", tc.path, tc.gitSubdir, got, ok, tc.want, tc.ok)
		}
	}
}
